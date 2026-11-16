#!/usr/bin/env python3
"""
RJDAP-1 Compute Node (worker) - Phase 1 prototype.

Mirrors the Command Hub (src/hub.py) and RFC sections 1-3:
  * 16-byte header '!BBHIBHIB', CRC32 over header (CRC field zeroed) + payload
  * WORKER_JOIN -> JOIN|ACK (assigned Worker_ID, heartbeat interval, task timeout)
  * HEARTBEAT every heartbeat_ms, hub echoes it (HEARTBEAT|ACK) -> RTT sample
  * TASK_DISPATCH -> search [range_start, range_end) for the nonce n with
        SHA-256( str(n).encode("ascii") ) == target_digest
  * TASK_RESULT -> retransmitted (RETX flag, exponential backoff, capped) until
    ACK_RESULT arrives
  * duplicate TASK_DISPATCH of a seen task is never recomputed (2.5)
  * FRAG reassembly per 3.3

Standard library only.
    python3 src/worker.py --server 127.0.0.1 --port 9999
"""

import argparse
import csv
import hashlib
import os
import socket
import struct
import sys
import time
import zlib
from collections import deque
from dataclasses import dataclass
from typing import Optional

# --------------------------------------------------------------------------
# message formats (identical to the hub)
# --------------------------------------------------------------------------
VERSION = 1
HDR_FMT = "!BBHIBHIB"              # 1+1+2+4+1+2+4+1 = 16 bytes
HDR_LEN = struct.calcsize(HDR_FMT)
assert HDR_LEN == 16
MAX_DGRAM = 512
MAX_PAYLOAD = MAX_DGRAM - HDR_LEN  # 496

T_JOIN, T_HEARTBEAT, T_DISPATCH, T_RESULT, T_ACK_RESULT = 1, 2, 3, 4, 5
TYPE_NAMES = {1: "WORKER_JOIN", 2: "HEARTBEAT", 3: "TASK_DISPATCH",
              4: "TASK_RESULT", 5: "ACK_RESULT"}

F_ACK, F_FRAG, F_RETX = 0x01, 0x02, 0x04

P_JOIN_REQ = struct.Struct("!BB")      # capability u8, reserved u8
P_JOIN_ACK = struct.Struct("!HH")      # heartbeat_interval_ms u16, task_timeout_ms u16
P_HEARTBEAT = struct.Struct("!BBI")    # state u8, inflight u8, ts_us u32
P_DISPATCH = struct.Struct("!QQ32s")   # range_start u64, range_end u64, target_digest
P_RESULT = struct.Struct("!BQI")       # found u8, nonce u64, compute_us u32


@dataclass
class Msg:
    mtype: int
    flags: int
    worker_id: int
    task_id: int
    attempt: int
    payload: bytes


def pack_msg(mtype, flags, worker_id, task_id, attempt, payload=b""):
    if len(payload) > MAX_PAYLOAD:
        raise ValueError("payload exceeds 496 bytes")
    vt = (VERSION << 4) | (mtype & 0x0F)
    hdr0 = struct.pack(HDR_FMT, vt, flags, worker_id, task_id, attempt,
                       len(payload), 0, 0)
    crc = zlib.crc32(hdr0 + payload) & 0xFFFFFFFF
    return struct.pack(HDR_FMT, vt, flags, worker_id, task_id, attempt,
                       len(payload), crc, 0) + payload


def unpack_msg(data: bytes) -> Optional[Msg]:
    """Return None if malformed or the CRC32 does not match (silent drop)."""
    if len(data) < HDR_LEN or len(data) > MAX_DGRAM:
        return None
    vt, flags, wid, tid, att, plen, crc, rsvd = struct.unpack(HDR_FMT, data[:HDR_LEN])
    if (vt >> 4) != VERSION or plen != len(data) - HDR_LEN:
        return None
    payload = data[HDR_LEN:]
    zeroed = struct.pack(HDR_FMT, vt, flags, wid, tid, att, plen, 0, rsvd)
    if (zlib.crc32(zeroed + payload) & 0xFFFFFFFF) != crc:
        return None
    return Msg(vt & 0x0F, flags, wid, tid, att, payload)


def search_range(start: int, end: int, digest: bytes, tick=None):
    """Return (found, nonce). Range is [start, end); digest of decimal ASCII."""
    sha = hashlib.sha256
    for n in range(start, end):
        if sha(str(n).encode("ascii")).digest() == digest:
            return True, n
        if tick is not None and (n & 0x3FF) == 0:
            tick()                     # keep heartbeats / retransmits / ACKs alive
    return False, 0


# --------------------------------------------------------------------------
# worker
# --------------------------------------------------------------------------
@dataclass
class PendingResult:
    """A computed result still waiting for its ACK_RESULT (2.5 RESULT_PENDING)."""
    task_id: int
    attempt: int
    payload: bytes
    next_tx: float
    rto: float
    retries: int = 0


class Worker:
    def __init__(self, args):
        self.args = args
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server = (args.server, args.port)
        self.worker_id = 0
        self.joined = False
        self.heartbeat_s = args.heartbeat_ms / 1000.0
        self.task_timeout_s = 0.2

        self.inbox = deque()           # dispatches waiting to be computed
        self.queued = set()            # (task_id, attempt) in inbox / computing
        self.pending = {}              # task_id -> PendingResult (unACKed results)
        self.acked = set()             # task_ids whose result the hub confirmed
        self.frags = {}

        self.computing = False
        self.t0 = time.monotonic()
        self.last_hub_rx = self.t0
        self.next_hb = 0.0
        self.rtt_samples = []

        self.tasks_computed = 0
        self.results_sent = 0
        self.retransmissions = 0
        self.dup_dispatch_ignored = 0
        self.busy_s = 0.0

        self.log_file = open(args.log, "w", newline="") if args.log else None
        self.log = csv.writer(self.log_file) if self.log_file else None
        if self.log:
            self.log.writerow(["t", "dir", "type", "task_id", "attempt",
                               "worker_id", "len"])

    # ---- I/O --------------------------------------------------------------
    def _log(self, direction, mtype, task_id, attempt, length):
        if self.log:
            self.log.writerow([f"{time.monotonic() - self.t0:.6f}", direction,
                               TYPE_NAMES.get(mtype, mtype), task_id, attempt,
                               self.worker_id, length])

    def send(self, mtype, flags, task_id, attempt, payload=b""):
        data = pack_msg(mtype, flags, self.worker_id, task_id, attempt, payload)
        self.sock.sendto(data, self.server)
        self._log("TX", mtype, task_id, attempt, len(data))

    def recv_one(self, timeout):
        """Receive and handle at most one datagram. Returns True if one arrived."""
        self.sock.settimeout(timeout)
        try:
            data, addr = self.sock.recvfrom(2048)
        except (socket.timeout, BlockingIOError):
            return False
        if addr[0] != self.server[0] or addr[1] != self.server[1]:
            return True                                    # not from the hub: ignore
        msg = unpack_msg(data)
        if msg is None:
            return True                                    # bad format / CRC: drop
        self.last_hub_rx = time.monotonic()
        self._log("RX", msg.mtype, msg.task_id, msg.attempt, len(data))
        if msg.flags & F_FRAG:
            msg = self.reassemble(msg)
            if msg is None:
                return True
        self.handle(msg)
        return True

    def drain(self, limit=32):
        for _ in range(limit):
            if not self.recv_one(0.0):
                break

    def reassemble(self, msg: Msg) -> Optional[Msg]:
        """3.3: first 2 payload bytes are frag_index u8, frag_total u8."""
        if len(msg.payload) < 2:
            return None
        idx, total = msg.payload[0], msg.payload[1]
        if total == 0 or idx >= total:
            return None
        key = (msg.mtype, msg.task_id, msg.attempt)
        buf = self.frags.setdefault(key, {})
        buf[idx] = msg.payload[2:]
        if len(buf) < total:
            return None
        del self.frags[key]
        full = b"".join(buf[i] for i in range(total))
        return Msg(msg.mtype, msg.flags & ~F_FRAG, msg.worker_id,
                   msg.task_id, msg.attempt, full)

    # ---- message handling -------------------------------------------------
    def handle(self, msg: Msg):
        if msg.mtype == T_JOIN and (msg.flags & F_ACK):
            self.on_join_ack(msg)
        elif msg.mtype == T_HEARTBEAT and (msg.flags & F_ACK):
            self.on_heartbeat_ack(msg)
        elif msg.mtype == T_DISPATCH:
            self.on_dispatch(msg)
        elif msg.mtype == T_ACK_RESULT:
            self.on_ack_result(msg)

    def on_join_ack(self, msg: Msg):
        if self.joined or len(msg.payload) != P_JOIN_ACK.size or msg.worker_id == 0:
            return
        hb_ms, to_ms = P_JOIN_ACK.unpack(msg.payload)
        self.worker_id = msg.worker_id
        self.heartbeat_s = hb_ms / 1000.0
        self.task_timeout_s = to_ms / 1000.0
        self.joined = True
        print(f"[worker {self.worker_id}] joined hub {self.server[0]}:{self.server[1]} "
              f"(heartbeat {hb_ms} ms, task timeout {to_ms} ms)")

    def on_heartbeat_ack(self, msg: Msg):
        if len(msg.payload) != P_HEARTBEAT.size:
            return
        _, _, ts_us = P_HEARTBEAT.unpack(msg.payload)
        now_us = int(time.monotonic() * 1e6) & 0xFFFFFFFF
        rtt_ms = ((now_us - ts_us) & 0xFFFFFFFF) / 1000.0  # clock only meaningful to us
        if rtt_ms < 60_000:
            self.rtt_samples.append(rtt_ms)

    def on_dispatch(self, msg: Msg):
        if len(msg.payload) != P_DISPATCH.size:
            return
        tid, att = msg.task_id, msg.attempt
        # 2.5: an already-seen task is never recomputed
        if tid in self.acked:
            self.dup_dispatch_ignored += 1
            return
        if tid in self.pending:                            # have the result: resend it
            self.dup_dispatch_ignored += 1
            pr = self.pending[tid]
            pr.attempt = att
            self.transmit_result(pr, retx=True)
            return
        if any(q[0] == tid for q in self.queued):
            self.dup_dispatch_ignored += 1                 # already queued/computing
            return
        self.queued.add((tid, att))
        self.inbox.append(msg)

    def on_ack_result(self, msg: Msg):
        self.pending.pop(msg.task_id, None)
        self.acked.add(msg.task_id)

    # ---- timers -----------------------------------------------------------
    def send_heartbeat(self, now):
        busy = 1 if (self.computing or self.inbox) else 0
        inflight = min(255, len(self.pending) + len(self.inbox) + (1 if self.computing else 0))
        ts_us = int(now * 1e6) & 0xFFFFFFFF
        self.send(T_HEARTBEAT, 0, 0, 0, P_HEARTBEAT.pack(busy, inflight, ts_us))

    def transmit_result(self, pr: PendingResult, retx: bool):
        flags = F_RETX if retx else 0
        self.send(T_RESULT, flags, pr.task_id, pr.attempt, pr.payload)
        if retx:
            self.retransmissions += 1
        else:
            self.results_sent += 1

    def tick(self):
        """Called between compute chunks and from the main loop."""
        self.drain()
        now = time.monotonic()
        if self.joined and now >= self.next_hb:
            self.send_heartbeat(now)
            self.next_hb = now + self.heartbeat_s
            # after the retry cap, results are resent only on the heartbeat tick
            for pr in list(self.pending.values()):
                if pr.retries >= self.args.max_retries:
                    self.transmit_result(pr, retx=True)
        for pr in list(self.pending.values()):
            if pr.retries < self.args.max_retries and now >= pr.next_tx:
                pr.retries += 1
                pr.rto = min(pr.rto * 2, self.args.max_rto)   # exponential backoff
                pr.next_tx = now + pr.rto
                self.transmit_result(pr, retx=True)

    # ---- compute ----------------------------------------------------------
    def run_task(self, msg: Msg):
        tid, att = msg.task_id, msg.attempt
        start, end, digest = P_DISPATCH.unpack(msg.payload)
        self.computing = True
        t = time.monotonic()
        found, nonce = search_range(start, end, digest, tick=self.tick)
        elapsed = time.monotonic() - t
        self.computing = False
        self.busy_s += elapsed
        self.tasks_computed += 1
        compute_us = min(0xFFFFFFFF, int(elapsed * 1e6))
        payload = P_RESULT.pack(1 if found else 0, nonce, compute_us)
        now = time.monotonic()
        pr = PendingResult(tid, att, payload, now + self.args.initial_rto,
                           self.args.initial_rto)
        self.queued.discard((tid, att))
        self.pending[tid] = pr
        self.transmit_result(pr, retx=False)
        if self.args.crash_after and self.tasks_computed >= self.args.crash_after:
            print(f"[worker {self.worker_id}] simulated crash after "
                  f"{self.tasks_computed} tasks")
            if self.log_file:
                self.log_file.flush()
            os._exit(1)

    # ---- main -------------------------------------------------------------
    def join(self):
        """JOINING: resend WORKER_JOIN every 1 s until JOIN|ACK arrives."""
        deadline = time.monotonic() + self.args.join_timeout
        while not self.joined:
            if time.monotonic() > deadline:
                print("[worker] no JOIN|ACK from hub, giving up")
                return False
            self.send(T_JOIN, 0, 0, 0, P_JOIN_REQ.pack(0, 0))
            t_end = time.monotonic() + 1.0
            while not self.joined and time.monotonic() < t_end:
                self.recv_one(0.05)
        return True

    def run(self):
        print(f"[worker] connecting to {self.server[0]}:{self.server[1]}")
        try:
            if not self.join():
                return 1
            self.last_hub_rx = time.monotonic()
            while True:
                self.tick()
                if self.inbox:
                    msg = self.inbox.popleft()
                    if msg.task_id in self.acked or msg.task_id in self.pending:
                        self.queued.discard((msg.task_id, msg.attempt))
                        continue
                    self.run_task(msg)
                    continue
                self.recv_one(0.005)
                if time.monotonic() - self.last_hub_rx > self.args.idle_exit:
                    print(f"[worker {self.worker_id}] hub silent for "
                          f"{self.args.idle_exit:.0f} s, exiting")
                    break
        except KeyboardInterrupt:
            print("\n[worker] interrupted")
        self.summary()
        if self.log_file:
            self.log_file.close()
        return 0

    def summary(self):
        wall = time.monotonic() - self.t0
        rtt = (sum(self.rtt_samples) / len(self.rtt_samples)) if self.rtt_samples else 0.0
        w = self.worker_id
        print(f"[worker {w}] tasks_computed: {self.tasks_computed}")
        print(f"[worker {w}] results_sent: {self.results_sent}, "
              f"retransmissions: {self.retransmissions}")
        print(f"[worker {w}] duplicate_dispatches_ignored: {self.dup_dispatch_ignored}")
        print(f"[worker {w}] unacked_results: {len(self.pending)}")
        print(f"[worker {w}] mean_heartbeat_rtt_ms: {rtt:.3f}")
        print(f"[worker {w}] busy_s: {self.busy_s:.3f} of {wall:.3f} s")


def parse_args():
    p = argparse.ArgumentParser(description="RJDAP-1 compute node (sections 1-3)")
    p.add_argument("--server", default="127.0.0.1")
    p.add_argument("--port", type=int, default=9999)
    p.add_argument("--heartbeat-ms", type=int, default=500,
                   help="used until the hub's JOIN|ACK overrides it")
    p.add_argument("--initial-rto", type=float, default=0.1,
                   help="first TASK_RESULT retransmit timeout (s)")
    p.add_argument("--max-rto", type=float, default=2.0)
    p.add_argument("--max-retries", type=int, default=8,
                   help="backoff retransmissions per result before heartbeat-tick resends")
    p.add_argument("--join-timeout", type=float, default=30.0)
    p.add_argument("--idle-exit", type=float, default=5.0,
                   help="exit after this many seconds of hub silence")
    p.add_argument("--crash-after", type=int, default=0,
                   help="test aid: hard-exit after N computed tasks (0 = never)")
    p.add_argument("--log", default="worker_packets.csv",
                   help="per-packet CSV log ('' to disable)")
    return p.parse_args()


if __name__ == "__main__":
    sys.exit(Worker(parse_args()).run())