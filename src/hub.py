#!/usr/bin/env python3
"""
RJDAP-1 Command Hub (server) - Phase 1 prototype.

Scope:
  Sec. 1  Introduction / constraints : UDP only, datagram <= 512 bytes,
          network byte order, >= 4 workers, 1,000 tasks, static task
          timeout of 200 ms, at-least-once execution + exactly-once
          result registration.
  Sec. 2  Architecture : message types, normal sequence, server
          per-task FSM, worker liveness, stop-and-wait
          scheduling.
  Sec. 3  Message formats : 16-byte header '!BBHIBHIB', CRC32, payload
          layouts, fragmentation rule.

Phase 1 mapping: INIT = WORKER_JOIN, DATA = TASK_DISPATCH / TASK_RESULT /
ACK_RESULT.

Conventions the worker must share with the hub (not fixed by the draft):
  * digest = SHA-256( str(nonce).encode("ascii") )   (decimal ASCII)
  * range  = [range_start, range_end)                (end exclusive)

Standard library only.
    python3 rjdap_hub.py --port 9999 --tasks 1000 --min-workers 4 --seed 1
"""

import argparse
import csv
import hashlib
import random
import socket
import struct
import sys
import time
import zlib
from collections import deque
from dataclasses import dataclass
from typing import Optional

# --------------------------------------------------------------------------
# message formats
# --------------------------------------------------------------------------
VERSION = 1
HDR_FMT = "!BBHIBHIB"              # 1+1+2+4+1+2+4+1 = 16 bytes
HDR_LEN = struct.calcsize(HDR_FMT)
assert HDR_LEN == 16
MAX_DGRAM = 512                    # header + payload
MAX_PAYLOAD = MAX_DGRAM - HDR_LEN  # 496

# message types (4-bit field)
T_JOIN, T_HEARTBEAT, T_DISPATCH, T_RESULT, T_ACK_RESULT = 1, 2, 3, 4, 5
TYPE_NAMES = {1: "WORKER_JOIN", 2: "HEARTBEAT", 3: "TASK_DISPATCH",
              4: "TASK_RESULT", 5: "ACK_RESULT"}

# flags
F_ACK, F_FRAG, F_RETX = 0x01, 0x02, 0x04

# payload layouts
P_JOIN_REQ = struct.Struct("!BB")      # capability u8, reserved u8
P_JOIN_ACK = struct.Struct("!HH")      # heartbeat_interval_ms u16, task_timeout_ms u16
P_HEARTBEAT = struct.Struct("!BBI")    # state u8, inflight u8, ts_us u32
P_DISPATCH = struct.Struct("!QQ32s")   # range_start u64, range_end u64, target_digest 32B
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
                       len(payload), 0, 0)               # CRC field zeroed
    crc = zlib.crc32(hdr0 + payload) & 0xFFFFFFFF
    return struct.pack(HDR_FMT, vt, flags, worker_id, task_id, attempt,
                       len(payload), crc, 0) + payload


def unpack_msg(data: bytes) -> Optional[Msg]:
    """Parse a datagram; return None if malformed or the CRC32 does not match."""
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


# --------------------------------------------------------------------------
# hub state
# --------------------------------------------------------------------------
PENDING, DISPATCHED, DONE = "PENDING", "DISPATCHED", "DONE"


@dataclass
class Task:
    task_id: int
    range_start: int
    range_end: int
    state: str = PENDING
    owner: int = 0
    attempt: int = 1
    sent_at: float = 0.0
    deadline: float = 0.0
    found: bool = False
    nonce: int = 0


@dataclass
class Worker:
    worker_id: int
    addr: tuple
    last_seen: float
    alive: bool = True
    current: Optional[int] = None      # one outstanding task per worker
    idle_ms: float = 0.0               # sum of (round-trip time - compute_us)


class Hub:
    def __init__(self, args):
        self.args = args
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((args.host, args.port))
        self.sock.settimeout(0.005)

        # 2.6: heartbeat every 500 ms, DEAD after 3 missed (1.5 s)
        self.dead_after = 3 * args.heartbeat_ms / 1000.0
        # 1.1: static server-defined task timeout (default 200 ms)
        self.task_timeout = args.task_timeout_ms / 1000.0

        self.workers_by_addr = {}
        self.workers_by_id = {}
        self.next_worker_id = 1
        self.frags = {}                # reassembly buffers

        self.tasks = {}
        self.pending = deque()
        rng = random.Random(args.seed)
        self.secret = rng.randrange(args.tasks * args.range_size)
        self.target = hashlib.sha256(str(self.secret).encode("ascii")).digest()
        for i in range(args.tasks):
            tid = i + 1                                  # Task_ID 0 is reserved
            self.tasks[tid] = Task(tid, i * args.range_size, (i + 1) * args.range_size)
            self.pending.append(tid)

        self.done_count = 0
        self.found_results = []
        self.reassigned_task_count = 0
        self.duplicate_results_dropped = 0
        self.t_first_dispatch: Optional[float] = None
        self.t_last_done: Optional[float] = None

        self.t0 = time.monotonic()
        self.log_file = open(args.log, "w", newline="") if args.log else None
        self.log = csv.writer(self.log_file) if self.log_file else None
        if self.log:
            self.log.writerow(["t", "dir", "type", "task_id", "attempt",
                               "worker_id", "len"])

    # ---- I/O --------------------------------------------------------------
    def _log(self, direction, mtype, task_id, attempt, worker_id, length):
        if self.log:
            self.log.writerow([f"{time.monotonic() - self.t0:.6f}", direction,
                               TYPE_NAMES.get(mtype, mtype), task_id, attempt,
                               worker_id, length])

    def send(self, addr, mtype, flags, worker_id, task_id, attempt, payload=b""):
        data = pack_msg(mtype, flags, worker_id, task_id, attempt, payload)
        self.sock.sendto(data, addr)
        self._log("TX", mtype, task_id, attempt, worker_id, len(data))

    # ---- receive path -----------------------------------------------------
    def handle_datagram(self, data, addr, now):
        msg = unpack_msg(data)
        if msg is None:
            return                                        # bad format / CRC: drop
        self._log("RX", msg.mtype, msg.task_id, msg.attempt, msg.worker_id, len(data))

        if msg.flags & F_FRAG:                            # fragmentation rule
            msg = self.reassemble(msg)
            if msg is None:
                return

        if msg.mtype == T_JOIN and not (msg.flags & F_ACK):
            self.on_join(addr, now, msg)
        elif msg.mtype == T_HEARTBEAT and not (msg.flags & F_ACK):
            self.on_heartbeat(addr, now, msg)
        elif msg.mtype == T_RESULT:
            self.on_result(addr, now, msg)

    def reassemble(self, msg: Msg) -> Optional[Msg]:
        """FRAG: first 2 payload bytes are frag_index u8, frag_total u8.
        Buffer per (Task_ID, Attempt_Num); process once all fragments arrived."""
        if len(msg.payload) < 2:
            return None
        idx, total = msg.payload[0], msg.payload[1]
        if total == 0 or idx >= total:
            return None
        key = (msg.mtype, msg.worker_id, msg.task_id, msg.attempt)
        buf = self.frags.setdefault(key, {})
        buf[idx] = msg.payload[2:]
        if len(buf) < total:
            return None
        del self.frags[key]
        full = b"".join(buf[i] for i in range(total))
        return Msg(msg.mtype, msg.flags & ~F_FRAG, msg.worker_id,
                   msg.task_id, msg.attempt, full)

    def touch(self, w: Worker, now):
        w.last_seen = now
        w.alive = True

    def on_join(self, addr, now, msg):
        if len(msg.payload) != P_JOIN_REQ.size:
            return
        w = self.workers_by_addr.get(addr)
        if w is None:                                     # create entry, assign ID
            w = Worker(self.next_worker_id, addr, now)
            self.next_worker_id += 1
            self.workers_by_addr[addr] = w
            self.workers_by_id[w.worker_id] = w
            print(f"[hub] worker {w.worker_id} joined from {addr[0]}:{addr[1]}")
        else:                                             # repeated JOIN: same ID back
            self.touch(w, now)
        payload = P_JOIN_ACK.pack(self.args.heartbeat_ms, self.args.task_timeout_ms)
        self.send(addr, T_JOIN, F_ACK, w.worker_id, 0, 0, payload)

    def on_heartbeat(self, addr, now, msg):
        w = self.workers_by_addr.get(addr)
        if w is None or len(msg.payload) != P_HEARTBEAT.size:
            return
        self.touch(w, now)
        self.send(addr, T_HEARTBEAT, F_ACK, w.worker_id, 0, 0, msg.payload)  # echo

    def on_result(self, addr, now, msg):
        """2.4: DISPATCHED --valid TASK_RESULT--> DONE; DONE --any result--> DONE."""
        w = self.workers_by_addr.get(addr)
        task = self.tasks.get(msg.task_id)
        if w is None or task is None or len(msg.payload) != P_RESULT.size:
            return
        self.touch(w, now)
        found, nonce, compute_us = P_RESULT.unpack(msg.payload)

        def ack():
            self.send(addr, T_ACK_RESULT, 0, w.worker_id, msg.task_id, msg.attempt)

        if task.state == DONE:                            # duplicate: drop, re-ACK
            self.duplicate_results_dropped += 1
            ack()
            return

        # first valid result wins, whichever attempt or worker produced it
        owner = self.workers_by_id.get(task.owner) if task.state == DISPATCHED else None
        if task.state == DISPATCHED and task.owner == w.worker_id and task.attempt == msg.attempt:
            rtt = now - task.sent_at
            w.idle_ms += max(0.0, rtt - compute_us / 1e6) * 1000.0

        task.state = DONE
        task.found, task.nonce = bool(found), (nonce if found else 0)
        self.done_count += 1
        self.t_last_done = now
        if found:
            self.found_results.append((task.task_id, nonce))
        if owner is not None and owner.current == task.task_id:
            owner.current = None
        if w.current == task.task_id:
            w.current = None
        ack()

    # ---- timers -----------------------------------------------------------
    def requeue(self, task: Task, worker: Worker, reason: str):
        """2.4: DISPATCHED --timeout or worker dead--> PENDING (attempt n+1)."""
        task.state = PENDING
        task.attempt = min(255, task.attempt + 1)         # Attempt_Num is 8 bits
        task.owner = 0
        worker.current = None
        self.reassigned_task_count += 1
        self.pending.appendleft(task.task_id)
        if self.args.verbose:
            print(f"[hub] task {task.task_id} -> PENDING ({reason}, "
                  f"worker {worker.worker_id}), attempt {task.attempt}")

    def check_timers(self, now):
        for w in self.workers_by_id.values():
            if w.alive and now - w.last_seen > self.dead_after:       
                w.alive = False
                print(f"[hub] worker {w.worker_id} marked DEAD")
                if w.current is not None:
                    t = self.tasks[w.current]
                    if t.state == DISPATCHED:
                        self.requeue(t, w, "worker dead")
                    w.current = None
                continue
            if w.current is not None:                                  # per-task timeout
                t = self.tasks[w.current]
                if t.state == DISPATCHED and now >= t.deadline:
                    self.requeue(t, w, "timeout")

    def dispatch(self, now):
        """2.7: one outstanding task per worker (stop-and-wait)."""
        if self.t_first_dispatch is None and self.count_alive() < self.args.min_workers:
            return
        for w in self.workers_by_id.values():
            if not w.alive or w.current is not None:
                continue
            task = None
            while self.pending:
                cand = self.tasks[self.pending.popleft()]
                if cand.state == PENDING:                 # skip tasks already DONE
                    task = cand
                    break
            if task is None:
                return
            task.state, task.owner = DISPATCHED, w.worker_id
            task.sent_at, task.deadline = now, now + self.task_timeout
            w.current = task.task_id
            if self.t_first_dispatch is None:
                self.t_first_dispatch = now
            payload = P_DISPATCH.pack(task.range_start, task.range_end, self.target)
            flags = F_RETX if task.attempt > 1 else 0
            self.send(w.addr, T_DISPATCH, flags, w.worker_id, task.task_id,
                      task.attempt, payload)

    def count_alive(self):
        return sum(1 for w in self.workers_by_id.values() if w.alive)

    # ---- main loop --------------------------------------------------------
    def run(self):
        print(f"[hub] listening on {self.args.host}:{self.args.port}, "
              f"{self.args.tasks} tasks, waiting for {self.args.min_workers} worker(s)")
        try:
            while self.done_count < len(self.tasks):
                try:
                    data, addr = self.sock.recvfrom(2048)
                except (socket.timeout, ConnectionResetError):
                    data = None
                now = time.monotonic()
                if data is not None:
                    self.handle_datagram(data, addr, now)
                    now = time.monotonic()
                self.check_timers(now)
                self.dispatch(now)
        except KeyboardInterrupt:
            print("\n[hub] interrupted")
        self.summary()
        if self.log_file:
            self.log_file.close()
        return 0 if self.done_count == len(self.tasks) else 1

    def summary(self):
        total = ((self.t_last_done - self.t_first_dispatch)
                 if self.t_first_dispatch and self.t_last_done else 0.0)
        print(f"[hub] tasks done: {self.done_count}/{len(self.tasks)}")
        print(f"[hub] total_completion_time: {total:.3f} s")
        print(f"[hub] reassigned_task_count: {self.reassigned_task_count}")
        print(f"[hub] duplicate_results_dropped: {self.duplicate_results_dropped}")
        for w in self.workers_by_id.values():
            print(f"[hub] worker {w.worker_id} worker_idle_time_ms: {w.idle_ms:.1f}")
        print(f"[hub] nonce results: {self.found_results} (secret was {self.secret})")


def parse_args():
    p = argparse.ArgumentParser(description="RJDAP-1 Command Hub (sections 1-3)")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=9999)
    p.add_argument("--tasks", type=int, default=1000)
    p.add_argument("--range-size", type=int, default=5000, help="nonces per task")
    p.add_argument("--min-workers", type=int, default=4,
                   help="workers required before the first dispatch")
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--heartbeat-ms", type=int, default=500)
    p.add_argument("--task-timeout-ms", type=int, default=200)
    p.add_argument("--log", default="hub_packets.csv",
                   help="per-packet CSV log ('' to disable)")
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args()


if __name__ == "__main__":
    sys.exit(Hub(parse_args()).run())