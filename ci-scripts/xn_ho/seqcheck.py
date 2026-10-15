#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CSSL-1.0
"""Sequence-numbered UDP traffic for handover loss/duplicate/reorder checks.

Sender (core/DN side for DL, UE side for UL):
  seqcheck.py send --dst 12.1.1.2 --port 5001 --pps 2000 --size 1200 --duration 30
Receiver (UE side for DL, DN side for UL):
  seqcheck.py recv --bind 12.1.1.2 --port 5001 --duration 35 --json out.json

Each datagram carries a 64-bit sequence number and a 64-bit send timestamp
(CLOCK_REALTIME ns). The receiver reports lost, duplicated and reordered
datagrams, plus every loss gap with its wall-clock time so it can be lined up
with the handover in the gNB logs. Exit code 0 only if nothing was lost,
duplicated or reordered.
"""

import argparse
import json
import socket
import struct
import sys
import time

HDR = struct.Struct("!QQ")


def cmd_send(a):
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  if a.bind:
    s.bind((a.bind, 0))
  pad = b"\0" * max(0, a.size - HDR.size)
  period = 1.0 / a.pps
  t0 = time.monotonic()
  end = t0 + a.duration
  seq = 0
  nxt = t0
  while True:
    now = time.monotonic()
    if now >= end:
      break
    if now < nxt:
      time.sleep(min(nxt - now, 0.001))
      continue
    s.sendto(HDR.pack(seq, time.time_ns()) + pad, (a.dst, a.port))
    seq += 1
    nxt += period
  print(json.dumps({"sent": seq}))
  return 0


def cmd_recv(a):
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 << 20)
  s.bind((a.bind, a.port))
  s.settimeout(0.2)
  seen = bytearray()
  received = dup = reordered = 0
  max_seq = -1
  first_rx = None
  last_rx = None
  end = time.monotonic() + a.duration
  idle_end = None
  while time.monotonic() < end:
    try:
      data = s.recv(65535)
    except socket.timeout:
      if a.idle and first_rx is not None and idle_end is None:
        idle_end = time.monotonic() + a.idle
      if idle_end is not None and time.monotonic() >= idle_end:
        break
      continue
    idle_end = None
    if len(data) < HDR.size:
      continue
    seq, _ = HDR.unpack_from(data)
    now_ns = time.time_ns()
    if first_rx is None:
      first_rx = now_ns
    last_rx = now_ns
    if seq >= len(seen):
      seen.extend(b"\0" * (seq + 1 - len(seen) + 4096))
    if seen[seq]:
      dup += 1
      continue
    seen[seq] = 1
    received += 1
    if seq < max_seq:
      reordered += 1
    else:
      max_seq = seq

  # loss gaps over [0, max_seq]; trailing loss is not detectable without --expect
  top = max(max_seq, a.expect - 1 if a.expect else -1)
  gaps = []
  i = 0
  while i <= top:
    if i < len(seen) and seen[i]:
      i += 1
      continue
    j = i
    while j + 1 <= top and not (j + 1 < len(seen) and seen[j + 1]):
      j += 1
    gaps.append({"first": i, "last": j, "count": j - i + 1})
    i = j + 1
  lost = sum(g["count"] for g in gaps)
  res = {
    "received": received,
    "highest_seq": max_seq,
    "lost": lost,
    "duplicates": dup,
    "reordered": reordered,
    "gaps": gaps[:100],
    "first_rx_ns": first_rx,
    "last_rx_ns": last_rx,
  }
  out = json.dumps(res, indent=2)
  if a.json:
    with open(a.json, "w") as f:
      f.write(out)
  print(out)
  return 0 if lost == 0 and dup == 0 and reordered == 0 and received > 0 else 1


def main():
  p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
  sub = p.add_subparsers(dest="cmd", required=True)
  ps = sub.add_parser("send")
  ps.add_argument("--dst", required=True)
  ps.add_argument("--port", type=int, default=5001)
  ps.add_argument("--bind", help="source IP (e.g. oaitun_ue1 address for UL)")
  ps.add_argument("--pps", type=float, default=1000)
  ps.add_argument("--size", type=int, default=1200)
  ps.add_argument("--duration", type=float, default=30)
  pr = sub.add_parser("recv")
  pr.add_argument("--bind", default="0.0.0.0")
  pr.add_argument("--port", type=int, default=5001)
  pr.add_argument("--duration", type=float, default=35)
  pr.add_argument("--idle", type=float, default=3.0, help="stop after this many idle seconds once traffic started (0: never)")
  pr.add_argument("--expect", type=int, default=0, help="number of datagrams sent (to detect trailing loss)")
  pr.add_argument("--json", help="write the summary here")
  a = p.parse_args()
  return cmd_send(a) if a.cmd == "send" else cmd_recv(a)


if __name__ == "__main__":
  sys.exit(main())
