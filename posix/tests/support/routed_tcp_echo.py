#!/usr/bin/env python3
"""Loopback-only host peer for the native C TCP probe; serves two identities."""
import argparse
import json
import os
from pathlib import Path
import socket
import struct

parser = argparse.ArgumentParser()
parser.add_argument("--port", type=int, default=28377)
parser.add_argument("--record", type=Path, required=True)
args = parser.parse_args()
assert not args.record.exists(), "never overwrite a previous peer record"
record = {"pid": os.getpid(), "port": args.port, "completed": [], "finished": False}
def save():
    args.record.write_text(json.dumps(record, indent=2) + "\n")
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", args.port))
    listener.listen(2)
    listener.settimeout(300)
    save()
    print("routed-tcp-echo: ready on loopback", args.port, flush=True)
    for expected_uid in (0, 501):
        connection, _ = listener.accept()
        with connection:
            connection.settimeout(30)
            payload = bytearray()
            while len(payload) < 8192:
                block = connection.recv(8192 - len(payload))
                assert block, "premature EOF"
                payload.extend(block)
            assert payload[:4] == b"TCP7"
            uid = struct.unpack("!I", payload[4:8])[0]
            assert uid == expected_uid, (uid, expected_uid)
            assert all(value == (index * 31) & 255 for index, value in enumerate(payload) if index >= 8)
            assert connection.recv(1) == b"", "expected the guest's write half-close"
            for offset in range(0, len(payload), 317):
                connection.sendall(payload[offset:offset + 317])
            connection.shutdown(socket.SHUT_WR)
        record["completed"].append(uid)
        save()
        print("routed-tcp-echo: PASS 8192 bytes, EOF and reply euid", uid, flush=True)
record["finished"] = True
save()
