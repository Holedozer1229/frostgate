#!/usr/bin/env python3
"""Broadcast a signed release tx via lightwalletd SendTransaction.

On success the node returns errorCode=0 and the ACCEPTED txid arrives in
the errorMessage field (lightwalletd convention). Real consensus failures
arrive with nonzero errorCode.
"""
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lwd_query import varint, f_bytes, grpc_frame, split_frames, parse_fields, to_i32

ENDPOINT = "https://testnet.zec.rocks"
SERVICE = "cash.z.wallet.sdk.rpc.CompactTxStreamer"


def main():
    raw_hex = sys.argv[1].strip()
    raw = bytes.fromhex(raw_hex)

    # RawTransaction{ data = 1: bytes }
    payload = f_bytes(1, raw)
    url = f"{ENDPOINT}/{SERVICE}/SendTransaction"
    frame = grpc_frame(payload)
    p = subprocess.run(
        [
            "curl", "-s", "--http2", "--http2-prior-knowledge",
            "-X", "POST",
            "-H", "content-type: application/grpc",
            "-H", "te: trailers",
            "--data-binary", "@-",
            "--max-time", "60",
            url,
        ],
        input=frame,
        capture_output=True,
    )
    if p.returncode != 0:
        print(f"curl failed rc={p.returncode}: {p.stderr.decode()[:300]}")
        sys.exit(1)
    frames = split_frames(p.stdout)
    if not frames:
        print("no response frames (empty body)")
        sys.exit(1)
    resp = parse_fields(frames[0])
    # proto3 omits scalar fields at their default: a missing errorCode means 0.
    code_raw = resp.get(1, [0])[0]
    code = to_i32(code_raw) if code_raw is not None else 0
    msg = resp.get(2, [b""])[0]
    if isinstance(msg, bytes):
        msg = msg.decode("utf-8", "replace")
    if code == 0:
        # Success: the server echoes the accepted txid in errorMessage.
        print(f"ACCEPTED txid={msg}")
        sys.exit(0)
    print(f"REJECTED errorCode={code} errorMessage={msg}")
    sys.exit(2)


if __name__ == "__main__":
    main()
