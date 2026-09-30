#!/usr/bin/env python3
"""Query live Zcash testnet via lightwalletd gRPC (testnet.zec.rocks:443).

Uses curl --http2 for transport and hand-rolled protobuf framing.
Read-only: GetLightdInfo, GetAddressUtxos, GetLatestBlock, GetTransaction.

Correct protobuf notes (learned 2026-09-30):
- GetAddressUtxos returns GetAddressUtxosReplyList (field 1 = repeated
  GetAddressUtxosReply); each stream frame is the LIST wrapper, not the
  reply itself. The old version parsed frames as replies and printed garbage.
- Protobuf int32 negative values arrive as 10-byte varints; decode with
  sign extension (uint32 range -> int32).
"""
import argparse
import subprocess
import sys

ENDPOINT = "https://testnet.zec.rocks"
SERVICE = "cash.z.wallet.sdk.rpc.CompactTxStreamer"


def varint(n):
    out = b""
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out += bytes([b | 0x80])
        else:
            out += bytes([b])
            break
    return out


def f_bytes(num, data):
    return varint((num << 3) | 2) + varint(len(data)) + data


def grpc_frame(payload):
    return b"\x00" + len(payload).to_bytes(4, "big") + payload


def parse_varint(buf, pos):
    r, s = 0, 0
    while True:
        b = buf[pos]
        pos += 1
        r |= (b & 0x7F) << s
        if not b & 0x80:
            return r, pos
        s += 7


def parse_fields(buf):
    f = {}
    pos = 0
    while pos < len(buf):
        tag, pos = parse_varint(buf, pos)
        num, wire = tag >> 3, tag & 7
        if wire == 0:
            v, pos = parse_varint(buf, pos)
            f.setdefault(num, []).append(v)
        elif wire == 2:
            ln, pos = parse_varint(buf, pos)
            f.setdefault(num, []).append(buf[pos : pos + ln])
            pos += ln
        elif wire == 5:
            f.setdefault(num, []).append(int.from_bytes(buf[pos : pos + 4], "little"))
            pos += 4
        elif wire == 1:
            f.setdefault(num, []).append(int.from_bytes(buf[pos : pos + 8], "little"))
            pos += 8
        else:
            raise ValueError(f"bad wire type {wire}")
    return f


def to_i32(v):
    """Sign-extend a protobuf int32 (arrives as up-to-64-bit varint)."""
    v &= 0xFFFFFFFF
    return v - 0x100000000 if v & 0x80000000 else v


def split_frames(body):
    frames = []
    pos = 0
    while pos + 5 <= len(body):
        ln = int.from_bytes(body[pos + 1 : pos + 5], "big")
        payload = body[pos + 5 : pos + 5 + ln]
        if len(payload) < ln:
            break
        frames.append(payload)
        pos += 5 + ln
    return frames


def call(method, payload, timeout=30):
    url = f"{ENDPOINT}/{SERVICE}/{method}"
    frame = grpc_frame(payload)
    p = subprocess.run(
        [
            "curl", "-s", "--http2", "--http2-prior-knowledge",
            "-X", "POST",
            "-H", "content-type: application/grpc",
            "-H", "te: trailers",
            "--data-binary", "@-",
            "--max-time", str(timeout),
            url,
        ],
        input=frame,
        capture_output=True,
    )
    if p.returncode != 0:
        print(f"curl failed rc={p.returncode}: {p.stderr.decode()[:200]}", file=sys.stderr)
        sys.exit(1)
    return split_frames(p.stdout)


def show_info():
    frames = call("GetLightdInfo", b"")
    info = parse_fields(frames[0])
    chain = info.get(4, [b"?"])[0].decode()
    height = info.get(7, [0])[0]
    print(f"lightd: chain={chain} tip={height} version={info.get(1,[b''])[0].decode()}")
    if chain != "test":
        print("NOT TESTNET — abort", file=sys.stderr)
        sys.exit(1)


def show_tip():
    frames = call("GetLatestBlock", b"")
    b = parse_fields(frames[0])
    print(f"tip: height={to_i32(b.get(1,[0])[0])} hash={b.get(2,[b''])[0][::-1].hex()}")


def show_utxos(address):
    # AddressFilter: field 1 = address (string)
    arg = f_bytes(1, address.encode())
    frames = call("GetAddressUtxos", arg)
    replies = []
    for fr in frames:
        lst = parse_fields(fr)
        # GetAddressUtxosReplyList: field 1 = repeated GetAddressUtxosReply
        for raw in lst.get(1, []):
            replies.append(parse_fields(raw))
    print(f"utxos for {address}: {len(replies)}")
    for r in replies:
        txid = r.get(1, [b""])[0][::-1].hex()
        idx = to_i32(r.get(2, [0])[0])
        script = r.get(3, [b""])[0].hex()
        val = r.get(4, [0])[0]
        h = to_i32(r.get(5, [0])[0])
        addr = r.get(6, [b""])[0].decode()
        print(f"  txid={txid} vout={idx} value={val} zat height={h}")
        print(f"  script={script}")
        print(f"  addr={addr}")


def show_tx(txid_display):
    # TxFilter: field 3 = hash (bytes, internal order)
    h = bytes.fromhex(txid_display)[::-1]
    arg = f_bytes(3, h)
    frames = call("GetTransaction", arg)
    # Each frame IS a RawTransaction: field 1 = data (bytes), field 2 = height.
    found = False
    for fr in frames:
        r = parse_fields(fr)
        data = r.get(1, [b""])[0]
        if not data:
            continue
        found = True
        hgt = r.get(2, [0])[0]
        print(f"  height={hgt} raw_len={len(data)} raw_hex={data.hex()}")
    if not found:
        print("  (no mempool/confirmed data returned for this txid)")


def show_mempool():
    # GetMempoolTx(Empty) -> stream CompactTx; field 1 = hash (internal order)
    frames = call("GetMempoolTx", b"")
    print(f"mempool: {len(frames)} tx(s)")
    for fr in frames:
        r = parse_fields(fr)
        h = r.get(1, [b""])[0]
        if h:
            print(f"  {h[::-1].hex()}")


def main():
    ap = argparse.ArgumentParser(description="lightwalletd testnet query")
    ap.add_argument("--info", action="store_true", help="GetLightdInfo")
    ap.add_argument("--tip", action="store_true", help="GetLatestBlock")
    ap.add_argument("--address", help="address for GetAddressUtxos")
    ap.add_argument("--tx", help="display txid for GetTransaction")
    ap.add_argument("--mempool", action="store_true", help="list mempool txids")
    args = ap.parse_args()

    if args.info or not (args.address or args.tx or args.tip or args.mempool):
        show_info()
    if args.tip:
        show_tip()
    if args.address:
        show_utxos(args.address)
    if args.tx:
        show_tx(args.tx)
    if args.mempool:
        show_mempool()


if __name__ == "__main__":
    main()
