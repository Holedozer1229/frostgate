#!/usr/bin/env python3
"""Independent Zcash v4 transparent sighash (ZIP-143/ZIP-243) implementation.

From-scratch implementation used to cross-validate the Rust code in
crates/frostgate-zcash/src/tx.rs. Run:
    python3 zip143_check.py
Prints sighash + serialized tx for a fixed fixture; the Rust test
`tx::tests::sighash_matches_independent_python_vector` pins these values.
"""
import hashlib

def sha256d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def compactsize(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")

VERSION = 0x80000004
VERSION_GROUP_ID = 0x892F2085
SIGHASH_ALL = 1

def ser_prevout(txid_internal: bytes, vout: int) -> bytes:
    return txid_internal + vout.to_bytes(4, "little")

def ser_output(value: int, script: bytes) -> bytes:
    return value.to_bytes(8, "little") + compactsize(len(script)) + script

def sighash(unsigned: dict, input_index: int, script_code: bytes, input_value: int) -> bytes:
    ins = unsigned["inputs"]
    outs = unsigned["outputs"]
    hash_prevouts = sha256d(b"".join(ser_prevout(i["txid"], i["vout"]) for i in ins))
    hash_sequence = sha256d(b"".join(i["seq"].to_bytes(4, "little") for i in ins))
    hash_outputs = sha256d(b"".join(ser_output(o["value"], o["script"]) for o in outs))
    # Empty vectors hash to SHA256d(empty), NOT zeros (BIP-143/ZIP-243).
    # Corrected 2026-09-30 after live ScriptInvalid rejection.
    hash_empty = sha256d(b"")
    pre = b""
    pre += VERSION.to_bytes(4, "little")
    pre += VERSION_GROUP_ID.to_bytes(4, "little")
    pre += hash_prevouts
    pre += hash_sequence
    pre += hash_outputs
    pre += hash_empty  # hashJoinSplits (none)
    pre += hash_empty  # hashShieldedSpends (none)
    pre += hash_empty  # hashShieldedOutputs (none)
    pre += unsigned["locktime"].to_bytes(4, "little")
    pre += unsigned["expiry"].to_bytes(4, "little")
    pre += (0).to_bytes(8, "little", signed=True)  # valueBalanceSapling
    pre += SIGHASH_ALL.to_bytes(4, "little")
    inp = ins[input_index]
    pre += ser_prevout(inp["txid"], inp["vout"])
    pre += compactsize(len(script_code)) + script_code  # scriptCode as CScript
    pre += input_value.to_bytes(8, "little")
    pre += inp["seq"].to_bytes(4, "little")
    return sha256d(pre), pre

def ser_tx(unsigned: dict, script_sigs: list) -> bytes:
    out = b""
    out += VERSION.to_bytes(4, "little")
    out += VERSION_GROUP_ID.to_bytes(4, "little")
    out += compactsize(len(unsigned["inputs"]))
    for i, s in zip(unsigned["inputs"], script_sigs):
        out += ser_prevout(i["txid"], i["vout"])
        out += compactsize(len(s)) + s
        out += i["seq"].to_bytes(4, "little")
    out += compactsize(len(unsigned["outputs"]))
    for o in unsigned["outputs"]:
        out += ser_output(o["value"], o["script"])
    out += unsigned["locktime"].to_bytes(4, "little")
    out += unsigned["expiry"].to_bytes(4, "little")
    out += (0).to_bytes(8, "little", signed=True)  # valueBalanceSapling
    out += compactsize(0)  # nShieldedSpend
    out += compactsize(0)  # nShieldedOutput
    out += compactsize(0)  # nJoinSplit
    return out

if __name__ == "__main__":
    # Fixture: spend a P2PKH output.
    # funding txid (display order): 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33d
    funding_display = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33d"
    txid_internal = bytes.fromhex(funding_display)[::-1]
    pkh = bytes.fromhex("751e76e8199196d454941c45d1b3a323f1433bd6")
    script_pubkey = bytes([0x76, 0xA9, 0x14]) + pkh + bytes([0x88, 0xAC])
    dest_pkh = bytes.fromhex("b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0")  # 20 bytes
    dest_script = bytes([0x76, 0xA9, 0x14]) + dest_pkh + bytes([0x88, 0xAC])
    unsigned = {
        "inputs": [{"txid": txid_internal, "vout": 1, "seq": 0xFFFFFFFF}],
        "outputs": [
            {"value": 49_000_000, "script": dest_script},
            {"value": 900_000, "script": script_pubkey},  # change
        ],
        "locktime": 0,
        "expiry": 2_900_100,
    }
    sh, pre = sighash(unsigned, 0, script_pubkey, 50_000_000)
    print("sighash:", sh.hex())
    print("sighash_display:", sh[::-1].hex())
    print("preimage_len:", len(pre))
    raw = ser_tx(unsigned, [b""])
    print("unsigned_len:", len(raw))
    txid = sha256d(raw)
    print("unsigned_txid_display:", txid[::-1].hex())
