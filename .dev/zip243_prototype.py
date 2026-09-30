#!/usr/bin/env python3
"""ZIP-243 sighash prototype (BLAKE2b-256, per spec).

Verifies the correct sighash for our D7 release tx before porting to Rust.
"""
import hashlib

def blake2b_256(personalization: bytes, data: bytes) -> bytes:
    h = hashlib.blake2b(data, digest_size=32, person=personalization)
    return h.digest()

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
# Consensus branch ID from lightwalletd GetLightdInfo (testnet, 2026-09-30)
BRANCH_ID = 0x37A5165B

def ser_prevout(txid_internal: bytes, vout: int) -> bytes:
    return txid_internal + vout.to_bytes(4, "little")

def ser_output(value: int, script: bytes) -> bytes:
    return value.to_bytes(8, "little") + compactsize(len(script)) + script

def sighash(tx, input_index, script_code, input_value):
    ins = tx["inputs"]
    outs = tx["outputs"]

    hash_prevouts = blake2b_256(
        b"ZcashPrevoutHash",
        b"".join(ser_prevout(i["txid"], i["vout"]) for i in ins),
    )
    hash_sequence = blake2b_256(
        b"ZcashSequencHash",
        b"".join(i["seq"].to_bytes(4, "little") for i in ins),
    )
    hash_outputs = blake2b_256(
        b"ZcashOutputsHash",
        b"".join(ser_output(o["value"], o["script"]) for o in outs),
    )
    # Empty vectors -> zeros (per ZIP-243 spec, NOT sha256d(empty))
    zero32 = bytes(32)

    personalization = b"ZcashSigHash" + BRANCH_ID.to_bytes(4, "little")

    pre = b""
    pre += VERSION.to_bytes(4, "little")
    pre += VERSION_GROUP_ID.to_bytes(4, "little")
    pre += hash_prevouts
    pre += hash_sequence
    pre += hash_outputs
    pre += zero32  # hashJoinSplits
    pre += zero32  # hashShieldedSpends
    pre += zero32  # hashShieldedOutputs
    pre += tx["locktime"].to_bytes(4, "little")
    pre += tx["expiry"].to_bytes(4, "little")
    pre += (0).to_bytes(8, "little", signed=True)  # valueBalanceSapling
    pre += SIGHASH_ALL.to_bytes(4, "little")
    inp = ins[input_index]
    pre += ser_prevout(inp["txid"], inp["vout"])
    pre += compactsize(len(script_code)) + script_code
    pre += input_value.to_bytes(8, "little")
    pre += inp["seq"].to_bytes(4, "little")

    return blake2b_256(personalization, pre)

if __name__ == "__main__":
    # Our D7 tx
    faucet_txid = bytes.fromhex("c92cb7e4834c47876a0cba4e6b28e25f747c24ec5c9127549f6aa07a045baf8b")[::-1]
    vault_script = bytes.fromhex("76a914c3e89ec5dadf63b4a653146012e32b97cf195f4e88ac")
    dest_script = bytes.fromhex("76a9148675b22607e813f42788fe2ff7bad6b78db28c7088ac")

    tx = {
        "inputs": [{"txid": faucet_txid, "vout": 0, "seq": 0xFFFFFFFF}],
        "outputs": [
            {"value": 9_000_000, "script": dest_script},
            {"value": 990_000, "script": vault_script},
        ],
        "locktime": 0,
        "expiry": 4_425_000,
    }
    sh = sighash(tx, 0, vault_script, 10_000_000)
    print(f"sighash: {sh.hex()}")
    print(f"sighash display (reversed): {sh[::-1].hex()}")
