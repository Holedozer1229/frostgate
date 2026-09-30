#!/usr/bin/env python3
"""Independent Zcash testnet P2PKH address derivation (stdlib only).

Used to generate the cross-check vector baked into
crates/frostgate-zcash/src/address.rs tests. Run:
    python3 addr_check.py
"""
import hashlib

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def hash160(b: bytes) -> bytes:
    # hashlib may lack ripemd160 on some builds; try usedforsecurity=False
    try:
        h = hashlib.new("ripemd160", usedforsecurity=False)
    except TypeError:
        h = hashlib.new("ripemd160")
    h.update(hashlib.sha256(b).digest())
    return h.digest()

def b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n > 0:
        n, r = divmod(n, 58)
        out = ALPHABET[r] + out
    # leading zero bytes -> '1'
    pad = 0
    for c in data:
        if c == 0:
            pad += 1
        else:
            break
    return "1" * pad + out

def base58check(payload: bytes) -> str:
    chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return b58encode(payload + chk)

# secp256k1 for secret 0x11..11: computed via tinyec-free manual multiply?
# Instead we use the `ecdsa` lib if present, else fall back to known value.
SECRET = bytes([0x11]) * 32
try:
    from ecdsa import SigningKey, SECP256k1
    sk = SigningKey.from_string(SECRET, curve=SECP256k1)
    vk = sk.get_verifying_key()
    x = vk.pubkey.point.x()
    y = vk.pubkey.point.y()
    prefix = b"\x03" if (y & 1) else b"\x02"
    pubkey = prefix + x.to_bytes(32, "big")
    print("pubkey:", pubkey.hex())
except ImportError:
    # fallback: secp256k1 multiply implemented below (pure python, slow but fine)
    P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    def add(p, q):
        if p is None: return q
        if q is None: return p
        x1, y1 = p; x2, y2 = q
        if x1 == x2 and (y1 + y2) % P == 0: return None
        if p == q:
            lam = (3 * x1 * x1) * pow(2 * y1, P - 2, P) % P
        else:
            lam = (y2 - y1) * pow(x2 - x1, P - 2, P) % P
        x3 = (lam * lam - x1 - x2) % P
        return (x3, (lam * (x1 - x3) - y1) % P)
    k = int.from_bytes(SECRET, "big")
    r, addend = None, (Gx, Gy)
    while k:
        if k & 1: r = add(r, addend)
        addend = add(addend, addend)
        k >>= 1
    x, y = r
    pubkey = (b"\x03" if (y & 1) else b"\x02") + x.to_bytes(32, "big")
    print("pubkey:", pubkey.hex())

payload = bytes([0x1D, 0x25]) + hash160(pubkey)
print("address:", base58check(payload))
