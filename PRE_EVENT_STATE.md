# PRE-EVENT STATE — Frostgate: Threshold Federation Bridge

Disclosure of pre-existing work. Written **2026-09-30**, before any hackathon-judged
work began. Colosseum World's Fair rules judge only work done Sep 14 – Oct 12, 2026
and require pre-existing code to be disclosed. This file is that disclosure.

## What existed BEFORE Sep 30, 2026 (baseline, not judged work)

1. **`~/workspace/genesis_fork/aetherion/aetherion_bridge.py`** (468 lines) plus
   **`test_aetherion_bridge.py`** (381 lines, 29/29 passing):
   a federated, attested, **off-chain** bridge LEDGER connecting Aetherion coins to
   the EXCAL Genesis Fork chain. M-of-N operator quorum, 30 bps toll, replay
   protection, supply invariant (`outstanding == minted - burned`). Pure Python,
   stdlib only. Built September 2026 (production fee schedule set 2026-09-21).
   This is the *design* baseline: the operator-quorum model and the MINT/RELEASE
   attestation flow. None of its code is reused verbatim in the new build —
   different language, different chain pair, different cryptography.

2. **`~/workspace/genesis_fork/mldsa.py`**: pure-Python ML-DSA-65, bit-for-bit
   KAT-verified against the C reference (2026-09-21). Relevant ONLY if the
   post-quantum operator-authentication stretch goal is built; if used, it is
   disclosed here as pre-existing.

3. General prior art (not code): solo BTC mining infrastructure, Stratum/pool
   plumbing, secp256k1 tooling. No FROST code of any kind existed in any prior work.

## What is NEW (judged work, Sep 30 – Oct 12, 2026)

Everything in this repository:
- Rust workspace: FROST distributed key generation + threshold signing sessions
  via the Zcash Foundation's `frost` crates (RFC 9591), pinned ≥ 2.2.0.
- Taproot (BIP340/BIP341) federation key: the 3-of-5 operator quorum holds a
  single P2TR key-path address; attestations are single 64-byte Schnorr signatures.
- Bitcoin testnet3 peg-in watcher (Esplora).
- Zcash testnet release path (shielded recipient).
- Coordinator service + operator relay.
- Adversarial demo: liveness with 2-of-5 offline, cheater identification/exclusion.
- Pitch + demo videos showing real testnet transactions.

The chain pair (BTC testnet ↔ ZEC testnet) is new. The threshold-signing ceremony,
the Taproot custody, and the coordinator are new. The unfair advantage being
disclosed and rolled with: a working federated-bridge design and operator-quorum
experience, so the 10-day budget buys the FROST heart transplant — not a bridge
from zero.
