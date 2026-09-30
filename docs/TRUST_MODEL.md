# Frostgate — Trust Model

*Stated precisely, in writing, before any mainnet conversation. If a sentence
here is wrong, the code is wrong — file an issue.*

## What the 3-of-5 quorum guarantees

1. **No single key exists.** The Bitcoin custody key is the FROST group key.
   It was never assembled: the dealerless DKG means no party ever held it.
   Stealing any one (or two) operator machines yields shares, not a key.
2. **No unilateral spend.** A valid Taproot signature requires 3 of the 5
   share-holders to participate in a signing session. Below threshold, funds
   freeze — they are not lost, and they cannot be moved.
3. **Cheaters are named, not just tolerated.** A malformed signing share is
   detected during aggregation, attributed to its operator index, and
   excluded; the session retries with fresh nonces. (`demo --fault
   malicious:2` demonstrates this.)
4. **Releases are quorum-authorized, exactly.** The ZEC release is built only
   after the operators threshold-sign a `ReleaseAttestation` naming the exact
   destination address, amount, peg-in outpoint, and toll. The coordinator
   independently re-verifies the aggregate FROST signature before constructing
   any transaction. An attestation for (addr A, 100k) cannot release to
   (addr B, 200k).
5. **No replay.** The settlement journal records consumed peg-ins; a second
   settlement attempt for the same peg-in is refused.

## What the quorum does NOT guarantee (residual trust)

1. **ZEC execution is 1-of-1.** The coordinator holds the Zcash vault hot
   key. FROST (RFC 9591) is a Schnorr scheme; Zcash transparent inputs
   require ECDSA, so the threshold shares cannot directly sign the ZEC spend.
   A malicious coordinator could move vault funds without — or against — a
   quorum attestation. The quorum gives *authorization and accountability*
   (every legitimate release carries a publicly verifiable 3-of-5
   attestation), not threshold custody, on the ZEC leg.
2. **Coordinator liveness.** The coordinator builds signing packages and
   relays messages. It cannot forge a FROST signature, but it can stall,
   censor, or equivocate between operators.
3. **Demo transport.** The `OperatorRelay` in this repo is in-process. Real
   operators need mutually authenticated channels (Noise/TLS + identity
   keys), which do not exist yet.
4. **No threshold ECDSA.** Deliberately out of scope: rolling a new
   unaudited threshold-ECDSA protocol would be less safe than the attestation
   design. Candidate paths: a second ceremony with an audited threshold-ECDSA
   (e.g. CGGMP21) for the ZEC leg, or a Zcash-side Schnorr-capable vault
   (e.g. a Taproot-style script on a future Zcash upgrade).

## Assumptions

- The Zcash Foundation `frost-secp256k1` crates are correct (they were
  NCC-audited; `frost-secp256k1-tr` was outside that audit's scope — noted,
  not hidden).
- `rust-bitcoin`/`rust-secp256k1` are correct (BIP341 tweak cross-checked
  byte-for-byte).
- Testnet only. The threat model above has not been reviewed by an external
  auditor; the $100K track prize is earmarked to fund exactly that.

## What "trustless" would require (not claimed)

A two-way trustless peg is impossible on today's Bitcoin and Zcash: neither
chain can verify the other's consensus. Anyone selling a two-way trustless
BTC↔ZEC bridge is selling theater. Frostgate claims the achievable thing — a
federation whose custody key provably never existed in one place — and states
the residual trust in writing.
