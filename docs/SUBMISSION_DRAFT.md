# Frostgate — Colosseum Submission Draft

*Prepared 2026-09-30. Travis authorized Hal to submit. Deadline: **Oct 12, 2026, 11:59 PM PDT** (official, from colosseum.com/worldsfair). Zcash track: **$100,000 pool — 10 projects × $10,000** (per event coverage; the official prizes page lists the $840,000 total without a per-track breakdown). Total hackathon prizes: $840,000 + $2.5M accelerator seed funding (official).*

> ⚠️ **Action needed:** Travis's Arena profile is INCOMPLETE — the dashboard banner says "Complete your profile ... to be eligible to compete." Builder details (bio, skills, links) show "Nothing to see here!" This must be fixed before submission.

## Project name
Frostgate

## Tagline
Threshold custody for cross-chain bridges — five operators, one key that never exists.

## Track
Zcash

## Repository
https://github.com/Holedozer1229/frostgate (public, MIT/Apache-2.0)

## Videos (Colosseum-spec versions, unlisted)
- Elevator pitch (0:32, spec: 30-second pitch): https://youtu.be/3hty44PFQH0
- Technical walkthrough (3:39, spec: 3–5 minute video): https://youtu.be/BjN5Y7RLgYU
- Earlier cuts (superseded, still unlisted): pitch https://youtu.be/2GzfhwevnXI, demo https://youtu.be/y39ULUT2C3U

## Logo
`~/workspace/frostgate/assets/frostgate-logo.webp` — five shards converging on a keyhole.

## Description (for the form)

Frostgate is threshold-federation custody infrastructure for cross-chain bridges. Five independent operators run a dealerless 3-of-5 FROST ceremony (RFC 9591, Zcash Foundation implementation) and jointly control a single Bitcoin Taproot address. The full key never exists at any point in time; the quorum produces one 64-byte BIP340 Schnorr signature on-chain, indistinguishable from a normal Taproot spend.

The bridge settles across chains: the FROST quorum signs an exact ReleaseAttestation, and a coordinator verifies the aggregate signature before constructing the Zcash testnet release. The adversarial demo shows the failure modes handled in production: an offline quorum still settles, a malicious operator is cryptographically identified and excluded mid-session, and replayed attestations are refused.

Live on testnet: the full path — fresh 5-of-3 DKG → quorum settlement → broadcast — has settled real transactions on the Zcash testnet, independently verified against a live node (heights 4,419,998 through 4,420,003). The Bitcoin leg is proven with a live threshold spend on regtest.

Trust model is documented honestly in the repo: threshold custody on the Bitcoin side, threshold authorization with a coordinator-held release key on the Zcash side (structural — FROST Schnorr shares cannot produce Zcash's ECDSA signatures), with a threshold-ECDSA roadmap item to remove it.

Pre-existing work is disclosed day-one in PRE_EVENT_STATE.md: a federated M-of-N bridge design (30-bps toll, replay protection, supply invariants) built before the event. The new work is the FROST heart transplant — dealerless threshold custody replacing the old trust assumptions.

## Team
Travis Jones (@AetherionQASI, Blanco, TX) — founder. Independent researcher and systems builder: from-scratch ML-DSA-65 (bit-for-bit KAT verified), Bitcoin mining/Stratum infrastructure, federated bridge ledger.

## Technical stack
Rust (cargo workspace, 5 crates), Zcash Foundation FROST (RFC 9591), Bitcoin Taproot (BIP340 Schnorr), Zcash transparent testnet (ZIP-243 BLAKE2b-256 sighash, pure-Rust implementation), secp256k1, tokio async relay, lightwalletd.

## Chains / tools
Bitcoin (testnet path proven on regtest), Zcash (testnet, live settlements).

## License / IP
Core crates MIT/Apache-2.0 dual license. All-permissive dependency tree (no copyleft) — see LICENSES.md in the repo.

## Prior development disclosure
Yes — disclosed in PRE_EVENT_STATE.md in the repo root: pre-event federated M-of-N bridge design with 30-bps toll schedule, replay protection, supply invariants. All threshold-cryptography work (DKG, FROST ceremony, operator relay, coordinator settlement, Zcash BLAKE2b-256 sighash) was built during the hackathon.

## Business framing (from docs/BUSINESS_PLAN.md)
Problem: bridges are crypto's #1 loss vector (Ronin $625M via key compromise; Poly $611M, Wormhole $326M, Nomad $190M via contract verification bugs) — every one a failure of the bridge's trust assumptions. Product: threshold-federation custody with no trusted dealer. Revenue lanes: 30-bps bridge toll (inherited design), quorum-as-a-service, mainnet custody pilot. Ask: $250k pre-seed via the Colosseum accelerator.
