# Frostgate — Dependency & License Inventory

Generated 2026-09-30 from `Cargo.lock` and vendored crate metadata
(`~/.cargo/registry/src/*`). Versions pinned by `Cargo.lock` at the repo root.

## License posture

- **Frostgate's own crates** (`frostgate-federation`, `frostgate-bitcoin`,
  `frostgate-zcash`, `frostgate-operator`, `frostgate-coordinator`): each declares
  `license = "MIT OR Apache-2.0"` in its `Cargo.toml`.
- **Every direct third-party dependency is permissive.** No GPL, AGPL, LGPL, or
  other copyleft licenses anywhere in the direct dependency set. Indirect
  (transitive) dependencies were not exhaustively audited; run `cargo deny` /
  `cargo license` before a production release if you need a full SBOM.

## Direct dependencies

| Crate | Locked version | License | Role in Frostgate |
|---|---|---|---|
| frost-core | 3.0.0 | MIT OR Apache-2.0 | Zcash Foundation FROST protocol core (RFC 9591) — DKG, signing rounds, aggregation, cheater detection |
| frost-secp256k1-tr | 3.0.0 | MIT OR Apache-2.0 | ZF FROST ciphersuite for secp256k1 with Taproot (BIP341) tweak support |
| bitcoin | 0.32.102 | CC0-1.0 | rust-bitcoin: P2TR address derivation, Taproot sighash, transaction building |
| bitcoin_hashes | 0.14.101 | CC0-1.0 | Tagged hashes (TapTweak), hash160 for Zcash P2PKH |
| ureq | 2.12.1 | MIT OR Apache-2.0 | HTTP client for Esplora watcher and Zcash JSON-RPC (TLS, proxy-aware) |
| thiserror | 2.0.21 | MIT OR Apache-2.0 | Error enums across crates |
| serde | 1.0.229 | MIT OR Apache-2.0 | Serialization of key material and attestations |
| serde_json | 1.0.151 | MIT OR Apache-2.0 | JSON persistence (operator files, journal, RPC) |
| rand | 0.8.8 | MIT OR Apache-2.0 | CSPRNG for DKG and fresh signing nonces |
| rand_core | 0.6.4 | MIT OR Apache-2.0 | RNG trait bounds |
| clap | 4.6.7 | MIT OR Apache-2.0 | Operator and coordinator CLIs |
| anyhow | 1.0.104 | MIT OR Apache-2.0 | CLI error propagation |
| tempfile | 3.27.0 | MIT OR Apache-2.0 | Test fixtures (dev-dependency use) |
| base64 | 0.22.1 | MIT OR Apache-2.0 | RPC auth encoding |

## Cryptography provenance (for the security-minded reader)

- Threshold signing is **built on the Zcash Foundation's FROST implementation**
  (RFC 9591), not a from-scratch protocol. Do not describe Frostgate as an
  "audited bridge": the FROST core crates were NCC-audited, but
  `frost-secp256k1-tr` was **outside** that audit scope.
- FROST shares are Schnorr shares. They cannot produce ECDSA signatures; the
  Zcash release leg therefore uses a coordinator-held hot key for the
  transparent transaction, with the *authorization* (the attestation) carrying
  the threshold signature. This is documented as a trust boundary, not hidden.

## Reproducing this inventory

```bash
cargo tree --depth 1            # direct deps
cargo tree                       # full transitive tree
grep -m1 '^license' ~/.cargo/registry/src/*/frost-core-3.0.0/Cargo.toml
```
