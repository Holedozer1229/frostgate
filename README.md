# Frostgate — Threshold Federation Custody for Cross-Chain Bridges

**Bridges are crypto's #1 loss vector — every major bridge hack was a failure
of the bridge's trust assumptions: Ronin fell to compromised validator keys;
Poly, Wormhole, and Nomad fell to contract-level verification bugs.** Frostgate removes the
key entirely. Five independent operators jointly custody a single Bitcoin
Taproot address through a **dealerless 3-of-5 FROST threshold ceremony** (built
on the Zcash Foundation's RFC 9591 implementation). No single operator ever
holds the key. No trusted dealer ever existed. Two operators can go offline
and the bridge keeps settling; a cheating operator is detected, named, and
excluded automatically.

Frostgate is being built as a company, not a demo: threshold-federation
custody as infrastructure, with operator-quorum-as-a-service and a 30-bps
bridge toll as the revenue engine. See [docs/BUSINESS_PLAN.md](docs/BUSINESS_PLAN.md).

> **Status labels.** Every claim in this README is tagged: **[IMPLEMENTED]** (code
> exists), **[MEASURED]** (ran and observed), or **planned** (not yet built).
> The demo never claims more than the measurements support.

## What works today (Sep 30, 2026)

- **[IMPLEMENTED + MEASURED]** Dealerless 5-of-3 FROST DKG — no trusted dealer, key shares persisted mode 0600.
- **[IMPLEMENTED + MEASURED]** Single Taproot (P2TR) federation address; the on-chain key commits to the threshold group key via the BIP341 tweak, and all five operators independently derive the identical tweak (verified byte-for-byte against rust-bitcoin).
- **[IMPLEMENTED + MEASURED]** Live threshold spend on Bitcoin regtest: federation funded with 1.0 BTC, operators 1–3 signed, spend confirmed — txid `c3dbc434d47fd6a27987241bf8384c936630cfa1f83656673ddf87fbbf977676`, mined in regtest block 103, federation balance 0.0 afterward.
- **[IMPLEMENTED + MEASURED]** Bitcoin testnet3 peg-in watcher over public Esplora (`blockstream.info/testnet/api`), proxy-aware.
- **[IMPLEMENTED + MEASURED]** Zcash testnet release path: v4 transparent transaction builder, ZIP-243 BLAKE2b-256 sighash (pure-Rust, personalized) and base58check address encoding cross-validated against independent from-scratch Python implementations — and against the live chain.
- **[IMPLEMENTED + MEASURED]** Coordinator service: peg-in → threshold attestation → ZEC release, with settlement journal and replay refusal.
- **[IMPLEMENTED + MEASURED]** Adversarial demo: two operators offline → quorum of 3 still settles; one malicious share → detected, attributed, excluded, session retried with fresh nonces.
- **[IMPLEMENTED + MEASURED]** Live Zcash testnet releases via lightwalletd (`testnet.zec.rocks:443`):
  - D7 (direct path): `aa8972f2829ef07ab9efa7b636f38f83df859e9db0dfa0eca56cefdf5d785b5c`, mined at height 4,419,993 — 9,000,000 zat released.
  - D7b (full quorum path): `54a36d22f06f22740ccc061612decba7cd7a58203df9d68179e26a64dd52a8c6`, mined at height 4,419,998 — fresh 5-of-3 DKG → quorum-signed attestation → 100,000 zat released.
  - D8 (reproducible quorum path): `7f6cc65612b6f7e79ee679bf64013204d3ce92486269cd705330ad78f4db11bd`, mined at height 4,420,002 — `cargo run -p frostgate-coordinator --example d8_demo_live` reproduces the full path end to end (each run mints a fresh txid and destination).
  - D8 rerun (auto-discovering vault UTXO): `1767009eee0a104682221fdfdebe7a141c1842bcc3d172e0eb85510f94289eda`, mined at height 4,420,003 — 100,000 zat released, 660,000 zat change. Current vault: `1767009e...:1` = 660,000 zat.
- **62 tests pass, 0 fail. `cargo clippy -- -D warnings` clean. `cargo fmt --check` clean.**

## Architecture

```
┌─────────────┐     peg-in (BTC testnet3)      ┌──────────────────┐
│   Bitcoin   │ ── Esplora watcher ──────────▶ │   Coordinator    │
│   testnet3  │                                │  (liveness only) │
└─────────────┘                                └────────┬─────────┘
                                                        │ attestation
                                                        ▼
┌─────────────┐    3-of-5 FROST signing        ┌──────────────────┐
│ 5 operators │ ◀─── commitments/shares ────── │  Operator relay  │
│ (threshold  │                                │  (demo transport)│
│     3)      │ ──▶ one 64-byte BIP340 sig ──▶ └──────────────────┘
└─────────────┘
                                                        │ release tx
                                                        ▼
                                               ┌──────────────────┐
                                               │  Zcash testnet   │
                                               │  (v4 transparent)│
                                               └──────────────────┘
```

Crates:

| Crate | Role |
|---|---|
| `frostgate-federation` | DKG ceremony, signing sessions, Taproot tweak, cheater attribution — the FROST core |
| `frostgate-bitcoin` | P2TR derivation, regtest/testnet spend builder, Esplora watcher |
| `frostgate-zcash` | Release-key management, P2PKH addressing, v4 tx builder, ZIP-143 sighash, RPC client |
| `frostgate-operator` | CLI: `dkg`, `federation-address`, `taproot-spend`, `demo-sign` |
| `frostgate-coordinator` | Settlement service + adversarial demo CLI (`demo`, `watch`) |

## Run the demo

Prerequisites: Rust ≥ 1.98 (`rustup` toolchain), no API keys needed.

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd frostgate

# 1. Run the dealerless DKG ceremony (5 operators, threshold 3)
cargo run -q -p frostgate-operator -- dkg --operators 5 --threshold 3 --out ./ceremony

# 2. Print the federation's Taproot address
cargo run -q -p frostgate-operator -- federation-address --ceremony ./ceremony

# 3. Run the coordinator demo — three fault modes:
cargo run -q -p frostgate-coordinator -- demo --fault none           # honest quorum
cargo run -q -p frostgate-coordinator -- demo --fault offline:1,2    # 2 operators down: still settles
cargo run -q -p frostgate-coordinator -- demo --fault malicious:2    # bad share: attributed + excluded
```

The `malicious:2` run prints `EXCLUDED CHEATERS (bad share detected + attributed): [2]`,
retries with a fresh quorum and fresh nonces, settles the release, then refuses a
replay of the same peg-in.

Watch mode (live Esplora polling + Zcash RPC release leg):

```bash
cargo run -q -p frostgate-coordinator -- watch \
  --ceremony ./ceremony \
  --release-key ./rehearsal/release-key.json \
  --zcash-rpc-url http://127.0.0.1:18232 --zcash-rpc-user user --zcash-rpc-pass pass \
  --vault-txid <funding-txid> --vault-vout 0 \
  --dest tmTaDmKA1kc43EVxzefNdHBszy2DV4zpjXr
```

## Security limitations (read before mainnet dreams)

- **Coordinator is trusted for liveness.** It builds signing packages and relays messages; it cannot forge a signature, but it can stall or equivocate. Production needs authenticated operator channels.
- **Demo relay trust gap.** The demo relay signs what the coordinator hands it; production operators must verify the attestation message and commitment set before signing.
- **ZEC release leg is a coordinator-held hot key.** FROST shares are Schnorr shares and cannot produce the ECDSA signatures Zcash transparent scripts require — this is a structural fact, not a bug. The threshold signature authorizes the release (attestation); the hot key executes it. Reducing this trust is future work (options: threshold ECDSA as a second ceremony, or a Zcash-side Schnorr-capable vault).
- **Below threshold, funds freeze — they are not lost.** A 3-of-5 federation tolerates 2 offline or malicious members; below 3, no signature is possible and the BTC stays at the federation address.
- **Built on Zcash Foundation's FROST implementation** — never "an audited bridge." The FROST core crates were NCC-audited; `frost-secp256k1-tr` was outside that audit scope.
- **Fresh nonces every session**, enforced structurally (a commitment pair is single-use; reuse is refused, not just discouraged).

## Disclosure

Day-one disclosure of pre-existing work vs. hackathon-judged work lives in
[PRE_EVENT_STATE.md](PRE_EVENT_STATE.md). The unfair advantage, stated plainly:
a working federated M-of-N bridge design and operator-quorum experience from
before the event — so the build budget bought the FROST heart transplant, not
a bridge from zero. The 30-bps toll in the attestation format is inherited from
that pre-existing design (currently attestation *metadata*; production must
withhold it from the release amount).

## Docs

- [PRE_EVENT_STATE.md](PRE_EVENT_STATE.md) — pre-event disclosure
- [docs/PITCH.md](docs/PITCH.md) — the 3-minute pitch + company case
- [docs/DEMO.md](docs/DEMO.md) — reproducible demo instructions
- [docs/TRUST_MODEL.md](docs/TRUST_MODEL.md) — trust model, stated precisely
- [D4_ZCASH_RELEASE_PATH.md](D4_ZCASH_RELEASE_PATH.md) — Zcash leg design + measurements
- [D5_D6_COORDINATOR.md](D5_D6_COORDINATOR.md) — coordinator + adversarial demo
- [LICENSES.md](LICENSES.md) — dependency & license inventory (all permissive, no copyleft)
- [docs/BUSINESS_PLAN.md](docs/BUSINESS_PLAN.md) — the company case

## License

MIT OR Apache-2.0. Built by Travis Jones ([@AetherionQASI](https://colosseum.com/arena/profiles/AetherionQASI)) for the Colosseum Crypto World's Fair.
