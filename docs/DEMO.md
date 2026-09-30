# Frostgate — Reproducible Demo

*Everything a judge needs to reproduce the Frostgate demo, in order.
Prerequisites: Rust ≥ 1.98 (`rustup` toolchain), `python3`, network access.
No API keys. All commands run from the repo root.*

## 0. Verify the test suite (2 min)

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cargo test --workspace
# expect: 60 passed, 0 failed, 2 ignored
cargo clippy --workspace -- -D warnings   # expect: clean
```

## 1. Dealerless DKG ceremony (30 s)

Five operators, threshold 3, no trusted dealer:

```bash
cargo run -q -p frostgate-operator -- dkg --operators 5 --threshold 3 --out ./ceremony
cargo run -q -p frostgate-operator -- federation-address --ceremony ./ceremony
# prints the single Taproot (P2TR) address all five operators independently derive.
# Key packages are written mode 0600; inspect with: ls -l ./ceremony
```

## 2. Adversarial coordinator demo (1 min, no network)

Three fault modes. Each run performs a fresh in-process DKG, drives the
`OperatorRelay`, and settles a mock peg-in through `CoordinatorService`:

```bash
# Honest quorum: attestation signed, release built, journal written.
cargo run -q -p frostgate-coordinator -- demo --fault none

# Two operators offline: the remaining three still form a quorum and settle.
cargo run -q -p frostgate-coordinator -- demo --fault offline:1,2

# One malicious operator: bad share is detected, attributed, excluded;
# the session retries with fresh nonces and settles; a replay is refused.
cargo run -q -p frostgate-coordinator -- demo --fault malicious:2
```

Expected in the malicious run: `EXCLUDED CHEATERS (bad share detected +
attributed): [2]`, followed by a successful settlement and a replay refusal.

## 3. Live quorum settlement on Zcash testnet (2 min, network)

The full path — fresh DKG → quorum-signed attestation → independent
aggregate-signature verification → v4 transparent release → live broadcast
via `testnet.zec.rocks:443`:

```bash
cargo run -q -p frostgate-coordinator --example d8_demo_live
```

Expected output (values vary per run; structure does not):

```
=== Frostgate D8: live quorum settlement (testnet) ===

DKG complete: 5 operators, threshold 3
vault: tmTaDmKA1kc43EVxzefNdHBszy2DV4zpjXr
lightwalletd tip: 4420002
dest:  tmF4wMJyh1X9nxKz2RY7x3i9QyLWyRgnExn

peg-in (SYNTHETIC REHEARSAL): ae2ad897…:0 (100000 sats)
running FROST attestation + quorum signing...

--- settlement report ---
attestation message: …
quorum signers: [1, 2, 3]
excluded cheaters: []
release: 100000 zat to tmF4wMJyh1X9nxKz2RY7x3i9QyLWyRgnExn
toll: 300 zat (30 bps)
quorum signature re-verifies: (checked inside settle)
ZEC release txid (LIVE broadcast): 7f6cc65612b6f7e79ee679bf64013204d3ce92486269cd705330ad78f4db11bd

verify: python3 .dev/lwd_query.py --tx 7f6cc65612b6f7e79ee679bf64013204d3ce92486269cd705330ad78f4db11bd
```

The peg-in is a **labeled synthetic rehearsal peg-in** (the BTC peg-in leg was
proven separately on Bitcoin regtest — txid `c3dbc434…f977676`, block 103).
What this exercises is the quorum authorization → ZEC release path.

Verify independently (no trust in our output):

```bash
python3 .dev/lwd_query.py --tx <txid>     # raw transaction from the node
python3 .dev/lwd_query.py --tip           # chain tip; confirmations = tip - height
```

The historical live releases (all independently verifiable on testnet):

| Run | Txid | Mined at | Release |
|---|---|---|---|
| D7 (direct) | `aa8972f2829ef07ab9efa7b636f38f83df859e9db0dfa0eca56cefdf5d785b5c` | 4,419,993 | 9,000,000 zat |
| D7b (quorum) | `54a36d22f06f22740ccc061612decba7cd7a58203df9d68179e26a64dd52a8c6` | 4,419,998 | 100,000 zat |
| D8 (quorum) | `7f6cc65612b6f7e79ee679bf64013204d3ce92486269cd705330ad78f4db11bd` | 4,420,002 | 100,000 zat |

## 4. What the demo does NOT show (honesty section)

- The ZEC-side vault is a **coordinator-held hot key**, not a threshold key:
  FROST is Schnorr and Zcash transparent inputs need ECDSA. The 3-of-5 quorum
  controls *authorization* (it threshold-signs the exact release attestation,
  which the coordinator independently re-verifies); execution is 1-of-1. This
  is documented in the README and `crates/frostgate-zcash/src/keys.rs`.
- The demo `OperatorRelay` is an in-process transport. Production needs
  authenticated operator channels; the coordinator is trusted for liveness.
- Testnet only. No mainnet funds have touched this code.

## 5. One-command full pass

```bash
cargo test --workspace && \
cargo run -q -p frostgate-coordinator -- demo --fault malicious:2 && \
cargo run -q -p frostgate-coordinator --example d8_demo_live
```
