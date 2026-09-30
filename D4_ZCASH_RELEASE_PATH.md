# D4 — Zcash testnet release path: COMPLETE (code + tests)

Date: 2026-09-30. Crate: `crates/frostgate-zcash` (new, in workspace via `crates/*`).

## What was built

| Module | Contents |
|---|---|
| `keys.rs` | Coordinator release key: OsRng keygen, 0600 JSON persistence, network-tag refusal |
| `address.rs` | Testnet P2PKH (`0x1d25` → `tm…`), self-contained base58check, scriptPubKey builder, strict parser |
| `tx.rs` | v4 transparent tx build, ZIP-143/243 sighash, ECDSA P2PKH signing, `build_release` with 10k-zat fee + change |
| `attest.rs` | `ReleaseAttestation` canonical v1 encoding, 30-bps toll consistency check, BIP340 verification of the quorum signature against the federation group key |
| `client.rs` | `ChainClient` trait + `ZcashRpc` (JSON-RPC: height / gettxout / sendrawtransaction / getrawtransaction) + `MockChain` for D5 tests |

## Verification (all measured, this box)

- `cargo test --workspace`: **48 passed, 0 failed** (frostgate-zcash: 29/29; federation 13; others unchanged).
- `cargo clippy -p frostgate-zcash --all-targets -- -D warnings`: clean.
- `cargo fmt -p frostgate-zcash`: applied.
- **ZIP-143 cross-validation**: independent from-scratch Python implementation
  (`.dev/zip143_check.py`) agrees byte-for-byte on the fixture sighash
  (`55e1f03d…78f10`), preimage (294 bytes), and unsigned-tx length (138 bytes).
- **Address cross-validation**: independent Python base58check (`.dev/addr_check.py`)
  agrees on the test vector (`tmYjAZFpvdDXTaJrq2WikAntitBNJJo9VSo` for secret `0x11…11`).
- ECDSA signatures produced by `sign_p2pkh_input` verify against the sighash
  with secp256k1 inside the test suite.

## Caught by the cross-checks (both fixed before claiming)

1. A hand-written address vector in the test was wrong; the Python
   implementation produced the correct one (`tmYjAZF…o9VSo`). Never hand-write
   vectors.
2. The first Python fixture used a 21-byte push under a `0x14` opcode; Rust and
   Python disagreed on the sighash until both fixtures were made well-formed
   (20-byte pkh, `0x14`). The byte-level diff hunt confirmed the Rust preimage
   was correct and the Python fixture was malformed — fixed the fixture, not
   the code.

## Trust model (documented in code, not hidden)

- The ZEC-side vault is a **coordinator-held hot key**. The 3-of-5 FROST quorum
  controls *authorization* (it threshold-signs the `ReleaseAttestation` naming
  the exact destination, amounts, peg-in outpoint, and replay nonce); execution
  is 1-of-1.
- Rationale: Zcash transparent inputs need ECDSA; FROST (RFC 9591) is Schnorr.
  Threshold-ECDSA would be a new unaudited protocol. The attestation design is
  the safer, honest choice.

## Consensus-assumption flags (validated at D7 against live testnet)

1. Empty joinsplit/shielded vectors hash to 32 zero bytes in the sighash preimage.
2. `scriptCode` = prevout scriptPubKey as CScript (length-prefixed).
3. `hashPrevouts`/`hashSequence` hash concatenated serializations, no length prefix.
4. `nVersionGroupId = 0x892F2085`, `nVersion = 0x80000004`.

A wrong assumption fails loudly at broadcast — testnet is the ground truth.

## Still open (NOT done in D4)

- **No TAZ obtained.** Faucet interaction (likely CAPTCHA / live browser) is
  parent-side work. The crate is ready: generate a key, print its `tm…`
  address, fund it, then `get_utxo` → `build_release` → `broadcast`.
- **No live broadcast yet.** First real txid + explorer evidence lands in D7.
- **Zebra fallback verified but not needed.** The background download that
  first reported failure actually succeeded — the failure was a filename
  mismatch in the `sha256sum -c` step (`-o zebrad.tar.gz` vs the `.sha256`
  listing the release filename). Manual verification 2026-09-30: SHA-256
  `505cab2c…c29e7b8b` matches, `zebrad 6.4.2` binary runs, 150 MB in
  `.zebrad/` (tarball retained), 72 GB disk still free. No sync started:
  the D4 light path (local tx build + public RPC/broadcast) does not need a
  full node, and a 2-CPU testnet sync was not attempted.
- Shielded release: explicit stretch goal, not attempted.

## D5 handoff

D5 consumes: `ChainClient` (use `MockChain` in tests, `ZcashRpc` live),
`build_release`, `ReleaseAttestation` + `SignedAttestation::verify` against
the federation group key, and the 30-bps toll rule (`release_zat * 30 / 10_000`,
integer floor — enforced by `ReleaseAttestation::validate`).

## D7 CORRECTION (2026-09-30): BLAKE2b-256, not SHA256d

**The D4 sighash implementation was fundamentally wrong.**

The original implementation used SHA256d (double-SHA256) for the ZIP-243
sighash. This was rejected by testnet with `ScriptInvalid`.

**Root cause:** ZIP-243 specifies BLAKE2b-256, NOT SHA256d, for the v4
transaction sighash. From the ZIP-243 spec:

> "BLAKE2b-256 hash of the serialization of: ..."

The personalization field is `"ZcashSigHash" || CONSENSUS_BRANCH_ID`.

**Correct construction (per ZIP-243):**
1. `hashPrevouts`: BLAKE2b-256("ZcashPrevoutHash", serialized prevouts)
2. `hashSequence`: BLAKE2b-256("ZcashSequencHash", serialized sequences)
3. `hashOutputs`: BLAKE2b-256("ZcashOutputsHash", serialized outputs)
4. `hashJoinSplits`, `hashShieldedSpends`, `hashShieldedOutputs`: 32 zero bytes (when empty)
5. Main digest: BLAKE2b-256("ZcashSigHash" || branch_id_le, preimage)

**Consensus branch ID:** 0x37A5165B for testnet (from lightwalletd
GetLightdInfo, 2026-09-30). This domain-separates the sighash by network
epoch (replay protection).

**Verification:** Transaction `aa8972f2829ef07ab9efa7b636f38f83df859e9db0dfa0eca56cefdf5d785b5c`
was ACCEPTED by testnet.zec.rocks on 2026-09-30, spending the faucet UTXO
(c92cb7e4...:0, 10,000,000 zat) to release 9,000,000 zat.

**Implementation:** Pure-Rust BLAKE2b-256 with 16-byte personalization in
`crates/frostgate-zcash/src/blake2b.rs`, verified against Python
hashlib.blake2b. The `blake2` crate (v0.10) does not expose personalization
via its high-level API, hence the from-scratch implementation.

**Lesson:** The D4 "cross-validation" was circular — both the Rust and
Python implementations shared the same wrong assumption (SHA256d). The live
node is the ground truth. Always verify against the spec AND the live network.

## D7b: FULL QUORUM PATH LIVE (2026-09-30)

D7 proved transaction construction + broadcast. D7b proves the **threshold
authorization path**: the release below was authorized by a live 3-of-5 FROST
quorum signing the exact release attestation — not by a direct
`build_release` call.

**Run:** `cargo run -p frostgate-coordinator --example d7b_coordinator_live`
(fresh 5-of-3 DKG -> `OperatorRelay` -> `CoordinatorService::settle()` ->
`LwdBridge` ChainClient -> testnet.zec.rocks).

**Settlement:**
- Peg-in: SYNTHETIC rehearsal peg-in
  `707487e92f94efdcdd3ebfe547173135844ad2dc7860aae88ce6cc58b7a18792:0`
  (100,000 sats). Labeled synthetic: the BTC peg-in leg was proven on
  regtest; D7b exercises FROST attestation -> ZEC release -> live acceptance.
- FROST: 3-of-5 quorum signed the `ReleaseAttestation`; `settle()` re-verified
  the aggregated signature against the group key before building the tx.
- Release txid: `54a36d22f06f22740ccc061612decba7cd7a58203df9d68179e26a64dd52a8c6`
- Mined: **height 4,419,998** (testnet.zec.rocks).
- Input (verified from the raw tx): `aa8972f2...:1` (the D7 vault change).
- vout 0: 100,000 zat -> `tmLdM92qF75c13rx5zg1bf786Y7hDG7Xd3t`
- vout 1: 880,000 zat -> vault change (`tmTaDmKA1kc43EVxzefNdHBszy2DV4zpjXr`)
- Fee: 10,000 zat. (990,000 = 100,000 + 880,000 + 10,000 exactly.)

**Current vault state:** `54a36d22...:1` = 880,000 zat.

**Tooling honesty note:** the first D7b run's broadcast *succeeded* but the
reporting script crashed with empty stdout — proto3 omits `errorCode` when it
is 0, and `to_i32(None)` raised. The tx sat in the mempool (found via
`--mempool`), got mined, and the *second* run's different tx was correctly
rejected with -25 (double-spend of the same input). Fixed in
`.dev/lwd_broadcast.py` (missing field = 0, `ACCEPTED txid=` labeling).
The -25 rejection is itself evidence the node was tracking our input.

**`.dev/lwd_query.py` fixes (same session):** `GetAddressUtxos` returns a
`GetAddressUtxosReplyList` wrapper — the old code parsed frames as replies
and printed garbage. Now unwraps field 1; `--address/--tx/--tip/--mempool/--info`
flags; `show_tx` uses the correct TxFilter field 3 and parses the
`RawTransaction` frame directly.
