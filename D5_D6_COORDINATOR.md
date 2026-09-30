# Frostgate D5–D6: Coordinator Service + Operator Relay + Adversarial Demo

**Date:** 2026-09-30
**Status:** IMPLEMENTED + MEASURED (all tests green, CLI demo captured)

## D5 — Coordinator service wiring

New crate `frostgate-coordinator` (lib + `main.rs` CLI):

```
Esplora watcher ──> peg-in ──> ReleaseAttestation ──> FROST 3-of-5 session
    │                                                │
    │  SignedAttestation::verify (independent)       │ OperatorRelay
    │                                                ▼
    └─> verify quorum signature ──> vault check ──> build_release ──>
        ChainClient::broadcast ──> journal (replay protection)
```

- `CoordinatorService` (`crates/frostgate-coordinator/src/service.rs`) owns one
  settlement pass: scan → attest → sign → verify → build → broadcast → record.
- Cheater handling: on a `CeremonyError::InvalidSignatureShare`, culprits are
  extracted via `frostgate_federation::cheater_culprits`, excluded, and the
  session is retried once with fresh nonces. Unattributed failure → clean
  `BelowThreshold` error (funds stay put; no partial release).
- `Journal` (`journal.rs`): settled-outpoint set + used-nonce set, JSON
  save/load. Replay of a settled peg-in is refused; nonces are never reused
  across sessions (fresh `commit` per attempt; the journal also records them).
- `OperatorRelay` (`relay.rs`): transport abstraction over operators with
  fault injection — `offline(i)` (no response) and `corrupt_share(i)` (signs a
  rogue message with the real commitment set, so the share fails equation
  check and is attributable). Production transport replaces this type behind
  the same trait-like surface; the relay's own doc states the demo trust gap.

## D6 — Adversarial demonstration (CLI-runnable)

`cargo run -p frostgate-coordinator -- demo --fault <mode>` runs the full
loop in-process: fresh DKG → mock Zcash vault funding → synthetic peg-in →
settlement → printed transcript. Measured 2026-09-30:

| mode | quorum signers | outcome |
|---|---|---|
| `none` | [1, 2, 3] | settled, tx broadcast on MockChain |
| `offline:1,2` | [3, 4, 5] | settled — two offline tolerated |
| `malicious:2` | [1, 3, 4] | **operator 2 detected, attributed, excluded; retried and settled** |
| (unit test) 3 offline | — | `BelowThreshold` — clean refusal, no partial release |

Every run also proves replay protection: a second `settle` of the same
peg-in is refused with "already settled (replay refused)".

Live-network evidence (not mocked): the demo's best-effort Esplora scan ran
against `blockstream.info/testnet/api` and returned 0 confirmed peg-ins for
the fresh federation address; the ignored live tests
(`live_esplora_testnet3_smoke`, `live_scan_fresh_federation_address_is_empty`)
both pass, proving the watcher's real HTTP path works.

`watch` subcommand: live coordinator loop — loads a persisted ceremony dir,
polls Esplora, settles via `ZcashRpc`, persists the journal each round.
Needs a funded vault; without TAZ it reports the RPC/funding state and
settles nothing (honest, not silent).

## Verification

- `cargo test --workspace --offline`: **59 passed, 0 failed**
  (2 ignored live-network tests pass when run with `-- --ignored`).
- `cargo clippy --workspace --all-targets --offline -- -D warnings`: clean.
- `cargo fmt --all -- --check`: clean.
- New tests: honest end-to-end, two-offline, malicious-share
  attribution/exclusion, below-threshold refusal, nonce freshness across
  settlements, journal replay refusal + persistence round-trip,
  persisted-ceremony → relay → service, live Esplora smoke.

## Trust model (documented, not hidden)

1. The coordinator is trusted for **liveness** (it drives the session) and
   can **equivocate** unless the channel is authenticated — same as any
   FROST coordinator. Operators must verify the exact attestation message
   and commitment set before signing; the demo relay does not (stated in
   its docs and the CLI output) — production relay must.
2. Nonces are fresh per session; used nonces are journaled and never reused.
3. If a Taproot tweak were applied, all operators must derive and verify
   the same tweak (currently no tweak is applied to the signing key).
4. 3-of-5 tolerates two offline operators; below threshold, funds freeze —
   nothing is auto-released and nothing is lost.

## Honest boundaries

- **Demo economics are metadata, not a market:** the demo converts 1 peg-in
  sat → 1 release zat and records a 30-bps toll in the attestation, but the
  toll is **not withheld** from the release output. A production service
  must subtract the toll before building the release tx. This is stated so
  nobody reads the transcript as "toll collected".
- **ZEC-side signing remains coordinator-held** (D4 boundary): the FROST
  quorum signs the *release authorization attestation*; the transparent ZEC
  release tx is signed by the coordinator's hot release key. "One DKG, two
  chains, two signature schemes" stays an open evaluation, not a claim.
- No TAZ faucet funds, no live Zcash broadcast. D7 (full testnet rehearsal)
  is blocked on human faucet/browser action.
