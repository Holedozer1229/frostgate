# ZCG Grant Proposal (DRAFT — not submitted): Frostgate End-to-End FROST Threshold Custody

> Status: draft for Travis's review. Do NOT post to GitHub/forum without his explicit approval.

---

## Project title

Frostgate: end-to-end FROST threshold custody for cross-chain bridges — external security review of the coordinator

## Applicant

Travis Jones — independent researcher/protocol engineer, Blanco, TX.
- GitHub: https://github.com/Holedozer1229 (Frostgate: https://github.com/Holedozer1229/frostgate)
- Colosseum Crypto World's Fair entry (Zcash Ecosystem track): https://colosseum.com/arena/projects/frostgate
- Demo videos: 30s pitch https://youtu.be/3hty44PFQH0 · technical walkthrough https://youtu.be/BjN5Y7RLgYU

## Problem

Cross-chain bridges are crypto's #1 loss vector — over $2B stolen in 2021–2022 alone (Chainalysis). Ronin ($625M) fell to compromised validator keys; Poly Network ($611M), Wormhole ($326M), and Nomad ($190M) fell to contract-level verification bugs. Every one was a failure of the bridge's trust assumptions. Multisig committees — the industry's current answer — still have trusted dealers, still coordinate off-chain, and still present N keys to attack.

## Proposed solution

Frostgate replaces the bridge multisig with a **dealerless 3-of-5 FROST threshold federation** built on the Zcash Foundation's FROST implementation (RFC 9591). Five operators run a distributed key generation ceremony — no trusted dealer ever exists. A 3-of-5 quorum signs an exact `ReleaseAttestation`; the coordinator independently verifies the aggregate signature before constructing the Zcash release. Bitcoin side: threshold custody of a single Taproot key. Zcash side: threshold authorization with full on-chain attribution.

## Why this is the end-to-end application the committee asked for

The committee declined #351 (FROST SDK, July) and #358 (FROST Custody, August), citing "lacking an end-to-end application." Frostgate is that application — it already exists and already settles:

- **End-to-end, live on testnet.** Fresh 5-operator DKG → operator relay → coordinator settlement → broadcast to the Zcash testnet. Three live releases mined (heights 4,419,998 / 4,420,002 / 4,420,003), txids published in the repo.
- **It answers the hard problems raised on #351.** Secure operator messaging: `OperatorRelay` (built). How participants get the exact bytes to sign: the coordinator constructs the `ReleaseAttestation` and every signer verifies it before signing (built). Share backup and participant disappearance: 3-of-5 tolerates two operators going offline or turning malicious; a cheating operator is detected, named, and excluded automatically (built and tested — 60/60 tests green).
- **It is cross-chain, not ZEC-only.** #358 was shielded-ZEC custody. Frostgate puts ZF cryptography to work securing Bitcoin via Taproot on one leg and settling to Zcash on the other — the Zcash-ecosystem payoff the track rewards.

## What the grant funds

A single, verifiable deliverable: **an external security review of the coordinator** — the one component that is genuinely new code (FROST core itself was NCC-audited; our `frost-secp256k1-tr` dependency was outside that scope, disclosed in the repo). The coordinator is the trust bottleneck: it constructs attestations, verifies quorum signatures, and builds Zcash transactions. It must be reviewed before any mainnet pilot touches real value.

This is also the unlock for everything after: no serious operator joins a mainnet federation, and no accelerator funds a custody pilot, without an independent review on record.

## Deliverables and milestones

1. **M1 — Auditor procurement (weeks 1–3).** Publish RFP, select firm, publish scope (coordinator crate: attestation construction/verification, Zcash transaction building, key handling). Deliverable: signed engagement letter + published scope.
2. **M2 — Review (weeks 4–10).** Auditor reviews the coordinator crate against the published scope. Deliverable: audit report, published in full.
3. **M3 — Remediation and re-test (weeks 11–14).** Fix all findings, add regression tests, re-run the full live testnet settlement suite. Deliverable: remediation report + green test suite + fresh live testnet settlement on the remediated code.

## Budget

| Item | Amount |
|---|---|
| External security review (coordinator crate) | $70,000 |
| Remediation engineering + testnet pilot ops | $10,000 |
| **Total** | **$80,000** |

## Timeline

14 weeks from funding. Monthly public progress reports on the Zcash Community Forum.

## Risks

- **Audit finds architectural flaws.** Mitigation: the coordinator is deliberately small and the trust model is documented (`docs/TRUST_MODEL.md`); findings become the remediation milestone, which is budgeted.
- **Single-developer bandwidth.** Mitigation: the codebase is complete and tested; the grant funds review, not new construction. The hackathon submission (Oct 12) completes before grant work begins.
- **Auditor availability.** Mitigation: RFP goes to multiple firms; M1 has three weeks of slack.

## Links

- Repo: https://github.com/Holedozer1229/frostgate
- Trust model: `docs/TRUST_MODEL.md` in repo (states exactly what is threshold, what is not, and where the remaining trust lives)
- Business plan: `docs/BUSINESS_PLAN.md` in repo
- Live testnet releases: `54a36d22f06f22740ccc061612decba7cd7a58203df9d68179e26a64dd52a8c6` (height 4,419,998), `7f6cc65612b6f7e79ee679bf64013204d3ce92486269cd705330ad78f4db11bd` (4,420,002), `1767009eee0a104682221fdfdebe7a141c1842bcc3d172e0eb85510f94289eda` (4,420,003)
- Prior development disclosure: `PRE_EVENT_STATE.md` in repo (pre-existing federated bridge design disclosed day one; all threshold-cryptography work built during the hackathon)
