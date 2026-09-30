# Frostgate — Business Plan

*Threshold-federation custody for cross-chain bridges. Pre-seed memo, Sep 30, 2026.*

## 1. The problem

Cross-chain bridges are crypto's #1 loss vector. Ronin ($625M), Poly Network
($611M), Wormhole ($326M), Nomad ($190M) — every one was a custody failure, not
a cryptography failure: a single key, a single server, a single compromised
signer set. Chainalysis estimated over $2B stolen from bridges in 2021–2022
alone. The industry's answer so far has been multisig committees — which still
have trusted dealers, still coordinate off-chain, and still present N keys to
attack instead of zero.

The structural fix: **no single key should ever exist.** Not split, not
sharded — never assembled in the first place.

## 2. The product

Frostgate is threshold-federation custody infrastructure. Five independent
operators run a **dealerless FROST ceremony** (RFC 9591, built on the Zcash
Foundation's implementation) and jointly control a single Bitcoin Taproot
address. Properties that matter to customers:

- **No trusted dealer, ever.** Key shares are generated collaboratively; the
  full key never exists at any point in time.
- **One signature on-chain.** The quorum produces a single 64-byte BIP340
  Schnorr signature — indistinguishable from a normal Taproot spend. No
  multisig script, no signer set leaked on-chain, lower fees.
- **Byzantine-tolerant operations.** 2-of-5 operators can be offline or
  malicious and the bridge keeps settling; cheaters are cryptographically
  identified and excluded mid-session.
- **Measured, not promised.** A live threshold spend is already confirmed on
  Bitcoin regtest; the adversarial demo (offline quorum + malicious share
  attribution) runs from the CLI today.

## 3. Why this team, why now

The founder's unfair advantage is disclosed day-one
([PRE_EVENT_STATE.md](../PRE_EVENT_STATE.md)): a working federated M-of-N
bridge design with a 30-bps toll schedule, replay protection, and supply
invariants, built before the event. The new work is the FROST heart transplant
— dealerless threshold custody replacing the federated ledger's trust
assumptions. Taproot (2021) + production FROST implementations (ZF, 2023–2025)
make this the first cycle where the design is buildable without inventing new
cryptography.

## 4. Revenue

**Lane 1 — Bridge toll (inherited design, labeled as pre-existing).**
The pre-event bridge design carries a 30-bps (0.30%) toll on transfers. Applied
to Frostgate's threshold custody, the toll is the primary revenue line.
*Illustrative, not a projection:* $10M monthly bridge volume → $30k/month toll
revenue at 30 bps. The toll rate and the operator-quorum model predate the
hackathon; the threshold-custody enforcement of it is new.

**Lane 2 — Operator-quorum-as-a-service.**
The 5-of-3 FROST ceremony is chain-agnostic. Other protocols, sidechains, and
L2s rent the quorum: they get threshold custody without running their own
operator set. Pricing: setup fee + basis points on custodied value, or flat
monthly per quorum. This is the higher-margin lane — infrastructure, not
per-transaction tolls.

**Lane 3 — Custody product (mainnet path).**
Testnet → mainnet is a deployment decision, not a research project: the same
ceremony, the same Taproot key-path mechanics, real BTC. Target customers:
OTC desks, mining pools, and treasuries that need multi-operator custody
without trusting any single custodian.

## 5. Go-to-market

1. **Now–Oct 12:** Colosseum World's Fair — working testnet demo, adversarial
   footage, public repo. Win the Zcash track; compete for the $250k accelerator.
2. **Q4 2026:** Security review of the coordinator/relay trust boundaries by an
   external firm; publish the audit scope honestly (what's covered, what isn't).
3. **Q1 2027:** Mainnet pilot with a capped federation (3-of-5, named
   operators, insurance-sized limits); first quorum-as-a-service customer.
4. **2027:** Scale operator set, add threshold-ECDSA leg or Schnorr-capable
   Zcash vault to remove the hot-key trust boundary on the release leg.

## 6. Open source & composability

Core crates are MIT/Apache-2.0 with an all-permissive dependency tree (no
copyleft — see [LICENSES.md](../LICENSES.md)). The moat is not the code; it's
the **operated quorum**: running reliable, attributable threshold operators is
an operations business. Open-sourcing the protocol grows the operator market
and the customer base simultaneously.

## 7. Team

**Travis Jones** ([@AetherionQASI](https://colosseum.com/arena/profiles/AetherionQASI),
Blanco, TX) — founder. Background: independent researcher and systems builder;
prior work includes a federated bridge ledger (M-of-N quorum, 30-bps toll,
supply invariants), a from-scratch ML-DSA-65 implementation (bit-for-bit KAT
verified), and Bitcoin mining/Stratum infrastructure. Building Frostgate
full-time through the World's Fair and beyond.

## 8. The ask

**$250,000 pre-seed** (Colosseum accelerator) for:

| Use | Amount |
|---|---|
| External security review (coordinator, relay, key handling) | $80k |
| Founder runway, 6 months | $90k |
| Testnet→mainnet pilot ops (infrastructure, monitoring) | $50k |
| Legal (entity, custody disclosures) | $30k |

Milestone for the next round: mainnet pilot settling real volume with named
operators and published uptime/attribution data.

## 9. Risks (stated plainly)

- **Coordinator liveness trust.** Documented in the README; external review and
  authenticated operator channels are funded by this round.
- **Hot-key release leg.** The ZEC-side release key is coordinator-held today
  (structural: FROST Schnorr shares can't make Zcash ECDSA signatures).
  Threshold-ECDSA or a Schnorr-capable vault is on the roadmap, not in the demo.
- **Regulatory.** Custody of user funds invites licensing questions
  jurisdiction by jurisdiction; legal budget is in the ask.
- **Below-threshold freeze.** If 3-of-5 operators are ever simultaneously
  unavailable or corrupt, funds freeze at the federation address. This is a
  liveness bound, not a loss — and the operator SLA design is part of the
  quorum-as-a-service product.
