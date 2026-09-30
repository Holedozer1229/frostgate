# Frostgate — Pitch

*3-minute pitch script + the company case. Written for the Colosseum Crypto
World's Fair, Zcash track.*

---

## The pitch (3 minutes)

**[0:00–0:25 — The problem]**

Bridges are crypto's number-one loss vector. Ronin: $625 million. Wormhole:
$320 million. Nomad, Multichain — billions gone. And every single one was the
same failure: *custody*. One key, one server, one small multisig group — one
compromise and the money is gone. The bridge didn't fail at cryptography. It
failed at *who holds the key*.

**[0:25–0:50 — The insight]**

What if there is no key to steal? Frostgate replaces the bridge multisig with
a **3-of-5 FROST threshold signature** — five independent operators who jointly
control a single Bitcoin Taproot address, where no operator ever holds the
full key — only a share, useless alone — and no trusted dealer ever existed
to compromise. Two
operators can go offline and the bridge keeps settling. One operator turns
malicious and the protocol names them, excludes them, and carries on.

**[0:50–1:50 — The product, live]**

This isn't a whitepaper — it's running. On screen: a fresh dealerless ceremony
spins up five operators. They derive one Taproot address. A peg-in is
detected. Three operators sign a quorum attestation authorizing the exact
release — destination, amount, source outpoint — and the coordinator verifies
that aggregate signature independently before building anything. Then a real
Zcash testnet transaction is broadcast and mined. You can look up every txid
in this repo on a public explorer. Sixty tests pass. The adversarial demo —
two operators down, one actively cheating — is in the repo and runs in one
command.

**[1:50–2:20 — Why this wins]**

Two things make Frostgate different from every "secure bridge" pitch. First,
the cryptography is not ours: FROST was built and audited at the **Zcash
Foundation**, and Frostgate puts the ZF implementation to work as bridge
custody — Zcash cryptography securing Bitcoin via Taproot. Second, the trust model is stated
honestly, in the README, in writing: what is threshold, what is not, and
exactly where the remaining trust lives. No "trustless" theater.

**[2:20–2:45 — The business]**

Frostgate is being built as a company, not a demo. Threshold-federation
custody as infrastructure: operator-quorum-as-a-service for any protocol that
needs cross-chain custody, plus a 30-basis-point bridge toll. Every wrapped
asset, every cross-chain protocol, every institutional custodian is a
customer. The hackathon build is the working prototype; the accelerator is
how it becomes the company.

**[2:45–3:00 — The team]**

I'm Travis Jones, solo founder, Blanco, Texas. I build blockchain
infrastructure from scratch — I shipped my own chain, my own federated bridge
ledger, a from-scratch ML-DSA-65 implementation. The pre-existing work is
disclosed day-one in the repo, because the unfair advantage is the point: the
hackathon budget bought the FROST heart transplant, not a bridge from zero.
Frostgate removes the key. There is nothing left to steal.

---

## Why the Zcash track

FROST is Zcash Foundation cryptography — designed, implemented, and audited
there (RFC 9591). Frostgate is a live deployment of the ZF implementation as
cross-chain bridge custody, and it pays the technology back: every quorum
attestation in Frostgate is a FROST signature, and the demo settles onto the
Zcash testnet.
This is ZF research securing real value flows, which is the best possible
advertisement for the Zcash ecosystem's cryptographic leadership.

## Traction (measured, not claimed)

| Milestone | Evidence |
|---|---|
| 5-of-3 dealerless DKG | `frostgate-operator dkg`, key packages mode 0600 |
| Single Taproot custody key | BIP341 tweak verified byte-for-byte vs rust-bitcoin |
| Bitcoin regtest threshold spend | txid `c3dbc434…f977676`, mined in regtest block 103 |
| Zcash testnet release (direct) | txid `aa8972f2…785b5c`, mined at height 4,419,993 |
| Full quorum path, live | txid `54a36d22…52a8c6`, mined at height 4,419,998 |
| Reproducible quorum path | txid `7f6cc656…f4db11bd`, mined at height 4,420,002 |
| Adversarial resilience | `demo --fault offline:1,2` and `--fault malicious:2` |
| Test suite | 60 pass, 0 fail, clippy + fmt clean |

## The ask

$100K Zcash track prize to fund the security audit of the coordinator and the
mainnet hardening; Colosseum accelerator ($250K) to build Frostgate into the
threshold-custody infrastructure company — operator quorum as a service, with
the bridge toll as the revenue engine.
