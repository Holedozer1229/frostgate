# Frostgate Mainnet Runbook — how the created methods go live on Bitcoin mainnet

Status: methods proven on mainnet params (`cargo test -p frostgate-bitcoin --test mainnet_params`: 2/2 green, 2026-09-30).
No cryptography changes needed — the delta from the testnet demo is configuration.

## What was proven

- Fresh dealerless 5-of-3 DKG → `federation_address(coord, Network::Bitcoin)` → `bc1p...` P2TR address.
- Full offline threshold spend on mainnet params: `build_spend` → BIP341 sighash → 3-of-5
  FROST `sign_with_tweak` → `aggregate_with_tweak` → witness verified by rust-bitcoin's
  Schnorr verifier. The exact D3 regtest flow, on mainnet bytes.
- The Esplora watcher already takes its endpoint as a parameter — mainnet just points it at
  `https://mempool.space/api`.

## What does NOT go mainnet (honest boundary)

- **Zcash via FROST: impossible.** FROST produces Schnorr signatures; Zcash transparent inputs
  require ECDSA (ZIP-243). Same signature-scheme wall documented in the trust model. A Zcash
  mainnet leg would be plain P2SH multisig — standard engineering, not our method. Don't sell
  it as Frostgate.
- **Bitcoin mainnet is the FROST chain.** Taproot key-path spends are exactly what
  `frost-secp256k1-tr` was built for.

## Play 1 — Dust-scale mainnet proof (your money only, ~$1 in fees right now)

Goal: "FROST threshold custody secured real mainnet BTC" — a claim nobody in the Zcash FROST
debate can make. Marketing asset for the grant, the accelerator, and Play 2.

1. Fresh 5-of-3 DKG on this box (ceremony math is network-independent; store the five
   operator packages + `group.json` — back them up, they're real keys now).
2. Derive the `bc1p...` federation address (`Network::Bitcoin`).
3. Fund it with a small amount of your own BTC (e.g. $20–50 — enough to be real, little
   enough to lose). Watch it land via mempool.space.
4. Run the quorum: 3 operators sign the exact spend via `OperatorRelay` → coordinator
   verifies the aggregate → builds the key-path spend → broadcast via mainnet Esplora.
5. Spend it back to an address you control. Verify confirmation.

**Cost right now:** fees are at 1 sat/vB (checked 2026-09-30, block 969,284). A key-path
spend is ~110 vB → ~110 sats. Fund + spend ≈ a few hundred sats total — under a dollar.
The dust itself comes back to you.

**Risks, stated plainly:**
- Mainnet has no undo. A bug loses real sats — keep it dust.
- The coordinator is unaudited. This play is sized so that an unknown bug costs you lunch,
  not a federation.
- Five operator shares on one box = one box to attack. Fine for your own dust demo;
  NOT the shape you'd sell to a client (see Play 2).

**One build step remains:** a `bitcoin_mainnet_demo` example mirroring `d8_demo_live.rs`
(DKG → derive bc1p → wait for funding → quorum-sign → broadcast). ~150 lines, all calls
already exist.

**Prerequisite:** ~$20–50 of BTC you control, plus the Bitcoin payout address you already use.

## Play 2 — "Bring your own keys" FROST vault service (the money, zero custody risk)

The shape that makes money without ever touching someone else's funds:

- The **client** holds all five shares — distributed across their people/devices. You never
  see a share, never hold funds, never operate custody.
- You deliver: the software (open-source repo), the facilitated DKG ceremony, the runbook,
  and a support retainer. Charge a setup fee + ongoing support.
- Why it beats multisig for the buyer: no trusted dealer ever exists (multisig setups need
  one), one `bc1p` address instead of N keys, 3-of-5 survives two lost/compromised shares,
  cheating signers are automatically identified.

This is consulting shaped as a product. Play 1's mainnet proof + the ZCG grant application
are the marketing. Targets: small funds, DAOs, family offices, Bitcoin treasuries that
currently trust a 2-of-3 multisig coordinator.

## Play 3 — Productize the CLI (after Play 2 validates demand)

Package DKG + relay + coordinator + spend as a polished `frostvault` CLI for Bitcoin
mainnet. Free software, paid setup/support. Do NOT build this before one paying Play-2
customer — demand first, product second.

## Play 4 — Real federation (gated)

Operating a federation that holds other people's money needs the external coordinator
review (the $80K ZCG proposal in `docs/ZCG_GRANT_PROPOSAL_DRAFT.md`). Nothing here changes
that gate. Plays 1–3 are all doable before it.

## Sequence

1. Play 1 as soon as you have ~$30 in BTC and approve the build of `bitcoin_mainnet_demo`.
2. Post the mainnet txids + Play 1 writeup → attach to the ZCG proposal as new evidence.
3. Play 2 outreach (one page: "dealerless 3-of-5 Bitcoin vault, we set it up, you hold the keys").
