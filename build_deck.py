#!/usr/bin/env python3
"""Generate the Frostgate pitch deck (PPTX) for Colosseum upload."""
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN

BG = RGBColor(0x0B, 0x0E, 0x14)
ACCENT = RGBColor(0x4C, 0xC3, 0xFF)
WHITE = RGBColor(0xFF, 0xFF, 0xFF)
GRAY = RGBColor(0xA8, 0xB0, 0xBC)
GOLD = RGBColor(0xF5, 0xB7, 0x01)

SLIDES = [
    ("Frostgate",
     "Threshold custody for cross-chain bridges",
     ["Five operators. One key that never exists.",
      "",
      "Colosseum Crypto World's Fair — Zcash Ecosystem track"]),
    ("The problem",
     "Bridges are crypto's #1 loss vector",
     ["Ronin — $625M", "Poly Network — $611M", "Wormhole — $326M", "Nomad — $190M",
      "",
      "Every one was the same failure: custody.",
      "One key, one server, one small multisig — one compromise and the money is gone."]),
    ("The insight",
     "What if there is no key to steal?",
     ["Frostgate replaces the bridge multisig with a 3-of-5 FROST threshold signature.",
      "",
      "• Five independent operators jointly control one Bitcoin Taproot address",
      "• No operator ever holds the full key — only a share, useless alone",
      "• No trusted dealer ever existed to compromise",
      "• Two operators offline → the bridge keeps settling",
      "• One operator turns malicious → the protocol names, excludes, and carries on"]),
    ("Live, not a whitepaper",
     "Running on testnet today",
     ["• Fresh dealerless DKG spins up five operators",
      "• They derive one Taproot address",
      "• A peg-in is detected",
      "• Three operators sign a quorum attestation authorizing the exact release —",
      "  destination, amount, source outpoint",
      "• The coordinator independently verifies the aggregate signature",
      "• A real Zcash testnet transaction is broadcast and mined",
      "",
      "Every txid in the repo is on a public explorer. 60 tests pass."]),
    ("The architecture",
     "One DKG, honest trust boundary",
     ["Bitcoin side: THRESHOLD CUSTODY — one FROST-controlled Taproot key",
      "Zcash side: THRESHOLD AUTHORIZATION — quorum attestation, verified by the coordinator",
      "Zcash execution: coordinator-held key (stated honestly, in writing)",
      "",
      "FROST (RFC 9591) produces Schnorr signatures — exactly what Taproot needs."]),
    ("Why Frostgate wins",
     "Two things no other bridge pitch has",
     ["1. The cryptography is not ours.",
      "   FROST was built and audited at the Zcash Foundation.",
      "   Frostgate puts the ZF implementation to work as bridge custody —",
      "   Zcash cryptography securing Bitcoin via Taproot.",
      "",
      "2. The trust model is stated honestly, in writing.",
      "   What is threshold, what is not, and exactly where the remaining trust lives.",
      "   No \"trustless\" theater."]),
    ("The business",
     "Infrastructure, not a demo",
     ["• 30-basis-point bridge toll (working design, disclosed pre-event)",
      "• Quorum-as-a-service — threshold custody for any protocol",
      "• Mainnet custody pilot with institutional partners",
      "",
      "Every wrapped asset, every cross-chain protocol, every institutional",
      "custodian is a customer."]),
    ("The ask",
     "$250k pre-seed via the Colosseum accelerator",
     ["Use of funds:",
      "• Security audit of the coordinator + relay (external, before mainnet)",
      "• Zcash shielded-release path (FROST over the Orchard spend auth)",
      "• Operator onboarding — first production federation",
      "",
      "The hackathon build is the working prototype;",
      "the accelerator is how it becomes the company."]),
    ("The team",
     "Travis Jones — solo founder, Blanco, Texas",
     ["Independent researcher and systems builder.",
      "• From-scratch ML-DSA-65, bit-for-bit KAT verified",
      "• Bitcoin mining and Stratum infrastructure",
      "• Federated bridge ledgers",
      "",
      "Built Frostgate end-to-end: cryptography, nodes, settlement, video, docs."]),
    ("Frostgate",
     "The key that never exists.",
     ["github.com/Holedozer1229/frostgate",
      "",
      "Live testnet settlements. Honest trust model. No trusted dealer.",
      "",
      "Win the fair. Then secure the bridges."]),
]

prs = Presentation()
prs.slide_width = Inches(13.333)
prs.slide_height = Inches(7.5)
blank = prs.slide_layouts[6]

for title, subtitle, bullets in SLIDES:
    slide = prs.slides.add_slide(blank)
    bg = slide.background
    fill = bg.fill
    fill.solid()
    fill.fore_color.rgb = BG

    # Accent bar
    bar = slide.shapes.add_shape(1, Inches(0.7), Inches(0.55), Inches(1.2), Pt(6))
    bar.fill.solid(); bar.fill.fore_color.rgb = ACCENT
    bar.line.fill.background()

    tx = slide.shapes.add_textbox(Inches(0.7), Inches(0.8), Inches(11.9), Inches(1.2)).text_frame
    tx.word_wrap = True
    p = tx.paragraphs[0]
    p.text = title
    p.font.size = Pt(44); p.font.bold = True; p.font.color.rgb = WHITE

    stx = slide.shapes.add_textbox(Inches(0.7), Inches(1.75), Inches(11.9), Inches(0.8)).text_frame
    stx.word_wrap = True
    p = stx.paragraphs[0]
    p.text = subtitle
    p.font.size = Pt(26); p.font.color.rgb = ACCENT

    btx = slide.shapes.add_textbox(Inches(0.7), Inches(2.8), Inches(11.9), Inches(4.2)).text_frame
    btx.word_wrap = True
    for i, b in enumerate(bullets):
        p = btx.paragraphs[0] if i == 0 else btx.add_paragraph()
        p.text = b
        p.font.size = Pt(22); p.font.color.rgb = WHITE if not b.startswith("•") and b else GRAY
        p.space_after = Pt(8)

out = "/home/hatch/workspace/frostgate/Frostgate-Pitch-Deck.pptx"
prs.save(out)
print("saved", out)
