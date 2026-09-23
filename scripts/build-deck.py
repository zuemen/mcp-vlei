"""Build the talk deck from the script in `docs/DEMO.md`.

The slides and the spoken script have to stay in step, so the deck is generated rather than drawn:
every slide's speaker notes here are the corresponding block quote in `docs/DEMO.md`. Change the
talk there, run this, and the deck follows.

The output is native PowerPoint — real text boxes, real tables, editable on the machine that will
be plugged into the projector. No images, no screenshots of text, nothing that stops being
editable when someone wants to fix a word the morning of.

    python scripts/build-deck.py            # -> docs/slides/mcp-vlei.pptx
    python scripts/build-deck.py --render   # ... and contact sheets, to look at the result

`--render` is not decoration. Every dimension in this file is arithmetic, and arithmetic produces
footers that collide with page numbers and beige panels with three empty inches under them — both
of which were in the first build and neither of which is visible from the code. It needs
LibreOffice on PATH (or at its usual Windows location) and PyMuPDF.
"""

from __future__ import annotations

import sys
from pathlib import Path

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.text import MSO_ANCHOR, PP_ALIGN
from pptx.util import Emu, Inches, Pt

OUT = Path(__file__).resolve().parents[1] / "docs" / "slides" / "mcp-vlei.pptx"

# The console's palette, so the deck and the thing on screen behind it are the same object.
PAPER = RGBColor(0xF7, 0xF5, 0xEF)
INK = RGBColor(0x1E, 0x1B, 0x16)
MUTED = RGBColor(0x6E, 0x66, 0x58)
BLUE = RGBColor(0x2E, 0x5D, 0x89)
RED = RGBColor(0xC0, 0x39, 0x2B)
RULE = RGBColor(0xDC, 0xD6, 0xC8)

SERIF = "Georgia"
SANS = "Segoe UI"
MONO = "Consolas"

W, H = Inches(13.333), Inches(7.5)
MARGIN = Inches(0.95)
BODY_W = W - 2 * MARGIN

# Everything below the rule and above the footer. Content is centred in it rather than hung from
# the top: a four-line slide otherwise sits in the upper third with the lower half empty, which on
# a projector reads as a slide that is missing something.
BODY_TOP = Inches(2.16)
BODY_BOTTOM = Inches(6.34)
BODY_H = BODY_BOTTOM - BODY_TOP


# ------------------------------------------------------------------------------------------- #
# Primitives
# ------------------------------------------------------------------------------------------- #

def _text(slide, left, top, width, height, *, align=PP_ALIGN.LEFT, anchor=MSO_ANCHOR.TOP):
    box = slide.shapes.add_textbox(left, top, width, height)
    frame = box.text_frame
    frame.word_wrap = True
    frame.vertical_anchor = anchor
    frame.margin_left = frame.margin_right = frame.margin_top = frame.margin_bottom = 0
    frame.paragraphs[0].alignment = align
    return frame


def _run(paragraph, text, *, size, color=INK, font=SANS, bold=False, italic=False, spacing=None):
    run = paragraph.add_run()
    run.text = text
    run.font.size = Pt(size)
    run.font.color.rgb = color
    run.font.name = font
    run.font.bold = bold
    run.font.italic = italic
    if spacing is not None:
        # python-pptx has no character-spacing API; set it on the run's rPr directly.
        run.font._rPr.set("spc", str(int(spacing * 100)))
    return run


def _rule(slide, top, width=None, color=RULE, height=Emu(9525)):
    line = slide.shapes.add_shape(1, MARGIN, top, width or BODY_W, height)  # 1 = rectangle
    line.fill.solid()
    line.fill.fore_color.rgb = color
    line.line.fill.background()
    line.shadow.inherit = False
    return line


def _slide(deck, notes=""):
    slide = deck.slides.add_slide(deck.slide_layouts[6])  # blank
    bg = slide.background.fill
    bg.solid()
    bg.fore_color.rgb = PAPER
    if notes:
        slide.notes_slide.notes_text_frame.text = notes.strip()
    return slide


def _heading(slide, kicker, title):
    """The running header: a small tracked-out kicker over a serif title."""
    frame = _text(slide, MARGIN, Inches(0.62), BODY_W, Inches(0.3))
    _run(frame.paragraphs[0], kicker.upper(), size=11, color=BLUE, bold=True, spacing=1.6)

    frame = _text(slide, MARGIN, Inches(1.0), BODY_W, Inches(0.9))
    _run(frame.paragraphs[0], title, size=32, font=SERIF)
    _rule(slide, Inches(1.86))


def _footer(slide, text, *, color=MUTED):
    # Stop short of the page number: a two-line footer used to run straight through it.
    frame = _text(slide, MARGIN, Inches(6.5), BODY_W - Inches(1.5), Inches(0.5))
    _run(frame.paragraphs[0], text, size=13, color=color, italic=True, font=SERIF)


def _page(slide, n, total):
    frame = _text(slide, W - MARGIN - Inches(1.2), Inches(6.54), Inches(1.2), Inches(0.3),
                  align=PP_ALIGN.RIGHT)
    _run(frame.paragraphs[0], f"{n} / {total}", size=10, color=MUTED, spacing=0.8)


# ------------------------------------------------------------------------------------------- #
# Slide kinds
# ------------------------------------------------------------------------------------------- #

def title_slide(deck, spec):
    slide = _slide(deck, spec["notes"])
    frame = _text(slide, MARGIN, Inches(2.5), BODY_W, Inches(1.2))
    _run(frame.paragraphs[0], spec["title"], size=46, font=SERIF)

    frame = _text(slide, MARGIN, Inches(3.72), BODY_W, Inches(0.5))
    _run(frame.paragraphs[0], spec["subtitle"], size=19, color=BLUE)

    _rule(slide, Inches(4.5), width=Inches(2.2), color=BLUE, height=Inches(0.03))

    frame = _text(slide, MARGIN, Inches(4.92), BODY_W, Inches(1.0))
    for i, line in enumerate(spec["meta"]):
        p = frame.paragraphs[0] if i == 0 else frame.add_paragraph()
        p.space_after = Pt(6)
        _run(p, line, size=14, color=MUTED, font=MONO if line.startswith("github") else SANS)


def bullets_slide(deck, spec):
    slide = _slide(deck, spec["notes"])
    _heading(slide, spec["kicker"], spec["title"])

    frame = _text(slide, MARGIN, BODY_TOP, BODY_W, BODY_H, anchor=MSO_ANCHOR.MIDDLE)
    for i, item in enumerate(spec["bullets"]):
        p = frame.paragraphs[0] if i == 0 else frame.add_paragraph()
        p.space_after = Pt(spec.get("gap", 16))
        if isinstance(item, tuple):
            lead, rest = item
            _run(p, lead, size=spec.get("size", 20), color=BLUE, bold=True)
            _run(p, rest, size=spec.get("size", 20))
        else:
            _run(p, item, size=spec.get("size", 20))
    if spec.get("footer"):
        _footer(slide, spec["footer"])


def table_slide(deck, spec):
    slide = _slide(deck, spec["notes"])
    _heading(slide, spec["kicker"], spec["title"])

    rows, cols = len(spec["rows"]) + 1, len(spec["head"])
    height = Inches(0.46) * rows
    top = BODY_TOP + (BODY_H - height) // 2
    shape = slide.shapes.add_table(rows, cols, MARGIN, top, BODY_W, height)
    table = shape.table
    table.first_row = True
    for c, width in zip(table.columns, spec["widths"]):
        c.width = Emu(int(BODY_W * width))

    for c, label in enumerate(spec["head"]):
        cell = table.cell(0, c)
        cell.fill.solid()
        cell.fill.fore_color.rgb = PAPER
        frame = cell.text_frame
        frame.margin_left = frame.margin_right = Inches(0.1)
        _run(frame.paragraphs[0], label.upper(), size=11, color=BLUE, bold=True, spacing=1.2)

    for r, row in enumerate(spec["rows"], start=1):
        for c, value in enumerate(row):
            cell = table.cell(r, c)
            cell.fill.solid()
            cell.fill.fore_color.rgb = PAPER
            cell.vertical_anchor = MSO_ANCHOR.MIDDLE
            frame = cell.text_frame
            frame.word_wrap = True
            frame.margin_left = frame.margin_right = Inches(0.1)
            mono = value.startswith("`") and value.endswith("`")  # the whole cell, or none of it
            negative = value.startswith("— ")  # "—" alone means "nothing today", not a refusal
            _run(frame.paragraphs[0], value.replace("`", ""),
                 size=spec.get("size", 14),
                 color=RED if negative else INK,
                 font=MONO if mono else SANS)
    if spec.get("footer"):
        _footer(slide, spec["footer"])


def mono_slide(deck, spec):
    slide = _slide(deck, spec["notes"])
    _heading(slide, spec["kicker"], spec["title"])

    size = spec.get("size", 15)
    pad = Inches(0.32)
    # A panel with three inches of empty beige under the last line looks like a rendering failure.
    height = pad * 2 + Pt(size * 1.3 + 3) * len(spec["lines"])
    top = BODY_TOP + (BODY_H - height) // 2

    panel = slide.shapes.add_shape(1, MARGIN, top, BODY_W, height)
    panel.fill.solid()
    panel.fill.fore_color.rgb = RGBColor(0xEF, 0xEB, 0xE1)
    panel.line.fill.background()
    panel.shadow.inherit = False

    frame = _text(slide, MARGIN + pad, top + pad, BODY_W - pad * 2, height - pad * 2)
    for i, line in enumerate(spec["lines"]):
        p = frame.paragraphs[0] if i == 0 else frame.add_paragraph()
        p.space_after = Pt(3)
        # A leading marker colours the key rather than the whole line.
        if line.startswith("*"):
            _run(p, line[1:], size=size, color=BLUE, font=MONO, bold=True)
        else:
            _run(p, line, size=size, color=INK, font=MONO)
    if spec.get("footer"):
        _footer(slide, spec["footer"], color=INK)


def statement_slide(deck, spec):
    """One sentence, alone. Used for the honesty statement, which is read aloud verbatim."""
    slide = _slide(deck, spec["notes"])
    frame = _text(slide, MARGIN, Inches(2.6), BODY_W, Inches(0.4))
    _run(frame.paragraphs[0], spec["kicker"].upper(), size=11, color=BLUE, bold=True, spacing=1.6)

    frame = _text(slide, MARGIN, Inches(3.2), BODY_W, Inches(2.2))
    for i, line in enumerate(spec["lines"]):
        p = frame.paragraphs[0] if i == 0 else frame.add_paragraph()
        p.space_after = Pt(14)
        _run(p, line, size=spec.get("size", 30), font=SERIF,
             color=RED if line.startswith("The root") else INK)
    if spec.get("footer"):
        _footer(slide, spec["footer"])


KINDS = {"title": title_slide, "bullets": bullets_slide, "table": table_slide,
         "mono": mono_slide, "statement": statement_slide}


# ------------------------------------------------------------------------------------------- #
# The deck. Notes are the block quotes in docs/DEMO.md, verbatim.
# ------------------------------------------------------------------------------------------- #

SLIDES = [
    {"kind": "title",
     "title": "Organizational Identity for MCP Agents",
     "subtitle": "vLEI × Model Context Protocol",
     "meta": ["An additive extension: org.gleif.vlei/identity",
              "github.com/zuemen/mcp-vlei · Apache 2.0"],
     "notes": "Fifteen minutes on one question: when an agent calls a tool across an "
              "organizational boundary, who is accountable, and how does the other side check?"},

    {"kind": "table", "kicker": "The stack today", "title": "What MCP verifies",
     "head": ["Layer", "What it proves", "What it does not"],
     "widths": [0.22, 0.39, 0.39],
     "rows": [
         ["TLS", "Control of a domain name", "— Which legal entity"],
         ["OAuth `iss`", "Which authorization server", "— Which legal entity"],
         ["OAuth `client_id`", "Control of a metadata URL", "— Which legal entity"],
         ["OAuth `sub`", "Which human user", "— Which organization they bind"],
         ["`clientInfo`", "Nothing. It is self-asserted", "— MUST NOT be used for security"],
     ],
     "footer": "Domain control, domain control, domain control, human user.",
     "notes": "MCP inherits a well-specified authentication stack. Every layer answers a real "
              "question. TLS proves control of a domain name. The OAuth issuer identifies the "
              "authorization server. The client ID proves control of the URL serving the client "
              "metadata. The subject identifies the human user.\n\n"
              "Read the right-hand column. Domain control, domain control, domain control, human "
              "user. No layer expresses a legal entity, and the specification is explicit that "
              "clientInfo must not be used for security decisions — correctly, because nothing "
              "backs it."},

    {"kind": "table", "kicker": "Measured, not asserted", "title": "The measurement",
     "head": ["Run", "clientInfo.name", "Approved"],
     "widths": [0.30, 0.42, 0.28],
     "rows": [["Honest", "`my-small-tool`", "1 hour"],
              ["Spoofed", "`Claude Desktop`", "50 hours"],
              ["Omitted", "`(absent)`", "1 hour"]],
     "size": 17,
     "footer": "One binary, one variable. The server's policy deliberately violates the "
               "specification — that is the experiment, not a recommendation.",
     "notes": "We measured it rather than asserting it. One binary, one server, fifty hours "
              "requested three times, changing only what the client said its name was.\n\n"
              "The server's policy deliberately violates the specification — that is the "
              "experiment, not a recommendation. What it establishes is that no layer of the "
              "stack can tell the three runs apart.\n\n"
              "The code is in the repository. Nothing was run against anyone else's service.\n\n"
              "[Play demo-scene0.mp4, 45 seconds.]"},

    {"kind": "mono", "kicker": "The protocol itself",
     "title": "The agent is absent from the protocol",
     "lines": ["schema.ts · revision 2026-07-28 · 3,197 lines", "",
               "*  agent        0 occurrences",
               "*  principal    0 occurrences",
               "*  delegation   0 occurrences",
               "*  mandate      0 occurrences", "",
               "   host         modelled",
               "   client       modelled",
               "   server       modelled"],
     "footer": "It cannot be named, delegated to, constrained, or revoked — there is nothing "
               "there to name.",
     "notes": "The protocol models a host, a client, and a server. The thing that decides to "
              "invoke a tool has no representation — so it cannot be named, delegated to, "
              "constrained, or revoked at the protocol layer, because there is nothing there to "
              "name."},

    {"kind": "bullets", "kicker": "Read it fairly",
     "title": "This is a boundary, not a defect",
     "bullets": [
         ('"MCP\'s trust model assumes a human in the loop"',
          "  — the Tools chapter's warning box"),
         ("NSA, May 2026", " — MCP does not define how a session maps to a verifiable identity"),
         ("Security IG proposals", " root in domain, DNS, or registry"),
         ("Those answer ", "which deployment is this. None answers which legal entity is this."),
     ],
     "size": 19,
     "notes": "Under that premise, self-asserted metadata is harmless: a person is accountable at "
              "the point of action. When the agent executes autonomously, the premise no longer "
              "holds, and the layer carrying accountability is simply not present.\n\n"
              "Everyone has noticed. The published server-identity proposals all root trust in a "
              "domain, DNS, or a registry. Those answer 'which deployment is this'. None answers "
              "'which legal entity is this', and none is revocable by an authority the "
              "counterparty's regulator also recognizes."},

    {"kind": "bullets", "kicker": "Why this year", "title": "Why now",
     "bullets": ["Autonomous execution — no human at the point of action",
                 "Actions with legal effect — a filing, a payment, a submission",
                 "Across organizations — a counterparty that has never met the agent"],
     "gap": 22, "size": 22,
     "footer": "Any one alone is survivable. Together they are not.",
     "notes": "Any one alone is survivable. Together they are not: an agent acting without "
              "review, on something that binds its organization, against a counterparty that has "
              "never met it."},

    {"kind": "bullets", "kicker": "Not a new identity system",
     "title": "GLEIF already solved the identity half",
     "bullets": [("Legal Entity (LE)", " — binds an identifier to an LEI"),
                 ("Engagement Context Role (ECR)", " — binds a person's identifier to a role "
                                                   "within that entity"),
                 ("Both chained ACDCs", " · both revocable · both verifiable offline"),
                 ("Anchored in KERI", " — key event logs, not a certificate authority")],
     "notes": "This is not a proposal for a new identity system. The Legal Entity credential "
              "binds an identifier to an LEI. The Engagement Context Role credential binds a "
              "person's identifier to a role within that entity. Both are chained ACDCs, both "
              "revocable, both verifiable offline."},

    {"kind": "table", "kicker": "A deliberate choice", "title": "Why ECR and not OOR",
     "head": ["", "OOR", "ECR"],
     "widths": [0.24, 0.38, 0.38],
     "rows": [["Names", "A public office", "An engagement context"],
              ["Vocabulary", "Controlled", "Defined by the entity"],
              ["Validated by", "GLEIF", "The entity itself"]],
     "size": 16,
     "footer": "\"May file regulatory returns up to this amount\" is an engagement context, not a "
               "public office.",
     "notes": "An agent's mandate — 'may file regulatory returns up to this amount' — is an "
              "engagement context, not a public office. ECR is the correct credential type, and "
              "the vocabulary belongs to the entity that defines the engagement."},

    {"kind": "mono", "kicker": "The extension", "title": "What we added: the schema",
     "lines": ['Implementation.extensions["org.gleif.vlei/identity"]',
               "    presents / requires / acceptedRoots / ttlMs", "",
               "params._meta",
               "*    org.gleif.vlei/credential",
               "*    org.gleif.vlei/credentialSaid",
               "*    org.gleif.vlei/delegatedAid",
               "*    org.gleif.vlei/signature", "",
               "Tool._meta",
               "*    org.gleif.vlei/requires  { credential, role, scope }"],
     "size": 14,
     "footer": "Four keys in _meta. Nothing in core changes.",
     "notes": "Everything travels in fields MCP already reserves for extensions, so a party that "
              "does not understand them behaves exactly as core MCP specifies.\n\n"
              "The last line is the one I would point at. The permission is declared in the "
              "schema the client already reads, so an agent can determine before calling whether "
              "it is entitled — and decline in terms a user understands, instead of attempting "
              "the call and interpreting a rejection.\n\n"
              "One structural note for the implementers here: Implementation has no _meta. That "
              "is why a server's credential travels at a well-known URL rather than on the party "
              "object."},

    {"kind": "mono", "kicker": "The extension", "title": "What we added: verification",
     "lines": ["   1  credential_present      local",
               "   2  freshness               local",
               "   3  digest                  local",
               "   4  signature               local",
               "   5  delegation              local",
               "   6  chain                   local",
               "*  7  revocation              the one remote check — deliberately last",
               "   8  authority               local"],
     "size": 15,
     "footer": "Eight checks. Nine failure layers. The verifier decides; nothing else does.",
     "notes": "Eight checks, and the order is the design. Seven are decided from the request "
              "itself; one leaves the machine. A verification service that is slow or down then "
              "costs you one check instead of all of them.\n\n"
              "Nine failure layers, and the correct response differs for each. A stale signature "
              "is retried once. 'revoked' means stop and tell the user a new credential is "
              "needed. 'unknown_root' means two organizations disagree about whom they trust and "
              "only they can fix it. An agent that receives 'access denied' can do none of that."},

    {"kind": "bullets", "kicker": "From building it",
     "title": "Three things the paper design did not predict",
     "bullets": [("1  ", "Presentation is the holder's step — so a counterparty's credential "
                         "must be verified locally"),
                 ("2  ", "Ask about the issuee, not the signer"),
                 ("3  ", "Protocol version negotiation decides whether extensions exist at all")],
     "gap": 24, "size": 21,
     "footer": "None of the three is derivable from the design. They are what a second "
               "implementer would otherwise pay for again.",
     "notes": "These three cost us days, and none of them is derivable from the design. I am "
              "putting them on a slide because they are what a second implementer would "
              "otherwise pay for again.\n\n"
              "The verifier's presentation endpoint requires headers signed by the credential "
              "holder — so a relying party cannot hand someone else's credential to a service and "
              "ask about it. It verifies the chain itself. That single fact determines the shape "
              "of every deployment.\n\n"
              "The agent signs with its delegated identifier; the credential was issued to a "
              "person; the record is keyed by the person. Read the issuee out of the credential, "
              "and never take the caller's word for whose record to consult.\n\n"
              "And extensions only exist at the 2026-07-28 revision. A server that appears to "
              "advertise nothing is usually a client that never got past the legacy handshake. We "
              "spent an afternoon on that."},

    {"kind": "bullets", "kicker": "Traceability", "title": "Every requirement, traced",
     "bullets": ["docs/CONFORMANCE.md — one row per normative statement, with its implementation "
                 "and its test",
                 "Three rows had nothing behind them. Writing the table is what found them.",
                 "A section listing what is deliberately not claimed"],
     "gap": 22, "size": 21,
     "footer": "A conformance document that lists only successes is not evidence of anything.",
     "notes": "A specification whose requirements cannot be traced to running code is a document. "
              "Every MUST and SHOULD in ours has a row: the function that implements it, the test "
              "that holds it.\n\n"
              "Writing that table found three requirements with nothing behind them. It also has "
              "a section on what we deliberately do not claim. A conformance document that lists "
              "only successes is not evidence of anything."},

    {"kind": "statement", "kicker": "Demo",
     "lines": ["Real KERI, real ACDC, real revocation.",
               "The root of trust is self-configured; in production it would be GLEIF's."],
     "footer": "We used GLEIF's verifier, found a defect in its revocation path, and wrote it up.",
     "notes": "Everything you are about to see is real KERI and real ACDCs, issued through "
              "GLEIF's own schemas, with a revocation read from the issuer's transaction event "
              "log. The one thing I control is the root of trust, because I do not have a "
              "production vLEI. In production the chain terminates at GLEIF's root.\n\n"
              "One more thing while this slide is up. We did use GLEIF's verifier, and we found a "
              "defect in its revocation path that takes the service down. It is written up and "
              "ready to file.\n\n"
              "[Play demo-full.mp4, 3:35.]"},

    {"kind": "bullets", "kicker": "Both already exist in institutions",
     "title": "Two ways to check an identity",
     "bullets": [("(a) Passive, from a public location", " — publish once, verify anywhere, no "
                                                          "per-check cost"),
                 ("(b) Attested confirmation (來函確認)", " — one institution confirms to "
                                                          "another, signed"),
                 ("The limit, stated: ", "relying on an attestation means relying on that "
                                         "institution's judgment — exactly as relying on a letter "
                                         "does today.")],
     "gap": 22, "size": 19,
     "footer": "The attesting institution must itself have been verified first.",
     "notes": "Institutions already have both. The first is a public key directory: publish once, "
              "and anyone verifies independently, including before making contact.\n\n"
              "The second is the letter of confirmation. District office A writes to office B to "
              "confirm a record; B replies; A relies on B's reply. As an agent call, B returns a "
              "signed attestation and A verifies B's signature.\n\n"
              "The correspondence procedure is not replaced by something unfamiliar. It becomes a "
              "verifiable call that completes in a second and leaves a signature rather than a "
              "letterhead.\n\n"
              "The honest limit: relying on an attestation means relying on that institution's "
              "judgment, exactly as relying on a letter does today. What the system enforces is "
              "that the attesting institution must itself have been verified first, and that "
              "every decision records whose attestation it rested on. It cannot make that "
              "institution careful."},

    {"kind": "bullets", "kicker": "Adoption", "title": "Six stages, one of which touches IT",
     "bullets": [("0  ", "Credential and role vocabulary — the business unit, not IT"),
                 ("1  ", "Publish at a well-known location"),
                 ("2  ", "Declare the requirement per tool"),
                 ("3  ", "Verify at the gateway ← the only IT change"),
                 ("4  ", "Attestations between institutions"),
                 ("5  ", "Audit records")],
     "gap": 12, "size": 19,
     "footer": "The filing service contains no verification code. It reads two headers.",
     "notes": "Each stage is independently useful. An institution that stops after stage two has "
              "gained something real.\n\n"
              "Stage zero is the substantive one and it is not technical: the business unit "
              "defines its role vocabulary. Those names appear in every authorization decision "
              "and every audit record afterwards.\n\n"
              "Only stage three touches IT, and it is the one that decides whether this is a "
              "configuration change or a project. Verification goes at the gateway; the systems "
              "behind it read headers, as they already do."},

    {"kind": "table", "kicker": "Adoption", "title": "What an institution gets",
     "head": ["", "Today", "After stage 3"],
     "widths": [0.30, 0.35, 0.35],
     "rows": [["Who filed", "A session, a token", "A named entity and role"],
              ["Authority changed", "A ticket", "Revoke the credential"],
              ["New system built", "—", "None"],
              ["Existing sign-on", "Answers which user", "Unchanged — still required"],
              ["Audit record", "An IP and a timestamp", "LEI, role, signature"]],
     "size": 14,
     "footer": "vLEI answers which organization. Your existing sign-on still answers which user. "
               "A high-value action should require both.",
     "notes": "One row deserves emphasis, because it is the one most likely to be misread. This "
              "does not replace existing user authentication. vLEI answers which organization; "
              "your existing sign-on still answers which user. A high-value action should require "
              "both. An institution that drops one because it gained the other has weakened "
              "itself."},

    {"kind": "bullets", "kicker": "Stated, not waited for", "title": "Limits",
     "bullets": ["Verifiable is not the same as trustworthy",
                 "LEIs are not issued to private individuals",
                 "There is a cost, and QVI coverage is still expanding",
                 "Our demo root is self-configured",
                 "Agent delegation conventions are not yet settled"],
     "gap": 14, "size": 20,
     "footer": "A valid credential proves an organization asserted a role. It does not prove the "
               "request is legitimate.",
     "notes": "I would rather state these than be asked. A valid credential proves an "
              "organization asserted a role. It does not prove the request is legitimate — "
              "authorization policy stays yours, and this makes it enforceable rather than "
              "writing it for you.\n\n"
              "The last one is a genuine open question, which brings me to what I am asking for."},

    {"kind": "bullets", "kicker": "The ask", "title": "Three requests",
     "bullets": [("Government  ", "one small pilot: one filing or lookup procedure, stages 0 to "
                                  "3, no change to the department's systems"),
                 ("GLEIF  ", "an ECR role vocabulary for agent contexts · confirmation of the "
                             "delegation model against the EGF · test credentials"),
                 ("AAIF  ", "take this to the Security Interest Group and the ext-auth "
                            "discussion")],
     "gap": 26, "size": 20,
     "footer": "We chose a reading of the existing mechanisms, and would rather be corrected now "
               "than at deployment.",
     "notes": "To the institutions here, first, because you are the ones who would carry the "
              "risk: one procedure, one counterpart, stages zero through three. Not a programme. "
              "One correspondence procedure that currently takes days, and no change to the "
              "system behind your gateway.\n\n"
              "To GLEIF: an ECR role vocabulary for agent engagement contexts. A confirmation of, "
              "or correction to, the delegated-AID model, including whether it is compatible with "
              "the Ecosystem Governance Framework — we chose a reading of the existing mechanisms "
              "and would rather be corrected now than at deployment. And test credentials against "
              "a real root, so the honesty statement can be retired.\n\n"
              "To AAIF: this belongs in the Security Interest Group and in the ext-auth "
              "discussion. I would like it discussed, and I would like to be told where it is "
              "wrong."},

    {"kind": "mono", "kicker": "One repository, Apache 2.0", "title": "Artifacts",
     "lines": ["spec/       specification v0.2, type definitions, wire examples, error shapes",
               "packages/   mcp-vlei — extension, client, chain verification, 77 tests",
               "skills/     implementing-vlei (build time) · vlei-identity (runtime)",
               "examples/   impersonation · console · association server · agent · regulator",
               "deploy/     gateway configuration — zero-code-change adoption",
               "docs/       problem · government adoption · conformance · the upstream defect",
               "",
               "github.com/zuemen/mcp-vlei"],
     "size": 14,
     "footer": "Real KERI, real ACDC, real revocation. The root of trust is self-configured; in "
               "production it would be GLEIF's.",
     "notes": "Everything is in one repository, Apache licensed. The specification, the package, "
              "both skills, the reference implementations, the gateway configuration, the "
              "conformance table — and the defect report, because we used your verifier and we "
              "owe you that.\n\nThank you. I have time for questions."},
]


def build(path: Path = OUT) -> Path:
    deck = Presentation()
    deck.slide_width, deck.slide_height = W, H

    total = len(SLIDES)
    for n, spec in enumerate(SLIDES, start=1):
        KINDS[spec["kind"]](deck, spec)
        if n > 1:
            _page(deck.slides[-1], n, total)

    path.parent.mkdir(parents=True, exist_ok=True)
    deck.save(path)
    return path


def render(deck_path: Path, out_dir: Path) -> list[Path]:
    """Rasterize into 2x2 contact sheets, so the whole deck can be looked at rather than sampled."""
    import shutil
    import subprocess

    import fitz

    soffice = shutil.which("soffice") or shutil.which("libreoffice") or         r"C:\Program Files\LibreOffice\program\soffice.exe"
    if not Path(soffice).exists():
        raise SystemExit(f"no LibreOffice at {soffice}; install it or render by hand")

    out_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run([soffice, "--headless", "--convert-to", "pdf", "--outdir", str(out_dir),
                    str(deck_path)], check=True, capture_output=True)

    pdf = fitz.open(out_dir / f"{deck_path.stem}.pdf")
    width, height = 1600, 900
    sheets = []
    for first in range(0, len(pdf), 4):
        sheet = fitz.open().new_page(width=width, height=height)
        for i, page in enumerate(range(first, min(first + 4, len(pdf)))):
            box = fitz.Rect((i % 2) * width / 2, (i // 2) * height / 2,
                            (i % 2 + 1) * width / 2, (i // 2 + 1) * height / 2)
            sheet.show_pdf_page(box, pdf, page)
        path = out_dir / f"sheet{first // 4}.png"
        sheet.get_pixmap(dpi=150).save(path)
        sheets.append(path)
    return sheets


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if a != "--render"]
    out = build(Path(args[0]) if args else OUT)
    print(f"{len(SLIDES)} slides -> {out}")

    if "--render" in sys.argv:
        for sheet in render(out, out.parent / "render"):
            print(f"  {sheet}")
