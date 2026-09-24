"""Build docs/proposals/DEMO-14min.md from docs/DEMO.md: same document, the cuts applied.

A proposal, not the talk: docs/DEMO.md is left as it is. Then run the second pass (slide 14
corrected, questions added, the timing table):

    python docs/proposals/make_proposal.py && python docs/proposals/proposal_taiwan.py
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
s = (ROOT / "docs" / "DEMO.md").read_text(encoding="utf-8")


def sub(old: str, new: str) -> None:
    global s
    assert old in s, old[:80]
    s = s.replace(old, new, 1)


def section(heading_prefix: str, end_marker: str = "\n---\n") -> tuple[int, int]:
    start = s.index(heading_prefix)
    end = s.index(end_marker, start)
    return start, end


def replace_quote(heading_prefix: str, new_quote: str) -> None:
    """Replace every block-quote paragraph under a heading with new_quote (a list of paragraphs)."""
    global s
    start, end = section(heading_prefix)
    body = s[start:end]
    lines = body.split("\n")
    first = next(i for i, l in enumerate(lines) if l.startswith(">"))
    last = max(i for i, l in enumerate(lines) if l.startswith(">"))
    quoted = []
    paragraphs = new_quote
    for i, paragraph in enumerate(paragraphs):
        text = paragraph
        if i == 0:
            text = '"' + text
        if i == len(paragraphs) - 1:
            text = text + '"'
        words, line = text.split(), ">"
        for word in words:
            if len(line) + 1 + len(word) > 100:
                quoted.append(line)
                line = "> " + word
            else:
                line = line + " " + word
        quoted.append(line)
        if i < len(paragraphs) - 1:
            quoted.append(">")
    lines[first:last + 1] = quoted
    s = s[:start] + "\n".join(lines) + s[end:]


# ------------------------------------------------------------------------------ recording script
sub("# Recording script — 4:05, six scenes", "# Recording script — 2:50, five scenes")
sub("## Scene 0 — Impersonation (45s)", "## Scene 0 — Impersonation (45s)")
sub("## Scene 1 — A verified call (45s)", "## Scene 1 — A verified call (30s)")
sub("## Scene 2 — A client without the extension (40s)", "## Scene 2 — A client without the extension (20s)")
sub("## Scene 4 — Through the gateway (40s)", "## Scene 4 — Through the gateway (30s)")

replace_quote("## Scene 0 — Impersonation", [
    "A vendor's server gives partner-tier quota to callers it recognises. We asked it for fifty GPU "
    "hours three times from the same binary, changing only the name the client gave.",
    "Honest: one hour. Claiming to be a well-known client: fifty. Omitting the name: one — the SDK "
    "sends a default, so you cannot even decline to identify yourself.",
    "The specification says this field must not be used for security, and it is right. The point is "
    "that nothing in the protocol can tell the difference. Look at the right-hand column: there is "
    "nothing to check.",
])
replace_quote("## Scene 1 — A verified call", [
    "Same interface, same call — now carrying the credential, the agent's delegated identifier and a "
    "signature. Eight checks: what the request alone settles; the signature, under the signer's "
    "current key read from a witness, never from the request; the signer is the holder or their "
    "agent; every issuance anchored in its issuer's log; revocation; the role. Allowed.",
])
replace_quote("## Scene 2 — A client without the extension", [
    "An ordinary client with none of this. It connects, sees every tool, and the public tool works. "
    "The protected one stops at the first check — unverified, not refused: it never made a claim. "
    "Nothing broke.",
])
replace_quote("## Scene 3 — Revocation", [
    "First, the same call: allowed. Now the legal entity withdraws the credential — a real "
    "revocation, written to its transaction event log, not a flag in a database.",
    "Same agent, same call, same key. Read the report, not the verdict: the signature still "
    "verifies, the arguments still match, the chain still holds. Six checks pass. The seventh reads "
    "the issuer's log and finds the withdrawal.",
    "Not 'access denied' — six things still true and one that stopped being true. And the agent "
    "knows not to retry.",
])
replace_quote("## Scene 4 — Through the gateway", [
    "Same agent, one environment variable: it now files with a regulator. The diff on the agent is "
    "empty. The regulator's filing server does no verification — it reads headers a gateway sets: "
    "the LEI, the role, the holder, the agent. Which entity is filing is not a parameter of the "
    "call; it comes from the verified credential.",
])
start, end = section("## Scene 5 — A server written from the skill")
s = s[:start] + (
    "## Scene 5 — cut\n\n"
    "Not recorded. Its point — a server written from the skill alone, running, and the hole it found "
    "in ours — is one sentence on slide 12, where the conformance story already is.\n"
) + s[end:]

# ------------------------------------------------------------------------------ slides
sub("Twenty slides.", "Twenty slides, fourteen minutes and thirty seconds at most, video included.")

sub('''> The code is in the repository. Nothing was run against anyone else's service."

*(Play `demo-scene0.mp4`, 45 seconds.)*''',
    '''> The code is in the repository. Nothing was run against anyone else's service."''')

# 9: drop the implementers' note
start, end = section("### 9 — What we added: the schema")
block = s[start:end]
block = re.sub(r">\n> One structural note for the implementers here:.*?party object\.\"", '"', block, flags=re.S)
block = block.replace('rejection."\n"', 'rejection."')
s = s[:start] + block + s[end:]

replace_quote("### 11 — Three things the paper design did not predict", [
    "Three things cost us days; I will name two, because a second implementer would otherwise pay "
    "for them again. Presentation is the holder's step: a relying party cannot hand someone else's "
    "credential to a service and ask about it, so it verifies the chain itself — that one fact "
    "shapes every deployment. And ask about the issuee, never the signer.",
])
replace_quote("### 12 — Every requirement, traced", [
    "Every MUST and SHOULD in our specification has a row: the code that implements it and the test "
    "that holds it.",
    "A review found something worse than a missing row, and I would rather tell you than have you "
    "find it: our verifier checked the request signature under a key the request itself carried. "
    "Every test passed, because every test signed with the right key. It now reads the key from the "
    "signer's own log, and the tests that would have caught it fail against the old code.",
    "And a server written by a fresh model from our skill alone found one more gap in ours: nothing "
    "tied an ECR's LEI to its legal entity. Both are fixed.",
])
sub("*(Play `demo-full.mp4`, 4:05.)*", "*(Play `demo-full.mp4`, 2:50.)*")
replace_quote("### 15 — Two ways to check an identity", [
    "Institutions already check identity two ways. A public directory: publish once, anyone "
    "verifies, even before making contact. And the letter of confirmation — office A writes to "
    "office B, B replies, A relies on the reply.",
    "As an agent call, B returns a signed attestation and A verifies B's signature: a second instead "
    "of days, a signature instead of a letterhead. The limit is today's: relying on an attestation "
    "means relying on that institution's judgment. The system insists only that the attesting "
    "institution was verified first, and records whose word it took.",
])
replace_quote("### 18 — Limits", [
    "I would rather state these than be asked. A valid credential proves an organization asserted a "
    "role; it does not prove the request is legitimate — that policy stays yours.",
    "Two are ours to fix. We compare key logs across the witnesses we are given, but run no "
    "independent watcher. And withdrawing one agent without touching the person's credential is not "
    "built; withdrawing the credential works, and stops every agent under it.",
])
sub("QVI coverage still expanding · Our demo root is self-configured · One witness is asked — conflicting\nkey logs are not yet detected ·",
    "QVI coverage still expanding · Our demo root is self-configured · Key logs compared across the\nconfigured witnesses — no independent watcher yet ·")
replace_quote("### 19 — Three requests", [
    "To the institutions here, first, because you would carry the risk: one procedure, one "
    "counterpart, stages zero to three, and no change to the system behind your gateway.",
    "To GLEIF: an ECR role vocabulary for agent contexts; a confirmation or correction of our "
    "delegation model against the Ecosystem Governance Framework — we would rather be corrected now "
    "than at deployment; and test credentials against a real root, so the honesty statement can be "
    "retired.",
    "To AAIF: this belongs in the Security Interest Group and the ext-auth discussion. I would like "
    "to be told where it is wrong.",
])
sub("packages/  mcp-vlei — extension, client, KEL + chain verification, 143 tests",
    "packages/  mcp-vlei — extension, client, KEL + chain verification, 155 tests")

out = ROOT / "docs" / "proposals" / "DEMO-14min.md"
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(s, encoding="utf-8")
print("ok", out)
