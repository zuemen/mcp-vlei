"""Second pass over docs/proposals/DEMO-14min.md: slide 14 corrected, questions added, timing table.

Run after make_proposal.py (which rebuilds the file from docs/DEMO.md).
"""
import importlib.util
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "docs" / "proposals" / "DEMO-14min.md"
s = PATH.read_text(encoding="utf-8")


def sub(old: str, new: str) -> None:
    global s
    assert old in s, old[:80]
    s = s.replace(old, new, 1)


def section(heading_prefix: str, end_marker: str = "\n---\n") -> tuple[int, int]:
    start = s.index(heading_prefix)
    end = s.index(end_marker, start)
    return start, end


# ------------------------------------------------------------------------------ slide 14, corrected
# Fact-checked 2026-09-24 against MOEA's release and presentation, MOEACA's practice statement, the
# GPKI certificate profile, MODA's wallet code and the GLEIF API. Two claims in the canonical slide do
# not survive: the business certificate is its own app (its place in the wallet is reported, not
# shown), and the per-site, per-time-limit delegation on the phone is announced, not live.
TAIWAN_SLIDE = """### 14 — Taiwan already runs this model

**Slide.** Two columns — Taiwan today and this proposal: holder (people, through the Digital Identity
Wallet 數位憑證皮夾; companies, through the MOEA business certificate 工商憑證 · legal entities and the
agents acting for them), delegation (to employees, through the certificate's attached card 附卡 —
per site and time limit announced for the phone · to an agent, a delegated identifier under the ECR
holder), identifier (統一編號 · LEI, whose record for a Taiwanese entity carries the 統一編號), reach
(domestic, over 180 G2B and B2B systems · verifiable abroad, back to GLEIF — ISO 17442-3:2024),
built on (X.509 for the certificate, OpenID4VC and SD-JWT VC for the wallet · KERI, ACDC).

**Footer:** *Taiwan already delegates a company's authority to its people. What it does not yet do is
delegate it to an agent, or make it verifiable abroad.*

> "Taiwan already runs this model — for people. The Digital Identity Wallet lets a person show only
> what a counter needs to see. And the MOEA business certificate already lets a company hand its
> authority to an employee, through an attached card; the ministry has announced the same on the
> phone, per site and per time limit.
>
> What neither does is the holder on the right: an agent acting for the entity. The certificate's
> own practice statement marks authenticating server software 'not applicable'. And it is domestic
> by design — but a Taiwanese company's LEI record already carries its unified business number, so
> the two meet at the same number. The Deputy Minister made the point this month: agents may need an
> ID.
>
> Same idea, a different holder — and one a counterparty abroad can verify."

*(Say "attached card" and, for the phone, "announced": MOEA's own release says the mobile delegation
"will be provided" (將提供), and today every mobile certificate is itself an attached card. Do not
say the business certificate is in the wallet — it has its own app, and its place in the wallet
ecosystem is reported by the press, not shown. The finance, HR and sales example is CNA's reporting,
not the ministry's release. GLEIF's data lists Taiwan as "Taiwan (Province of China)": put no GLEIF
search page on screen. The Deputy Minister's words are as reported; say "made the point".)*

**Sources** (checked 2026-09-24):
- Wallet pilot since 17 Dec 2025, selective disclosure: MODA press release 18262,
  <https://moda.gov.tw/press/press-releases/18262>
- Wallet stack — OID4VCI, OID4VP, DIDs, SD-JWT at the verifier; no KERI or ACDC: MODA's
  <https://github.com/moda-gov-tw/TWDIW-official-app> (README, `core-system/twdiw-vp-handler`)
- Mobile business certificate, 18 May 2026; "將提供行動附卡授權功能", per-site and per-period
  authorization as a future function; "目前核發的行動工商憑證在系統定義上均為「附卡」": MOEA news
  122729, <https://www.moea.gov.tw/MNS/populace/news/News.aspx?kind=1&menu_id=40&news_id=122729>;
  the release's presentation, p.12–14 ("附卡授權機制上路後", "未來藍圖"),
  <https://www.moea.gov.tw/MNS/populace/news/wHandNews_File.ashx?file_id=125306>
- Finance, HR, sales by site and time limit — CNA via UDN, 18 May 2026,
  <https://udn.com/news/story/7238/9510151> (reporting, not the release)
- Separate app (tw.gov.nat.moeaca); "joins the wallet ecosystem"; disclosure control in future:
  iThome, 18 May 2026, <https://www.ithome.com.tw/news/175909>
- Attached-card delegation on the IC card, in 14 systems; holders "仍以人為主":
  <https://moeaca.nat.gov.tw/attachedCard/attachedCard_1.html>; the holder field is a natural
  person's ID: <https://moeaca.nat.gov.tw/develop/develop_1.html>
- Practice statement v2.5 — §3.2.7 server application software authentication "不適用"; §3.2.6
  interoperation "不適用"; X.509 v3 and RFC 5280 (§7.1.1):
  <https://moeaca.nat.gov.tw/document/moeaca_cps_v2.5.pdf>
- 統一編號 in `subjectDirectoryAttributes` (uniformOrganizationID, OID 2.16.886.1.100.2.101), not in
  the subject name: GPKI certificate profile v2.4 §1.3.6,
  <https://grca.nat.gov.tw/download/GPKI_Cert_and_CRL_Profiles_v2.4.pdf>
- Over 180 G2B and B2B systems:
  <https://gcis.nat.gov.tw/mainNew/English/subclassEnAction.do?method=getFile&pk=1>
- ISO 17442-3:2024, *Verifiable LEIs (vLEIs)*, October 2024: <https://www.iso.org/standard/85628.html>
- A Taiwanese LEI record's `registeredAs` is the 統一編號 (checked: 82920981; TWSE 03559508);
  1,094 issued and 592 lapsed LEIs with a Taiwanese legal address; no LEI issuer based in Taiwan,
  ten accredited for it; no QVI based in Taiwan: GLEIF API, 2026-09-24
- Deputy Minister Hou Yi-hsiu on agents needing an ID, 9 Sep 2026, as reported:
  <https://techorange.com/2026/09/09/moda-ai-agent/>
- **Not used:** "已非超前部署，而是不得不正面應對" — see docs/DEMO.md, slide 14.
"""
start, end = section("### 14 — Taiwan already runs this model")
s = s[:start] + TAIWAN_SLIDE + s[end:]

# ------------------------------------------------------------------------------ questions
sub("""> event log and presents *that person's* credential. The accountable party stays a person. A useful
> consequence: two independent revocation switches. Revoke the delegation and one agent stops.
> Revoke the credential and everything acting under it stops, including the person.\"""",
    """> event log and presents *that person's* credential. The accountable party stays a person. Revoke
> the credential and everything acting under it stops. Withdrawing one agent alone is not built —
> it is on the limits slide.\"

*(The canonical answer promises "two independent revocation switches". Only one is built; saying
two contradicts slide 18.)*""")

QUESTIONS = """
### "GLEIF has proposed an Agent Mandate Credential. How does this relate?"

> "Closely — and I would rather say so than be told. GLEIF's working paper on agentic payments, this
> September, sketches an Agent Mandate Credential: issued by a role holder to the agent's
> identifier, which is itself a delegated identifier under that person's key event log. That is the
> delegation we built. The difference is where the scope lives: we read it from the ECR; the paper
> puts it in a credential of its own, issued to the agent — which would also give us the one thing
> on our limits slide we have not built, withdrawing one agent without touching the person. The
> paper names two open items: the credential's schema, and a standard interface for presenting and
> verifying the chain. This is a working version of the second, for MCP. The paper says it is not
> an official GLEIF position, and neither is our reading of it."

*(Source: GLEIF Working Paper Series, "Agentic AI in Payments: Establishing Interoperable Trust and
Control", September 2026 — Annex A; the disclaimer is on p.1.
<https://www.gleif.org/organizational-identity/research-publications/2026-08-13_agentic_ai_in_payments_v1.0-1.pdf>)*

### "Taiwan already has the MOEA business certificate. Why vLEI?"

> "They do not compete. The business certificate is Taiwan's domestic credential — X.509, with
> legal effect under the Electronic Signatures Act, naming a company by its unified business number
> — and it already delegates to people, through the attached card. Two things it does not do. It
> does not delegate to an agent with a scope: its practice statement marks server-software
> authentication not applicable. And we found no arrangement for verifying it abroad. A Taiwanese
> LEI record already carries the unified business number, so the two meet at the same number: the
> certificate for signatures at home, vLEI for agents and for counterparties abroad."

中文備用：

> 「兩者不衝突。工商憑證是國內的 X.509 憑證，依電子簽章法具效力，以統一編號識別企業，也已經能透過附卡把權限授權給員工。
> 它目前沒做的有兩件事：一是授權給 agent 並限定範圍——工商憑證的憑證實務作業基準，對伺服器應用軟體鑑別寫的是「不適用」；
> 二是境外驗證——我們查不到對外互認的安排。台灣企業的 LEI 紀錄裡，registeredAs 欄位就是統一編號，兩者在同一個號碼上接得起來：
> 國內簽章用工商憑證，agent 與境外的交易對手用 vLEI。」

*(Do not say the extension already carries other credential systems: it verifies vLEI chains only.
If asked whether the business certificate could be a second profile: "possible in principle; we
have not built it." Do not say vLEI is legally recognized abroad — it is verifiable abroad;
recognition is each jurisdiction's, and we did not check it.)*

### "Hardly any Taiwanese company has an LEI."

> "True today: about eleven hundred issued LEIs have a Taiwanese legal address, and no LEI issuer or
> vLEI issuer is based here — ten accredited issuers serve Taiwan from abroad. So this does not start
> as a national scheme. It starts where an LEI is already needed, in cross-border finance and
> reporting, and the first request on the last slide is one procedure with one counterpart, not a
> mandate."

*(Figures from the GLEIF API, 2026-09-24: 1,094 issued, 592 lapsed. Compare roughly 560,000 business
certificate cards, as reported by CNA — if someone raises the gap, agree with it.)*
"""
sub("# Anticipated questions\n\nOne paragraph each, rehearsed.\n",
    "# Anticipated questions\n\nOne paragraph each, rehearsed.\n" + QUESTIONS)

sub("""| 0–3 | The problem | Every layer proves domain control or a human user. The agent is absent from the protocol |
| 3–5 | Why now | Autonomous execution × actions with legal effect × across organizations |
| 5–7 | What GLEIF already solved | LE, ECR, revocation, offline verification — and why ECR, not OOR |
| 7–9 | What we added | One slide for the schema, one for verification |
| 9–12.5 | Demo recording | Six scenes, 4:05 |
| 12.5–14 | Government | Two verification modes, six stages, what an institution gets |
| 14–15 | Three requests | Government, GLEIF, AAIF |

Rehearse to 14:00. A 15-minute slot with questions is a 13-minute talk.""",
    """| 0–2¼ | The problem | Every layer proves domain control or a human user. The agent is absent from the protocol |
| 2¼–2½ | Why now | Autonomous execution × actions with legal effect × across organizations |
| 2½–3 | What GLEIF already solved | LE, ECR, revocation, offline verification — and why ECR, not OOR |
| 3–6 | What we added | The schema, verification, what building it taught us, every requirement traced |
| 6–9½ | Demo recording | Five scenes, 2:50 |
| 9½–12¾ | Government | Taiwan, two verification modes, six stages, what an institution gets, limits |
| 12¾–13¾ | Three requests | Government, GLEIF, AAIF — then the artifacts |

Rehearse to 13:45; 14:30 is the limit. If questions come out of the same fifteen minutes, cut slide
15 to its first two sentences and slide 10 to its last paragraph first.""")

PATH.write_text(s, encoding="utf-8")

# ------------------------------------------------------------------------------ timing table
spec = importlib.util.spec_from_file_location("build_deck", ROOT / "scripts" / "build-deck.py")
deck = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deck)
notes = deck.load_notes(PATH)
VIDEO = {13: 170}  # the 2:50 recording plays on slide 13
rows, total = [], 0.0
for n in sorted(notes):
    heading, text = notes[n]
    words = len(re.findall(r"[A-Za-z0-9'’-]+", re.sub(r"\[[^\]]*\]", "", text)))
    seconds = words / 130 * 60 + VIDEO.get(n, 0)
    total += seconds
    extra = f" + video {VIDEO[n] // 60}:{VIDEO[n] % 60:02d}" if n in VIDEO else ""
    rows.append(f"| {n} | {heading} | {words}{extra} | {seconds:.0f} | "
                f"{int(total // 60)}:{int(total % 60):02d} |")
assert total <= 14.5 * 60, f"over 14:30: {total / 60:.2f} min"
table = ("## Timing, slide by slide\n\n"
         "Spoken words at 130 a minute, stage directions excluded; the recording counted at its "
         f"length. Total **{int(total // 60)}:{int(total % 60):02d}** — the limit is 14:30, "
         "leaving the rest of the slot for questions.\n\n"
         "| Slide | Heading | Words | Seconds | Running |\n|---|---|---|---|---|\n"
         + "\n".join(rows) + "\n\n")
s = PATH.read_text(encoding="utf-8")
anchor = "## Fixed vocabulary"
s = s.replace(anchor, table + anchor, 1)
PATH.write_text(s, encoding="utf-8")
print(f"ok — {total / 60:.2f} min")
