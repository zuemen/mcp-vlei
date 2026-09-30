# Adopting Agent Identity in Public-Sector Institutions

**Audience:** policy and operational staff at government institutions
**Prerequisite reading:** none. No code appears in this document.
**中文摘要在文末。**

> **All identities are fictional. The root of trust is self-hosted for demonstration.**
> 所有身分都是虛構的。信任根為示範而自行架設。

This document answers one question: if a government institution wants to let agents act — its own
agents, or other institutions' agents calling it — what has to change, and what does it adopt to
make that change? Section 7 works one case through end to end: an employer's agent filing labour
insurance enrolments — **simulated, not connected to the Bureau of Labor Insurance**.

## 1. The anchor: this has already been done with people

GLEIF has run a regulatory-filing pilot ([`GLEIF-IT/reg-pilot`](https://github.com/GLEIF-IT/reg-pilot)).
In it, a filer signs in with a vLEI ECR credential, uploads a signed filing, and the regulator's
`vlei-verifier` validates the credential chain before the filing is accepted. The regulator learns
which legal entity filed, under which role, with a credential that can be revoked.

That pilot has a person in front of a browser. This project extends the same trust structure to an
**agent** acting through MCP. The credentials are the same and the revocation mechanism is the same;
GLEIF's verifier can be the same too, though the reference deployment reads revocation from the
issuer's log directly while an upstream defect is open (`docs/upstream/`). What is new is where the credential travels: inside the protocol call rather
than inside a web session.

That continuity is the substance of the proposal. Nothing here asks an institution to adopt a novel
trust model — it asks it to use the one it is already being asked to accept for human filers, in the
one place where it is currently impossible.

## 2. Two ways to check an identity

Institutions already have both of these patterns. They are not new procedures; they are existing
procedures with a verifiable form.

### (a) Passive checking from a public location

The institution publishes its Legal Entity credential at a fixed, public address — the same idea as
a public key directory or a published seal. Anyone who wants to verify who operates a service
fetches it and checks it themselves.

The institution does nothing per verification. It publishes once. Every counterparty, every agent,
every partner institution can verify independently, at any time, including before making contact.
There is no request to process, no queue, and no per-verification cost.

### (b) Confirmation between institutions ("來函確認")

District office A writes to district office B to confirm a birth record. B checks its own records,
replies confirming, and A relies on B's reply. A does not re-derive the record; it trusts B's
confirmation, because B is a known and accountable institution.

The agent equivalent: institution A's agent calls institution B's MCP server. B returns its answer
together with a **signed attestation** — a statement saying "we verified this party; here is the
LEI, the role, and when we checked it." A verifies B's signature and relies on B's statement.

This is the concrete meaning of "agents make government more efficient." The correspondence-and-
confirmation procedure that exists today is not replaced by something unfamiliar; it becomes a
verifiable call that completes in a second instead of a week, and leaves a stronger record than the
paper one did — a signature rather than a letterhead.

**The honest caveat, stated to the institution up front:** relying on an attestation means relying
on the attesting institution's judgment, exactly as relying on a letter of confirmation does today.
The system enforces that the attesting institution must itself have been verified under mode (a)
first, and that every decision records whose attestation it rested on. What it cannot do is make B
careful. That was always true of the letter as well.

## 3. The adoption path

Six stages, numbered 0 to 5. Each is independently useful: an institution that stops after stage 2 has gained
something real, and nothing in a later stage is required to make an earlier one work.

### Stage 0 — Obtain a credential and define the role vocabulary

- **Who:** the institution's legal or administrative office obtains the LE credential through a
  Qualified vLEI Issuer. Each business unit defines its own ECR role names.
- **What changes:** nothing technical. This is a registration and a vocabulary decision.
- **The vocabulary is the substantive work.** "labor-insurance-filing", "record-lookup",
  "permit-issuance" — these are the names that will appear in every authorization decision and every
  audit record afterwards. They should be chosen by the business unit that owns the process, not by
  an IT department, and they should match how the unit already describes who may do what.

### Stage 1 — Publish the institution's credential

- **Who:** whoever operates the institution's MCP server.
- **What changes:** the server publishes its LE credential at a fixed public location.
- **Effect:** any counterparty can establish who operates the service, independently, before
  contacting it. This is mode (a), and it costs the institution nothing per verification.

### Stage 2 — Declare which tools need which role

- **Who:** the business unit, expressed by whoever maintains the server.
- **What changes:** each tool that requires identity declares the role and any limits it requires —
  in the service's own published description, where callers already read it.
- **Effect:** a well-behaved agent can determine **before calling** whether it is entitled. Failed
  attempts stop arriving. The declared permission and the enforced permission are the same object,
  so they cannot drift apart.

### Stage 3 — Put verification at the gateway

- **Who:** the infrastructure team.
- **What changes:** an authorization gateway in front of existing systems performs the verification
  and passes the established facts downstream as ordinary request headers: the LEI, the role, the
  credential holder and the acting agent, plus a record of the checks behind them — five headers in
  `examples/regulator/` (`x-vlei-lei`, `x-vlei-role`, `x-vlei-holder-aid`, `x-vlei-delegate-aid`,
  `x-vlei-report`).
- **Effect:** **existing systems are not modified.** They read a header, as they already do for
  every other authentication scheme they sit behind. This is the stage that determines whether
  adoption is a procurement question or a rewrite, and `examples/regulator/` demonstrates the
  gateway shape end to end: a labour-insurance simulator containing no identity code at all.

### Stage 4 — Move inter-institution checks to attestations

- **Who:** pairs of institutions that already correspond.
- **What changes:** a confirmation request becomes a call that returns a signed attestation.
- **Effect:** mode (b). Correspondence that takes days takes seconds, and the resulting record is
  cryptographically verifiable rather than a scanned letter.

### Stage 5 — Record identity in the audit trail

- **Who:** the records or audit function.
- **What changes:** audit records store the LEI, the role, the delegated agent identifier, and the
  credential identifier, instead of an account name.
- **Effect:** "which organization did this, under whose authority, with what mandate" becomes
  answerable from the record alone, after the fact, without asking the counterparty.

### The path, in one picture

```mermaid
flowchart TD
    S0["Stage 0 · Legal / administrative office<br/>Obtain the LE credential through a QVI<br/>Business unit defines its ECR role vocabulary"]
    S1["Stage 1 · Service operator<br/>Publish the LE credential at a fixed public location"]
    S2["Stage 2 · Business unit<br/>Each tool declares the role and limits it requires"]
    S3["Stage 3 · Infrastructure<br/>Gateway verifies and passes LEI, role, holder and agent downstream<br/><b>Existing systems unchanged</b>"]
    S4["Stage 4 · Pairs of institutions<br/>Confirmation requests become signed attestations"]
    S5["Stage 5 · Records / audit<br/>Store LEI, role, delegated AID, credential SAID"]

    G1["Counterparties can verify who operates the service,<br/>independently, before making contact"]
    G2["A well-behaved agent knows before calling<br/>whether it is entitled"]
    G3["Adoption is a configuration change,<br/>not a rewrite"]
    G4["Correspondence that took days takes seconds"]
    G5["'Who did this, under whose authority'<br/>is answerable from the record alone"]

    S0 --> S1 --> S2 --> S3 --> S4 --> S5
    S1 -.-> G1
    S2 -.-> G2
    S3 -.-> G3
    S4 -.-> G4
    S5 -.-> G5
```

Each stage is independently useful. An institution that stops after stage 2 keeps everything stages
1 and 2 gave it, and stage 4 is the only one that needs a counterpart.

### Mode (b) in sequence

```mermaid
sequenceDiagram
    participant A as Institution A<br/>(its agent)
    participant B as Institution B<br/>(MCP server + gateway)
    participant V as B's verifier

    Note over A,B: Before anything: A verifies B's LE credential<br/>from B's public location — mode (a)

    A->>B: tools/call, presenting the ECR credential,<br/>delegated AID and signature
    B->>V: verify signature under the signer's key state, delegation,<br/>chain to an accepted root, revocation, role
    V-->>B: valid · LEI, role, holder, agent
    B->>B: perform the lookup
    B-->>A: result + signed attestation<br/>(verifierAid, subjectAid, LEI, role, verifiedAt, sig)

    A->>A: verify B's signature under B's<br/>already-established key state
    Note over A: Accepted — and the record says<br/>whose attestation it rested on
```

The order matters. A verifies B under mode (a) **first**; an attestation from a party whose own
identity has not been established is worth nothing, and the software refuses to accept one.

## 4. What an institution actually adopts

| Recipient | What they adopt | Effort |
|---|---|---|
| Agents | A skill and a software package | The skill is a document; the package is a dependency |
| Institution systems | A gateway configuration template — **or** the package, if the team prefers to embed it | Gateway: no change to existing systems. Package: a small change in one place |
| Business units | An ECR role vocabulary | A decision, not a deployment |

There is no new protocol to standardize, no MCP core change to wait for, and no dependency on any
other institution adopting first. An institution that adopts alone still gains stages 1–3 and 5.
Stage 4 is the only one that requires a counterpart, and it degrades gracefully: where the other
institution has not adopted, mode (a) still works.

## 5. What the institution gets

| Question | Today | After adoption |
|---|---|---|
| Who filed this? | An account, held by a person, in a system | An LEI, a role, and a delegated agent identifier, verifiable after the fact |
| Someone's authority changed | An account is edited; downstream systems learn later, or never | The credential is revoked at source; every relying party sees it at the next check |
| A new registration system is built | Identity is rebuilt again, differently | The same credentials are accepted; the new system reads the same headers |
| Integration with existing identity | Separate, parallel to everything else | vLEI answers *which organization*; existing sign-on still answers *which user*. Both, not either |
| Audit record | An account name, meaningful only inside one system | LEI, role, delegated AID, credential identifier — meaningful to an auditor who was never given access to that system |

The fourth row is the one most likely to be misread, so it is worth stating directly: **this does
not replace existing user authentication.** An institution that drops user sign-on because it now
has organizational identity has weakened itself. The two answer different questions, and a
high-value action should require both.

## 6. Limits, stated plainly

- **Verifiable is not trustworthy.** A valid credential proves an organization asserted a role for
  someone. It does not prove the request is legitimate, correct, or wise. Authorization policy
  remains the institution's own work, and this makes that policy enforceable — it does not write it.
- **LEIs are not issued to individuals acting in a personal capacity** — only to legal entities and
  registered sole proprietors. A citizen acting personally has
  no LEI and will not acquire one. This addresses organization-to-organization interaction:
  institutions, companies, associations. It is not a citizen identity scheme, and should not be
  presented as one.
- **There is a cost, and it recurs.** LEI registration carries an annual fee, as does vLEI
  credential issuance through a Qualified vLEI Issuer, on top of the operational work of managing
  role vocabularies and revocation. One thing worth knowing before treating this as a blocker:
  GLEIF's **Validation Agent** framework lets a financial institution perform the verification
  inside the KYC process it already runs for a client, so an entity that banks somewhere may be able
  to obtain its credentials through an existing relationship rather than as a separate procurement.
- **The QVI ecosystem is still expanding.** The set of Qualified vLEI Issuers is growing but finite,
  and coverage varies by jurisdiction. This is a live constraint on how fast an institution can move
  past stage 0, and it should be checked before a timeline is committed to. For Taiwan it is a hard
  one today: see section 7.4.
- **The demonstration uses a self-configured root of trust.** Real KERI, real ACDC, real
  revocation — but the root is one we control, not GLEIF's. Every claim in the demonstration
  holds; the trust anchor in production would be GLEIF's, and the demonstration says so wherever it
  is shown.
- **Agent delegation conventions are not yet settled.** This project uses a delegated AID created
  under the ECR holder's key event log. It is a reasonable reading of the existing mechanisms rather
  than a ratified pattern, and confirming it is one of the requests this project brings to GLEIF.

## 7. Worked example: labour-insurance enrolment (simulated)

> **Simulated — not connected to the Bureau of Labor Insurance.** `examples/regulator/labor-insurance-sim/`
> files nothing anywhere. It knows employers only by a test unified business number (`00000000`),
> people only by fictitious references (`EMP-0001`), and salary grades only as small integers. What
> is real is the verification: the credentials, the signatures, the revocation and the gateway.

### 7.1 The procedure as it stands

An employer (投保單位) must notify the Bureau on the day a worker starts or leaves; cover starts or
stops that day, and a notice filed late starts cover only from the day after, besides the penalty in
§72. This is **Article 11** of the Labor Insurance Act — the timing of enrolment and withdrawal is
§11 alone. **Article 14** is a different rule: what the monthly insured salary is, and the deadlines
for reporting a salary adjustment (by the end of August for February–July changes, by the end of
February for August–January ones). ([§11](https://law.moj.gov.tw/LawClass/LawSingle.aspx?pcode=N0050001&flno=11),
[§14](https://law.moj.gov.tw/LawClass/LawSingle.aspx?pcode=N0050001&flno=14))

Through the Bureau's e-service system an employer may file on the day itself, including on a
holiday; **pre-file up to ten days before** the start or leaving date; or, for a start or leaving
date that fell on a holiday, file on the first working day afterwards, effective from the holiday.
([BLI, labour insurance Q&A, question 25](https://www.bli.gov.tw/0101364.html))

On paper, the enrolment form carries **three seals**: the employer's, the responsible person's
(負責人) and the handler's (經辦人). ([Form 承表 D/E/G/H, notes 1 and filling instruction 4](https://www.bli.gov.tw/Files/10266);
[form page](https://www.bli.gov.tw/0009837.html))

Online, the e-service system authenticates with **an organisation certificate and a natural-person
certificate together**. The organisation certificate depends on the kind of employer — the MOEA
business certificate (工商憑證, MOEACA) for companies, and the government (GCA), organisation and
group (XCA) or medical institution (HCA) certificates for others — and the authorised administrator
and every labour-insurance handler must each hold a natural-person certificate card to operate the
system. ([BLI handbook, 玖 網路申辦, pp. 170–172](https://www.bli.gov.tw/Files/18080);
[e-service system page](https://www.bli.gov.tw/0021883.html)) The January 2025 expansion — to
employers holding a GCA, XCA or HCA certificate and a unified business number or withholding unit
number, with the responsible person's natural-person certificate — concerns **applying online to
establish a new insured unit**; it is not a change to how a registered employer signs in.
([BLI, 2025-01-07](https://www.bli.gov.tw/0108797.html); [BLI, 2025-04-01](https://www.bli.gov.tw/0108887.html))

### 7.2 Three seals, three credentials — and a fourth holder

| On the paper form | Who it stands for | vLEI | In the demonstration |
|---|---|---|---|
| 投保單位印章 · employer's seal | the legal entity | **LE** credential; the LEI's entity record carries the 統一編號 as `registeredAs` | employer card: `統一編號 00000000 (test value)`, linked by `registeredAs` |
| 負責人印章 · responsible person's seal | the person holding the official role | **OOR** credential (official organisational role) | not issued: the demonstration's chain has no OOR |
| 經辦人印章 · handler's seal | the person the employer designated for this work | **ECR** credential, role `labor-insurance-filing` | agent card: the ECR |
| — | an agent acting for the handler | **delegated AID** under the ECR holder's key event log | agent card: the delegated identifier that signs each call |

The first three rows are correspondences, not equivalences: a seal is a mark of consent the Bureau
recognises in law, and a credential is not that until a rule says it is. The fourth row is the one
the paper form has no place for, and the one this project contributes.

### 7.3 What the demonstration runs

The agent holds an ECR with the role `labor-insurance-filing`. Each call goes through the gateway,
which verifies it with the same package every other example uses and a closed policy
(`examples/regulator/vlei-authz/policy.json`), then reaches the simulator with four headers — LEI,
role, holder, agent. The simulator maps the LEI to a unified business number through
`registered_as.json` (test values) and shows an employer only its own records.

| Tool | Requires |
|---|---|
| `list_insured()` | an ECR; returns only the calling employer's records |
| `enroll_employee(person_ref, start_date, salary_grade)` | role `labor-insurance-filing`; `start_date` today to today + 10 |
| `withdraw_employee(person_ref, end_date)` | role `labor-insurance-filing`; `end_date` today to today + 10 |
| `adjust_insured_salary(person_ref, salary_grade)` | role `labor-insurance-payroll` |

Days are counted in Taiwan's time (`VLEI_POLICY_UTC_OFFSET=+08:00` on `vlei-authz`), not in the
container's UTC, which would shift the window by a day for eight hours of every morning.

The ten-day window is the e-service pre-filing rule of 7.1, written as an `arguments` rule
(`spec/SPEC.md`, *Tool-level requirements*). The split between a filing role and a payroll role is
the demonstration's vocabulary — the employer's choice, not a Bureau rule. Four scenes, each result
read from a real `VerificationReport`:

| Scene | Call | Result |
|---|---|---|
| 1 | enrol `EMP-0001` from today | `ALLOWED` |
| 2 | the same agent adjusts a salary | `REFUSED · role_mismatch` — the ECR is for filing, not payroll |
| 3 | pre-file a start date fifteen days ahead | `REFUSED · scope_exceeded` — outside today to today + 10 |
| 4 | the employer revokes the handler's ECR; the agent enrols again | `REFUSED · revoked` |

**What the simulation does not model:** the holiday rule (a fixed day count does not move a deadline
to the next working day); the retroactive effect of a holiday filing; late filing, which the Act
permits with cover from the next day and a penalty, and which the gateway's window refuses; the
real salary-grade table; and everything the Bureau checks about the worker.

### 7.4 What is already in place, what is not, and what this adds

**The pain this addresses.** Each credential the procedure uses today is bound to a person or a card:
the natural-person certificate to its holder; the mobile business certificate to one phone — "one
card, one device, one certificate", its key generated and kept in the phone's secure area and not
exportable, unlocked with a PIN **or** the phone's biometrics (the user chooses)
([MOEA, 2026-05-18](https://www.moea.gov.tw/MNS/populace/news/News.aspx?kind=1&menu_id=40&news_id=122729);
[presentation, pp. 4–5, 7](https://www.moea.gov.tw/MNS/populace/news/wHandNews_File.ashx?file_id=125306)).
The business certificate's practice statement marks authenticating equipment or server application
software **"不適用"** (not applicable) ([CPS v2.5, §3.2.7, p. 21](https://moeaca.nat.gov.tw/document/moeaca_cps_v2.5.pdf)).
None of them has a holder that is software. **The risk** that follows — stated as a risk, not as an
observed practice — is that an employer who wants software to file shares a person's certificate
card and PIN with it, and the record then names a person who did not act.

**What is not in place: a vLEI issuer in Taiwan.** GLEIF's data lists 41 LEI issuers and 8
Qualified vLEI Issuers; none has its legal address or headquarters in Taiwan
([LEI issuers](https://api.gleif.org/api/v1/lei-issuers), [vLEI issuers](https://api.gleif.org/api/v1/vlei-issuers),
each issuer's own LEI record; checked 2026-09-29). A Taiwanese entity can obtain an LEI from an
issuer based elsewhere, and its record then carries its unified business number as `registeredAs`
(checked 2026-09-29 against two records, among them the Taiwan Stock Exchange's:
[`registeredAs` 03559508](https://api.gleif.org/api/v1/lei-records?filter%5Bentity.registeredAs%5D=03559508)). Its vLEI credentials would today come from a QVI abroad.

**A domestic root is conceivable, and not designed here.** The MOEA business certificate authority
already binds a certificate to a unified business number, domestically and at scale. Whether a
credential chain could be anchored in it — rather than in GLEIF's root — is a question for the
authorities concerned. The demonstration anchors in a root it configures itself, and says so.

**What this project adds** is not an identity for employers — the unified business number and the
business certificate already are one. It is the delegation model: an employer's authority, handed
through a designated handler to an agent, **role-scoped** (filing, not payroll), **bounded** (a
filing window), **revocable at source** and **checked on every call** by whoever receives it.

---

## 中文摘要

**問題。** MCP 每一層驗證的都是網域控制權（TLS、OAuth 的 `iss` 與 `client_id`）或使用者身分
（OAuth 的 `sub`），沒有一層驗證法人身分；`clientInfo` 是自報的、協定不驗證，規格說不應（SHOULD NOT）依賴它做安全決策。
人在迴路中時這沒有問題——負責的是那個人。agent 自主執行、跨機關呼叫時，負責的一方在協定中
不存在。

**已有的基礎。** GLEIF 的監理申報試點（reg-pilot）已經讓申報方以 vLEI ECR 憑證登入、上傳簽章
檔案、由 vlei-verifier 查驗。那是人透過瀏覽器；本案把同一套憑證、同一個驗證器、同一套撤銷機制
延伸到 agent 透過 MCP。機關不需要接受一個新的信任模型，只是把已經要接受的那一個，用在目前做
不到的地方。

**兩種查驗方式，機關本來就都有。**

- **公開區域被動查驗**：機關把 LE 憑證公開在固定位置（類似公鑰目錄），誰要查誰自己去查、自己
  驗。機關公布一次，之後每次查驗都不需要機關做任何事，也沒有任何成本。
- **機關間來函確認**：區公所 A 向區公所 B 來函調閱，B 回覆確認，A 信任 B 的回覆。對應到 agent：
  A 的 agent 呼叫 B 的 MCP server，B 回傳帶簽章的確認書，A 驗過 B 的簽章後採信。這就是
  「加速政府效率」的具體意義——原本的來函調閱流程沒有被換掉，而是變成幾秒鐘完成、且留下比紙本
  更強的紀錄。誠實的但書：採信確認書等於採信 B 的判斷，這一點和今天的來函完全一樣；系統能強制
  的是「B 自己必須先被驗過」與「每筆決定都記錄依據的是誰的確認」，不能替 B 把關。

**導入分五階段，每一階段單獨就有用，停在第二階段也有收穫。** 階段 0 取得 LE 憑證、由業務單位
自己訂 ECR 角色詞彙（這是最實質的工作，該由懂流程的單位訂，不是 IT 訂）；階段 1 公開機關的
LE 憑證；階段 2 需要身分的工具在對外說明中宣告所需角色與範圍，agent 呼叫前就能自己判斷有沒有
資格；階段 3 驗證放在閘道，**既有系統不必改**，只讀閘道傳來的標頭；階段 4 機關間查驗改為
attestation；階段 5 稽核紀錄改記 LEI、角色、委任 AID、憑證識別碼。

**用什麼納入。** 給 agent 的是一份 skill 加一個套件；給機關系統的是閘道設定範本（不改既有系統），
或套件（改一個地方）；給業務單位的是 ECR 角色定義。沒有新協定要標準化，不必等 MCP 核心改版，
也不必等別的機關先動——單獨導入仍然拿得到階段 1–3 與 5。

**限制要講清楚。** 可驗證不等於可信賴，授權政策還是機關自己的事；LEI 只發給法人，不發給以
私人身分行動的自然人，這不是國民身分方案；LEI 與 vLEI 都有年費——但 GLEIF 的 Validation Agent
制度允許金融機構在既有 KYC 流程中協助客戶取得，有往來銀行的機構可能不必另外走採購；QVI 生態
仍在擴展，各法域覆蓋不一，排時程前要先確認；本案的示範用自架信任根——KERI、ACDC、驗證器、撤銷都是真的，只有根是我們自己的，
正式環境會是 GLEIF 的，所有展示場合都會標明；agent 委任的慣例尚未定案，本案用 ECR 持有人 KEL
下的委任 AID，這是對既有機制的合理解讀而非已認可的模式，確認這一點正是本案要向 GLEIF 提出的
請求之一。

**勞保加退保實例（模擬——未連接勞動部勞工保險局）。** 勞工保險條例 §11 規定到職、離職當日申報
加退保（§14 是月投保薪資與調薪申報時限，不是加退保時點）；e 化服務系統可當日申報（含假日）、
到離職日前 10 日內預辦、或假日到離職者於放假後第一個上班日申報。紙本加保表要蓋投保單位、
負責人、經辦人三顆章，分別對應 vLEI 的 LE、OOR、ECR（對應，不是等同）；紙本沒有位置的第四個
持有者——代經辦人行事的 agent——對應 ECR 持有人 KEL 下的委任 AID，這是本案的貢獻。線上申辦
以「單位憑證＋自然人憑證」認證；行動工商憑證「一卡一機一證」、金鑰存於手機安全區不可匯出、
以 PIN 碼或生物特徵（二擇一）解鎖；工商憑證 CPS §3.2.7「資通訊設備或伺服器應用軟體鑑別」
不適用——沒有一種憑證的持有者是軟體，由此衍生的「共用憑證」只是風險，不是觀察到的事實。示範的
四個場景：當日加保 → 允許；同一 agent 調整投保薪資 → role_mismatch；預辦 15 天後到職 →
scope_exceeded；撤銷經辦人 ECR 後再加保 → revoked，結果都來自實際的 VerificationReport。限制：
GLEIF 資料中 41 家 LEI 發行機構、8 家 QVI 沒有一家設在台灣（2026-09-29 查）；國內信任根可以
想像是工商憑證，但本案未設計、也不主張；模擬不處理假日順延、逾期申報與實際投保薪資分級表。
