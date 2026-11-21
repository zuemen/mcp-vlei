"""Re-verify the gateway's decision records, offline: no container, no witness, no network.

    python scripts/verify-audit.py deploy/agentgateway/audit/decisions.jsonl
    python scripts/verify-audit.py decisions.jsonl --line 12      # one record (1-based line)
    python scripts/verify-audit.py receipt.json                   # a labor-insurance-sim receipt
    python scripts/verify-audit.py decisions.jsonl --json         # one JSON verdict per record

Each record vlei-authz writes for a signed ``tools/call`` stores ``signedRequest`` (see
``examples/regulator/vlei-authz/service.py``): the exact vlei-sig/0.3 statement the caller signed —
recipient, credential SAID, window, nonce, the digest of the tool and its arguments — the Ed25519
signature, the digest of what actually arrived, and the signer's key state the gateway checked it
against (KEL sequence number, the SAID of that event, its public keys). A receipt the simulator
returned carries the same object. This script recomputes ``JCS(statement)`` and checks the
signature under that stored key state, so it still verifies after the signer rotates its keys.

For every record it prints who signed (signer AID; holder and agent; the LEI and role the gateway
established) and what (tool, recipient, credential, window, argument digest), and whether it holds:

* an **accepted** call holds only if the signature verifies, the signed digest equals the digest of
  what arrived, the signed credential is the one recorded, the signer is the recorded holder or
  agent, and the decision time lies inside the signed window. An accepted protected call with no
  signed request does not hold.
* a **refused** call holds if every check its own report says passed is borne out (a record that
  says the signature verified must carry one that does). Refused records whose signature does not
  verify are consistent with being refused.

Exit status: 0 when every record holds, 1 when any does not, 2 when the input cannot be read.

What it cannot establish offline: that the stored key state is the signer's real one at that time
(compare ``keyState.eventSaid`` at ``keyState.sn`` with the signer's KEL from any witness), and the
LEI and role, which come from the credential named by the signed SAID — resolve that SAID against
its issuer's registry. Argument values are never stored; given them, their digest must equal
``statement.digest``.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "mcp-vlei" / "src"))

from cryptography.exceptions import InvalidSignature as _BadSignature  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey  # noqa: E402

from mcp_vlei.errors import VleiError  # noqa: E402
from mcp_vlei.signing import (  # noqa: E402
    SIGNATURE_FORMAT,
    canonicalize,
    cesr_decode_signature,
    cesr_decode_verkey,
    statement as rebuild_statement,
)

#: How far outside the signed window a decision time may lie: the gateway's default tolerance.
DEFAULT_SKEW_SECONDS = 60
STATEMENT_FIELDS = ("aid", "aud", "cred", "digest", "exp", "method", "nonce", "ts", "v")


def _time(text: Any) -> datetime | None:
    if not isinstance(text, str):
        return None
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return moment if moment.tzinfo else None


def signature_verifies(signed: dict[str, Any]) -> tuple[bool, str]:
    """Does ``signed["sig"]`` verify over ``JCS(signed["statement"])`` under the stored key state?"""
    stmt = signed.get("statement")
    if not isinstance(stmt, dict) or set(stmt) != set(STATEMENT_FIELDS):
        return False, "the statement is not a vlei-sig/0.3 statement"
    if stmt.get("v") != SIGNATURE_FORMAT or signed.get("alg", "Ed25519") != "Ed25519":
        return False, f"not {SIGNATURE_FORMAT} / Ed25519"
    aud = stmt.get("aud")
    if not (isinstance(aud, dict) and set(aud) == {"aid", "url"}):
        return False, "statement.aud must hold exactly aid and url"
    state = signed.get("keyState")
    if not isinstance(state, dict) or not isinstance(state.get("keys"), list) or not state["keys"]:
        return False, "no key state was recorded: verification stopped before the signer's keys were read"
    if state.get("aid") != stmt.get("aid"):
        return False, "the stored key state is not the signer's"
    try:
        # Rebuilt from its fields, so a statement that carries anything else cannot slip through.
        payload = canonicalize(rebuild_statement(**{k: stmt[k] for k in STATEMENT_FIELDS if k != "v"}))
        raw = cesr_decode_signature(str(signed.get("sig", "")))
    except (VleiError, ValueError, TypeError, KeyError) as exc:
        return False, f"the signature is not readable ({exc.__class__.__name__})"
    for key in state["keys"]:
        try:
            Ed25519PublicKey.from_public_bytes(cesr_decode_verkey(str(key))).verify(raw, payload)
            return True, f"verifies under {stmt['aid']} at KEL sn {state.get('sn')} (event {state.get('eventSaid')})"
        except (_BadSignature, VleiError, ValueError):
            continue
    return False, "the signature does not verify under the recorded key state"


def _normalize(obj: dict[str, Any]) -> dict[str, Any]:
    """An audit record as is; a receipt (structured content of a filing) as an accepted record."""
    if "decision" in obj:
        return obj
    headers = obj.get("receivedHeaders") if isinstance(obj.get("receivedHeaders"), dict) else {}
    return {
        "decision": "allow", "receipt": True, "tool": None, "at": None,
        "lei": headers.get("x-vlei-lei"), "role": headers.get("x-vlei-role"),
        "holderAid": headers.get("x-vlei-holder-aid"), "delegateAid": headers.get("x-vlei-delegate-aid"),
        "signedRequest": obj.get("signedRequest"),
    }


def _check_passed(record: dict[str, Any], name: str) -> bool:
    report = record.get("report")
    checks = report.get("checks") if isinstance(report, dict) else None
    return any(isinstance(c, dict) and c.get("name") == name and c.get("passed") is True
               for c in (checks or []))


def verify_record(obj: Any, *, skew_seconds: int = DEFAULT_SKEW_SECONDS) -> dict[str, Any]:
    """The verdict on one record: ``holds`` (True / False / None for nothing signed), and why."""
    if not isinstance(obj, dict):
        return {"holds": False, "problems": ["not a JSON object"]}
    record = _normalize(obj)
    accepted = record.get("decision") == "allow"
    signed = record.get("signedRequest")
    verdict: dict[str, Any] = {
        "decision": "accepted" if accepted else "refused",
        "layer": record.get("layer"),
        "tool": record.get("tool"),
        "at": record.get("at"),
        "lei": record.get("lei"), "role": record.get("role"),
        "holderAid": record.get("holderAid"), "agentAid": record.get("delegateAid"),
        "receipt": bool(record.get("receipt")),
        "problems": [],
    }
    if not isinstance(signed, dict):
        if accepted and record.get("lei"):
            verdict["holds"] = False
            verdict["problems"].append("an accepted protected call carries no signed request")
        else:
            verdict["holds"] = None  # nothing was signed: a public tool, or refused before a signature
        return verdict

    stmt = signed.get("statement") if isinstance(signed.get("statement"), dict) else {}
    verdict.update(signer=stmt.get("aid"), audience=stmt.get("aud"), credentialSaid=stmt.get("cred"),
                   argumentsDigest=stmt.get("digest"), signedAt=stmt.get("ts"),
                   validUntil=stmt.get("exp"), keyState=signed.get("keyState"))
    ok, why = signature_verifies(signed)
    verdict["signatureVerifies"], verdict["signature"] = ok, why
    digest_matches = stmt.get("digest") is not None and stmt.get("digest") == signed.get("receivedDigest")
    verdict["digestMatches"] = digest_matches
    problems: list[str] = verdict["problems"]

    if accepted:
        if not ok:
            problems.append(f"signature: {why}")
        if not digest_matches:
            problems.append("the signed digest is not the digest of the arguments that arrived")
        if stmt.get("method") != "tools/call":
            problems.append("the statement is not for tools/call")
        if record.get("credentialSaid") and stmt.get("cred") != record["credentialSaid"]:
            problems.append("the signed credential is not the one recorded")
        signer = stmt.get("aid")
        named = [a for a in (record.get("holderAid"), record.get("delegateAid")) if a]
        if named and signer not in named:
            problems.append("the signer is neither the recorded holder nor the recorded agent")
        at, ts, exp = _time(record.get("at")), _time(stmt.get("ts")), _time(stmt.get("exp"))
        if at is not None:
            skew = timedelta(seconds=skew_seconds)
            if ts is None or exp is None or not (ts - skew <= at <= exp + skew):
                problems.append("the decision time lies outside the signed window")
    else:
        if _check_passed(record, "signature") and not ok:
            problems.append(f"the record says the signature verified, but: {why}")
        if _check_passed(record, "digest") and not digest_matches:
            problems.append("the record says the digest matched, but the stored digests differ")
    verdict["holds"] = not problems
    return verdict


def read_records(path: str) -> list[tuple[int, Any]]:
    """(line number, record) for a JSONL file, or (1, object) for a single JSON document."""
    text = sys.stdin.read() if path == "-" else Path(path).read_text(encoding="utf-8")
    try:
        whole = json.loads(text)
    except ValueError:
        whole = None
    if isinstance(whole, dict):
        # A tool result wrapping a receipt: {"structuredContent": {...}} or the receipt itself.
        for key in ("structuredContent", "structured_content"):
            if isinstance(whole.get(key), dict):
                whole = whole[key]
        return [(1, whole)]
    records: list[tuple[int, Any]] = []
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if line.startswith("AUDIT "):
            line = line[len("AUDIT "):]  # the stdout form, when no log file is configured
        if not line:
            continue
        try:
            records.append((number, json.loads(line)))
        except ValueError:
            records.append((number, None))
    return records


def _describe(number: int, v: dict[str, Any]) -> Iterable[str]:
    mark = {True: "HOLDS", False: "FAILS", None: "UNSIGNED"}[v.get("holds")]
    what = v["decision"] + (f" ({v['layer']})" if v.get("layer") else "")
    yield f"[{number}] {mark}  {what}  tool={v.get('tool')}  at={v.get('at')}" + ("  (receipt)" if v.get("receipt") else "")
    if v.get("signer"):
        yield (f"     signed by {v['signer']}  for LEI={v.get('lei')} role={v.get('role')} "
               f"holder={v.get('holderAid')} agent={v.get('agentAid')}")
        aud = v.get("audience") or {}
        yield (f"     what: tools/call to {aud.get('url')} ({aud.get('aid')}), credential "
               f"{v.get('credentialSaid')}, arguments digest {v.get('argumentsDigest')}, "
               f"window {v.get('signedAt')} .. {v.get('validUntil')}")
        yield f"     signature: {'valid' if v.get('signatureVerifies') else 'INVALID'} - {v.get('signature')}"
    for problem in v.get("problems", []):
        yield f"     ! {problem}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("path", help="audit JSONL, a single record or receipt (JSON), or - for stdin")
    parser.add_argument("--line", type=int, help="verify only this line (1-based)")
    parser.add_argument("--json", action="store_true", help="one JSON verdict per line")
    parser.add_argument("--skew", type=int, default=DEFAULT_SKEW_SECONDS,
                        help="seconds a decision may lie outside the signed window (default 60)")
    args = parser.parse_args(argv)
    try:
        records = read_records(args.path)
    except OSError as exc:
        print(f"verify-audit: cannot read {args.path}: {exc}", file=sys.stderr)
        return 2
    if args.line is not None:
        records = [(n, r) for n, r in records if n == args.line]
        if not records:
            print(f"verify-audit: no record at line {args.line}", file=sys.stderr)
            return 2
    failed = 0
    counts = {True: 0, False: 0, None: 0}
    for number, record in records:
        verdict = verify_record(record, skew_seconds=args.skew)
        counts[verdict.get("holds")] += 1
        failed += verdict.get("holds") is False
        if args.json:
            print(json.dumps({"line": number, **verdict}, ensure_ascii=False))
        else:
            for text in _describe(number, verdict):
                print(text)
    if not args.json:
        print(f"{len(records)} records: {counts[True]} hold, {counts[False]} fail, "
              f"{counts[None]} carry no signature")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
