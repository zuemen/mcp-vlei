"""A record of what was checked, in order, and what each check cost.

A refusal that says only `revoked` is correct and unconvincing. Someone watching a demo — or
reading an audit log six months later — needs to see which checks ran, which one stopped the call,
and that the ones before it passed. That is the difference between "the system said no" and "the
system established that the credential had been withdrawn, after establishing five other things".

The checks are fixed and ordered. Everything local comes before the one remote check, so a
verification service that is slow or down degrades exactly one line of this report rather than all
of it:

1. ``credential_present`` — something was presented at all
2. ``freshness`` — the signature is recent and not a replay
3. ``digest`` — the arguments match what was signed
4. ``signature`` — the signature verifies under the signing key
5. ``delegation`` — the acting AID is the holder's, or delegated by them
6. ``chain`` — every SAID recomputes, the links are continuous, the root is accepted
7. ``revocation`` — the issuer's log does not withdraw it
8. ``authority`` — the role and scope cover what the tool requires

**What a report may contain.** The LEI, the role, the credential SAID, the holder AID and the
delegated AID — enough to audit, and no more. Never the credential itself: an ECR names a natural
person, and `spec/SPEC.md` §Security Considerations is explicit that presenting one discloses them.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any

__all__ = ["CheckName", "CheckResult", "VerificationReport", "CHECK_ORDER"]

CheckName = str

#: Fixed, and in this order. A report that skipped a check shows it as skipped rather than absent,
#: so a reader can tell "did not run" from "did not apply".
CHECK_ORDER: tuple[CheckName, ...] = (
    "credential_present",
    "freshness",
    "digest",
    "signature",
    "delegation",
    "chain",
    "revocation",
    "authority",
)

_LABEL = {
    "credential_present": "credential presented",
    "freshness": "signature is fresh",
    "digest": "arguments match the signed digest",
    "signature": "signature verifies",
    "delegation": "acting identifier is authorized",
    "chain": "credential chain reaches an accepted root",
    "revocation": "credential is not revoked",
    "authority": "role and scope cover this tool",
}

_MARKS_UNICODE = ("✓", "✗", "·")
_MARKS_ASCII = ("+", "x", "-")


def _marks() -> tuple[str, str, str]:
    """Check marks the terminal can actually print.

    A Windows console on a CJK code page cannot encode `✓`, and printing the report is how the
    demo is shown — a `UnicodeEncodeError` mid-recording is a worse outcome than a plainer symbol.
    """
    import sys

    encoding = getattr(sys.stdout, "encoding", None) or "ascii"
    try:
        "".join(_MARKS_UNICODE).encode(encoding)
    except (LookupError, UnicodeEncodeError):
        return _MARKS_ASCII
    return _MARKS_UNICODE


@dataclass
class CheckResult:
    name: CheckName
    passed: bool | None = None  # None: not reached
    duration_ms: float = 0.0
    layer: str | None = None
    detail: str = ""

    @property
    def reached(self) -> bool:
        return self.passed is not None


@dataclass
class VerificationReport:
    """Accumulates check results, stopping at the first failure but keeping what came before."""

    tool: str = ""
    checks: dict[CheckName, CheckResult] = field(
        default_factory=lambda: {name: CheckResult(name) for name in CHECK_ORDER}
    )
    #: Established facts, deliberately narrow. See the module docstring.
    lei: str | None = None
    role: str | None = None
    credential_said: str | None = None
    holder_aid: str | None = None
    delegate_aid: str | None = None
    #: What was checked but not established — an unreachable log, an unverified signature.
    caveats: list[str] = field(default_factory=list)

    _started: float = field(default=0.0, repr=False)

    # -------------------------------------------------------------------------------------- #

    def start(self, name: CheckName) -> None:
        self._started = time.perf_counter()
        self.checks[name].name = name

    def passed(self, name: CheckName, detail: str = "") -> None:
        check = self.checks[name]
        check.passed = True
        check.detail = detail
        check.duration_ms = (time.perf_counter() - self._started) * 1000

    def failed(self, name: CheckName, layer: str, detail: str) -> None:
        check = self.checks[name]
        check.passed = False
        check.layer = layer
        check.detail = detail
        check.duration_ms = (time.perf_counter() - self._started) * 1000

    def skipped(self, name: CheckName, detail: str) -> None:
        """A check that did not apply — a public tool, or a source the deployment turned off.

        Distinct from not reached: "we chose not to" and "we never got there" are different
        statements, and a reader deserves to know which one they are looking at.
        """
        check = self.checks[name]
        check.passed = True
        check.detail = detail
        check.duration_ms = 0.0
        self.caveats.append(f"{_LABEL[name]}: {detail}")

    # -------------------------------------------------------------------------------------- #

    @property
    def failure(self) -> CheckResult | None:
        for name in CHECK_ORDER:
            check = self.checks[name]
            if check.passed is False:
                return check
        return None

    @property
    def allowed(self) -> bool:
        return self.failure is None and any(c.passed for c in self.checks.values())

    @property
    def total_ms(self) -> float:
        return sum(c.duration_ms for c in self.checks.values())

    def as_dict(self) -> dict[str, Any]:
        """For the dashboard and for logs. JSON-serializable, no credential content."""
        return {
            "tool": self.tool,
            "allowed": self.allowed,
            "layer": self.failure.layer if self.failure else None,
            "totalMs": round(self.total_ms, 1),
            "identity": {
                "lei": self.lei,
                "role": self.role,
                "credentialSaid": self.credential_said,
                "holderAid": self.holder_aid,
                "delegateAid": self.delegate_aid,
            },
            "caveats": list(self.caveats),
            "checks": [
                {
                    "name": name,
                    "label": _LABEL[name],
                    "passed": self.checks[name].passed,
                    "durationMs": round(self.checks[name].duration_ms, 1),
                    "layer": self.checks[name].layer,
                    "detail": self.checks[name].detail,
                }
                for name in CHECK_ORDER
            ],
        }

    def as_text(self, *, color: bool | None = None) -> str:
        """For a terminal, and for a screen recording.

        One line per check, the failing layer named on its own line, a verdict at the end. Colour
        is carried alongside a symbol, never instead of one — a projector, a colour-blind viewer or
        a piped log all need the line to read correctly without it.
        """
        if color is None:
            color = not os.environ.get("NO_COLOR") and os.environ.get("TERM") != "dumb"

        green, red, dim, reset = ("\033[32m", "\033[31m", "\033[90m", "\033[0m") if color else ("",) * 4
        ok_mark, fail_mark, skip_mark = _marks()

        lines = [f"  verifying {self.tool}" if self.tool else "  verifying"]
        for name in CHECK_ORDER:
            check = self.checks[name]
            if not check.reached:
                lines.append(f"    {dim}{skip_mark} {_LABEL[name]:<44} not reached{reset}")
                continue
            if check.passed:
                timing = f"{check.duration_ms:6.1f} ms" if check.duration_ms else "        —"
                lines.append(f"    {green}{ok_mark}{reset} {_LABEL[name]:<44} {dim}{timing}{reset}")
            else:
                lines.append(f"    {red}{fail_mark} {_LABEL[name]:<44} {check.layer}{reset}")
                lines.append(f"      {red}{check.detail}{reset}")

        for caveat in self.caveats:
            lines.append(f"    {dim}! {caveat}{reset}")

        if self.failure:
            lines.append(f"  {red}REFUSED: {self.failure.layer}{reset}")
        else:
            identity = f" {skip_mark} ".join(filter(None, [self.lei, self.role]))
            lines.append(f"  {green}ALLOWED{reset}{f'  {dim}{identity}{reset}' if identity else ''}")
        return "\n".join(lines)
