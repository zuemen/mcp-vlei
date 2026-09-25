"""Break each security check in turn and see whether any test notices.

A check here is an ``if`` whose body raises: the guard that turns a bad request, key log, chain or
status into a refusal. Each guard is mutated so that it never fires, is negated, and — for ``or``
and ``and`` conditions — loses one operand at a time. Every ``<``/``<=``/``>``/``>=`` in the
module is also moved across its boundary, because thresholds, receipt counts, quorums and windows
are where an off-by-one matters. The whole suite runs against each mutant. A mutant the suite still
passes is a check no test holds: it could be deleted tomorrow and CI would stay green.

What this measures is whether the tests notice a check being broken — not whether the check is
right. A survivor is one of three things: **equivalent** (the mutant behaves the same), **redundant**
(a later check refuses the same input), or **untested**. Only the last needs a test.

Runs on a copy of the package, so a demo running from this tree is not disturbed:

    python packages/mcp-vlei/tools/mutate_checks.py            # every module
    python packages/mcp-vlei/tools/mutate_checks.py kel.py     # one module

Writes a Markdown report (``--out``) and prints each result. Exit status is the number of survivors
and timeouts, capped at 100. Mutation IDs (``kel-12``) are stable only while the module is unchanged.
"""

from __future__ import annotations

import argparse
import ast
import copy
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
#: Modules whose refusals are security decisions. testing.py is a test helper; errors.py and
#: report.py only format what the others decided.
MODULES = ["signing.py", "kel.py", "chain.py", "verifier.py", "revocation.py", "attest.py",
           "extension.py", "client.py"]
#: A strict comparison and its non-strict twin, each way.
BOUNDARY = {ast.Lt: ast.LtE, ast.LtE: ast.Lt, ast.Gt: ast.GtE, ast.GtE: ast.Gt}


@dataclass
class Mutant:
    module: str
    line: int
    guard: str
    raises: str
    operator: str
    source: str  # the mutated module


def _raises(body: list[ast.stmt]) -> str | None:
    """The exception a guard body raises directly, if it does."""
    for statement in body:
        if isinstance(statement, ast.Raise) and statement.exc is not None:
            exc = statement.exc
            target = exc.func if isinstance(exc, ast.Call) else exc
            return ast.unparse(target)
        if isinstance(statement, ast.Raise):
            return "re-raise"
    return None


def _guards(tree: ast.AST) -> list[ast.If]:
    return [node for node in ast.walk(tree) if isinstance(node, ast.If) and _raises(node.body)]


def _boundaries(tree: ast.AST) -> list[ast.Compare]:
    return [node for node in ast.walk(tree) if isinstance(node, ast.Compare)
            and any(type(op) in BOUNDARY for op in node.ops)]


def mutants(module: str, text: str) -> list[Mutant]:
    tree = ast.parse(text)
    out: list[Mutant] = []

    for index, guard in enumerate(_guards(tree)):
        raised = _raises(guard.body) or "?"
        label = ast.unparse(guard.test)
        test = guard.test
        variants: list[tuple[str, ast.expr]] = [
            ("guard never fires", ast.Constant(False)),
            ("guard negated", ast.UnaryOp(op=ast.Not(), operand=copy.deepcopy(test))),
        ]
        if isinstance(test, ast.BoolOp) and len(test.values) > 1:
            # Dropping an operand of `or` weakens the guard; dropping one of `and` widens it.
            for dropped in range(len(test.values)):
                kept = [v for i, v in enumerate(test.values) if i != dropped]
                replacement = kept[0] if len(kept) == 1 else ast.BoolOp(op=test.op, values=kept)
                variants.append((f"drop `{ast.unparse(test.values[dropped])[:60]}`", replacement))
        for operator, replacement in variants:
            mutated = copy.deepcopy(tree)
            _guards(mutated)[index].test = replacement
            ast.fix_missing_locations(mutated)
            out.append(Mutant(module, guard.lineno, label, raised, operator, ast.unparse(mutated)))

    for index, compare in enumerate(_boundaries(tree)):
        for position, op in enumerate(compare.ops):
            if type(op) not in BOUNDARY:
                continue
            mutated = copy.deepcopy(tree)
            _boundaries(mutated)[index].ops[position] = BOUNDARY[type(op)]()
            ast.fix_missing_locations(mutated)
            out.append(Mutant(module, compare.lineno, ast.unparse(compare), "-",
                              f"{type(op).__name__} -> {BOUNDARY[type(op)].__name__}",
                              ast.unparse(mutated)))
    return out


def run_suite(copy_root: Path, timeout: float) -> tuple[str, str]:
    """("killed" | "survived" | "timeout", the first failing test or the reason).

    A timeout is not a kill: a mutant that makes the suite hang has not been caught by a test."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "-x", "-q", "-p", "no:cacheprovider", "tests"],
            cwd=copy_root, capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return "timeout", f"no result in {timeout:.0f} s"
    if result.returncode == 0:
        return "survived", ""
    for line in result.stdout.splitlines():
        if line.startswith(("FAILED ", "ERROR ")):
            return "killed", line.split(" - ")[0].split(" ", 1)[1]
    return "killed", f"exit {result.returncode}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("modules", nargs="*", default=MODULES)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--timeout", type=float, default=120)
    args = parser.parse_args()

    work = Path(tempfile.mkdtemp(prefix="mutate-"))
    root = work / "pkg"
    shutil.copytree(PACKAGE, root, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache",
                                                                   "tools", "*.egg-info"))
    started = time.time()
    verdict, reason = run_suite(root, args.timeout)
    if verdict != "survived":
        print(f"the unmutated suite does not pass ({verdict}: {reason}); fix that first")
        return 100
    baseline = time.time() - started

    rows: list[str] = []
    counts = {"killed": 0, "survived": 0, "timeout": 0}
    started = time.time()
    for module in args.modules:
        path = root / "src" / "mcp_vlei" / module
        original = path.read_text(encoding="utf-8")
        for number, mutant in enumerate(mutants(module, original), start=1):
            path.write_text(mutant.source, encoding="utf-8")
            verdict, by = run_suite(root, args.timeout)
            path.write_text(original, encoding="utf-8")
            counts[verdict] += 1
            shown = {"killed": f"killed by `{by}`", "survived": "**SURVIVED**",
                     "timeout": f"**TIMEOUT** ({by})"}[verdict]
            mid = f"{module.removesuffix('.py')}-{number}"
            rows.append(f"| {mid} | {module}:{mutant.line} | `{mutant.guard[:70]}` | "
                        f"{mutant.raises} | {mutant.operator} | {shown} |")
            print(f"  {mid:<14} {module}:{mutant.line:<4} {mutant.operator[:40]:<40} {verdict}",
                  flush=True)

    total = sum(counts.values())
    out = args.out or (work / "mutation-report.md")
    out.write_text(
        "# Security-check mutants\n\n"
        f"Python {sys.version.split()[0]} · baseline suite {baseline:.1f} s · "
        f"{time.time() - started:.0f} s in all · {total} mutants: "
        f"{counts['killed']} killed, {counts['survived']} survived, {counts['timeout']} timed out."
        "\n\n| ID | Where | Guard or comparison | Raises | Mutation | Result |\n"
        "|---|---|---|---|---|---|\n" + "\n".join(rows) + "\n", encoding="utf-8")
    print(f"\n{total} mutants: {counts} -> {out}")
    if args.out:
        shutil.rmtree(work, ignore_errors=True)
    return min(counts["survived"] + counts["timeout"], 100)


if __name__ == "__main__":
    sys.exit(main())
