"""Operate the interactive page (`/app`) in a real browser, as a visitor would, and check it.

Every scenario is clicked in 中文 and in English; the outcome and the refusing check on the page are
compared with what the scenario list says; a call is built by hand, including an invalid date;
the language is switched with a result on screen. With --revoke, the revocation scenario is run for
real and the credential re-issued afterwards (about 1.5 minutes).

    bash scripts/reset-demo.sh --keep-credentials     # READY first
    python scripts/try-app.py --out /tmp/app-shots [--revoke]

Exits 1 if anything on the page is not what the scenario list promises.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from playwright.sync_api import Page, sync_playwright

URL = "http://localhost:8800/app"
CHECKS = ["credential_present", "freshness", "digest", "signature", "delegation", "chain",
          "revocation", "authority"]


def outcome_of(page: Page) -> tuple[str, str | None]:
    page.wait_for_function(
        "() => !['sending', 'empty'].includes(document.querySelector('#outcome').dataset.status)",
        timeout=120_000)
    page.wait_for_function("() => document.body.classList.contains('revealed')", timeout=10_000)
    status = page.get_attribute("#outcome", "data-status")
    failed = page.query_selector('#checks li[data-state="fail"]')
    return status, failed.get_attribute("data-check") if failed else None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--revoke", action="store_true")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    problems: list[str] = []

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1440, "height": 900})
        scenarios = page.request.get("http://localhost:8800/api/scenarios").json()["scenarios"]
        for lang in ("zh", "en"):
            page.goto(f"{URL}?lang={lang}&tab=scenarios")
            page.wait_for_selector(".scenario")
            for s in scenarios:
                if s["id"] == "after-revocation":
                    continue
                page.click(f'.scenario[data-id="{s["id"]}"]')
                status, failed = outcome_of(page)
                want = s["expect"]
                ok = status == want["status"] and failed == want.get("check")
                print(f"{lang} {s['id']:18} {status:13} {failed or '':20} {'ok' if ok else 'MISMATCH'}")
                if not ok:
                    problems.append(f"{lang} {s['id']}: got {status}/{failed}, want {want}")
                page.screenshot(path=str(args.out / f"{lang}-{s['id']}.png"), full_page=True)

        # A call built by hand, then an invalid date, then the language switched on a result.
        page.goto(f"{URL}?lang=zh&tab=build")
        page.select_option("#f-tool", "enroll_employee")
        page.fill("#f-person_ref", "EMP-0301")
        page.select_option("#f-variant", "tamper")
        page.click("#build-send")
        status, failed = outcome_of(page)
        if (status, failed) != ("refused", "digest"):
            problems.append(f"built tamper: got {status}/{failed}")
        page.click('#lang button[data-lang="en"]')
        if "REFUSED" not in page.inner_text("#outcome"):
            problems.append("switching language did not re-render the result")
        page.screenshot(path=str(args.out / "build-tamper-en.png"), full_page=True)
        # A browser clears an impossible date like 2026-02-30 to empty; either way the page refuses it
        # before anything is signed, and says so under the field, in the page's language.
        page.evaluate("document.querySelector('#f-start_date').value = ''")
        page.click("#build-send")
        page.wait_for_selector(".field-error")
        if page.get_attribute("#f-start_date", "aria-invalid") != "true":
            problems.append("an invalid date was not marked on its field")
        page.fill("#f-person_ref", "Alice")
        page.click("#build-send")
        page.wait_for_selector("#f-person_ref[aria-invalid='true']")
        page.screenshot(path=str(args.out / "build-invalid-date.png"), full_page=True)

        if args.revoke:
            page.goto(f"{URL}?lang=zh&tab=scenarios")
            page.wait_for_selector("#revoke")
            page.click("#revoke")
            page.wait_for_selector("#reissue:not([disabled])", timeout=120_000)
            page.click('.scenario[data-id="after-revocation"]')
            status, failed = outcome_of(page)
            if (status, failed) != ("refused", "revocation"):
                problems.append(f"after revocation: got {status}/{failed}")
            page.screenshot(path=str(args.out / "zh-after-revocation.png"), full_page=True)
            page.click("#reissue")
            page.wait_for_selector("#revoke:not([disabled])", timeout=240_000)
            page.click('.scenario[data-id="enroll-today"]')
            status, _ = outcome_of(page)
            if status != "allowed":
                problems.append(f"after re-issue: got {status}")
        browser.close()

    for line in problems:
        print("PROBLEM:", line)
    print("OK" if not problems else f"{len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
