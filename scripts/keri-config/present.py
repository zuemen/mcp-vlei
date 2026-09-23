"""Present a credential to vlei-verifier with Signify-style signed HTTP headers.

vlei-verifier 1.0.0 will not accept a presentation on the strength of the CESR alone: the HTTP
request itself must be signed, with `SIGNATURE-INPUT`, `SIGNATURE`, `SIGNIFY-RESOURCE` and
`SIGNIFY-TIMESTAMP`. That is the right requirement — without it, anyone who obtained a copy of a
credential could present it as their own, and the verifier would have no way to tell. The signature
is what proves the presenter controls the AID the credential was issued to.

Those headers are normally produced by a Signify client talking to a KERIA agent. This project has
neither, so the signature is produced directly from the local keystore, against exactly the
serialization `verifier/core/utils.py` reconstructs.

Runs inside the keri-cli container, where the keystores live:

    python /keri-config/present.py <keystore> <alias> <said> <cesr-file> <verifier-url>

Prints the HTTP status code.
"""

import sys
import urllib.error
import urllib.request

from keri.app.cli.common import existing
from keri.end import ending
from keri.help import helping

#: Signed on every presentation. `@method` and `@path` bind the signature to this request rather
#: than any other; the timestamp bounds replay; the resource names the AID being claimed.
FIELDS = ["@method", "@path", "signify-resource", "signify-timestamp"]


def build_headers(hab, method: str, path: str) -> dict[str, str]:
    headers = {
        "Content-Type": "application/json+cesr",
        "SIGNIFY-RESOURCE": hab.pre,
        "SIGNIFY-TIMESTAMP": helping.nowIso8601(),
    }

    header, unsigned = ending.siginput(
        "signify", method=method, path=path, headers=headers, fields=FIELDS, hab=hab, alg="ed25519",
        keyid=hab.pre,
    )
    headers.update(header)

    signage = ending.Signage(
        markers=dict(signify=unsigned), indexed=False,
        signer=None, ordinal=None, digest=None, kind=None,
    )
    headers.update(ending.signature([signage]))
    return headers


def _send(hab, verifier: str, path: str, methods, body: bytes | None) -> int:
    for method in methods:
        request = urllib.request.Request(
            f"{verifier}{path}", data=body,
            headers=build_headers(hab, method, path), method=method,
        )
        try:
            with urllib.request.urlopen(request) as response:
                print(response.read().decode("utf-8", "replace")[:400], file=sys.stderr)
                return response.status
        except urllib.error.HTTPError as err:
            if err.code in (404, 405) and method != methods[-1]:
                continue
            print(err.read().decode("utf-8", "replace")[:400], file=sys.stderr)
            return err.code
    return 0


def open_hab(keystore: str, alias: str):
    hby = existing.setupHby(name=keystore, base="", bran=None)
    hab = hby.habByName(alias)
    if hab is None:
        raise SystemExit(f"no identifier aliased {alias!r} in keystore {keystore!r}")
    return hab


def present(keystore: str, alias: str, said: str, cesr_file: str, verifier: str) -> int:
    hab = open_hab(keystore, alias)
    body = open(cesr_file, "rb").read()
    # Released versions have accepted the presentation on either verb.
    return _send(hab, verifier, f"/presentations/{said}", ("PUT", "POST"), body)


def authorizations(keystore: str, alias: str, aid: str, verifier: str) -> int:
    """Read back what the verifier established. Signed for the same reason the presentation is."""
    hab = open_hab(keystore, alias)
    return _send(hab, verifier, f"/authorizations/{aid}", ("GET",), None)


if __name__ == "__main__":
    command = sys.argv[1]
    if command == "present":
        print(present(*sys.argv[2:7]))
    elif command == "authorizations":
        print(authorizations(*sys.argv[2:6]))
    else:
        raise SystemExit(f"unknown command {command!r}: expected 'present' or 'authorizations'")
