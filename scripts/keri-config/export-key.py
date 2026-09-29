"""Export an identifier's current private seed, for the reference agent to sign with.

    python /keri-config/export-key.py <keystore> <alias> <out-file>

**This is a demo affordance, and an uncomfortable one.** A private key written to a file is a
private key that can be copied. It exists because the reference agent has to be runnable and
inspectable by someone reading this repository, and because `mcp_vlei.Signer` deliberately knows
nothing about keripy's keystore.

In production, do not do this. Use Signify: the key stays on the holder's device and the agent
sends a payload to be signed and receives a signature back, never the key. `signing.Signer` is the
single class that would change.

The narrower point stands either way: the key exported here belongs to the agent's **delegated**
AID, not to the person. If it leaks, the delegation is revoked and the person's ECR credential is
untouched — which is the practical argument for delegation in `spec/SPEC.md`.
"""

import sys
from pathlib import Path

from keri.app.cli.common import existing


def export(keystore: str, alias: str, out: str) -> str:
    hby = existing.setupHby(name=keystore, base="", bran=None)
    hab = hby.habByName(alias)
    if hab is None:
        raise SystemExit(f"no identifier aliased {alias!r} in keystore {keystore!r}")

    # The current signing key for this AID, as keripy's manager holds it.
    signers = hby.mgr.getSigners(pres=[hab.kever.verfers[0].qb64])
    if not signers:
        raise SystemExit(f"no private key held for {alias!r} — is this keystore the controller?")

    seed = signers[0].raw
    if len(seed) != 32:
        raise SystemExit(f"expected a 32-byte Ed25519 seed, got {len(seed)}")

    path = Path(out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(seed)
    return hab.pre


if __name__ == "__main__":
    print(export(*sys.argv[1:4]))
