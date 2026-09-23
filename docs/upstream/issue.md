# Draft issue for GLEIF-IT/vlei-verifier

**Not submitted.** This is a draft for review before filing.

---

## Title

Revocation check crashes the service when a stored credential state has no AID

## Summary

`process_revocations_from_event_log` writes a database key of `None`, which raises a `TypeError`
inside keripy's `koming`. The exception is not caught, so the whole verifier process exits. When the
container is restarted, its database is empty, and a credential presented moments earlier is answered
with `unknown AID`.

## Environment

| | |
|---|---|
| Image | `gleif/vlei-verifier:1.0.0` (Docker Hub, pushed 2026-06-29) |
| Also affected | `gleif/vlei-verifier:0.1.5` (pushed 2026-08-20) — same code at `utils.py:133-143` |
| keripy | as bundled in the image (`/keripy/venv`, Python 3.12) |
| Host | Windows 11, Docker Desktop 28.0.4 |
| Mode | `VERIFIER_MODE=test`, `VERIFY_ROOT_OF_TRUST=True`, `revocationCheck: true` in the config file |
| Witnesses | `weboftrust/keri:1.2.14`, `kli witness demo` |

`revocationCheck` is enabled through the config file (`scripts/keri/cf/verifier-config-public.json`),
since there is no environment variable for it. With it disabled — the shipped default — the crash
does not occur, because the observer never runs.

## Steps to reproduce

Self-contained; approximately five minutes.

```bash
# 1. Witnesses, vLEI schemas, verifier.
#    The verifier's config must set "revocationCheck": true, and the config file must be mounted
#    writable — keripy's Configer opens it for writing even when it only reads it.
docker compose up -d

# 2. A credential chain: self-configured root -> QVI (delegated) -> LE -> ECR.
#    Any chain the verifier accepts will do; ours is issued with kli.
bash bootstrap-credentials.sh

# 3. Install the root of trust.
curl -X POST "http://localhost:7676/root_of_trust/$ROOT_AID" \
     -H 'Content-Type: application/json' \
     -d "{\"vlei\": \"$(cat root.kel)\", \"oobi\": \"$ROOT_OOBI\"}"
# -> 202

# 4. Introduce the holder and present, with Signify-signed headers, naming a witness so the
#    observer has a log to poll.
curl -X POST http://localhost:7676/oobi -H 'Content-Type: application/json' \
     -d "{\"oobi\": \"$HOLDER_OOBI\"}"
# -> 202
#    PUT /presentations/$ECR_SAID?witness_url=http://witness-demo:5642
# -> 202

# 5. Revoke the credential in the issuer's TEL.
kli vc revoke --name le --alias le --registry-name leRegistry --said "$ECR_SAID" --send "$ECR_AID"

# 6. Wait for the revocation observer's next poll (60s by default).
docker logs -f vlei-verifier
```

## Actual behaviour

The service exits:

```
  File "/usr/local/var/vlei-verifier/src/verifier/core/utils.py", line 143, in
      process_revocations_from_event_log
    vdb.iss.pin(keys=(aid,), val=rev_state)
  ...
  File "/keripy/venv/lib/python3.12/site-packages/keri/db/koming.py", line 110, in _tokey
    return (self.sep.join(key.decode() if hasattr(key, "decode") else key
TypeError: sequence item 0: expected str instance, NoneType found
```

The relevant code, unchanged in both 1.0.0 and 0.1.5
(`src/verifier/core/utils.py`, lines 133–143):

```python
for event in events:
    event_json = event.get("json", {})
    if event_json.get("t") == "rev" and event_json.get("i") == said:
        cur_state: CredProcessState = vdb.iss.get(keys=(said,))
        aid = cur_state.aid                      # may be None
        if aid:
            cur_state = vdb.iss.get(keys=(aid,))
        rev_state = CredProcessState(aid=aid, ...)
        vdb.iss.pin(keys=(aid,), val=rev_state)  # <-- None key
```

`aid` is read from the state stored under the credential's SAID. States created on the
`CRED_CRYPT_INVALID` path (`verifying.py`) are constructed without an `aid`, so that field is
legitimately `None`, and the guard two lines above already anticipates it — but the `pin` below does
not.

Two consequences beyond the crash itself:

1. **The HTTP service goes down with the observer.** Every client then reports a connection error
   rather than anything about credentials, so the cause is easy to misattribute to the network.
2. **The database is empty after the restart.** A credential presented seconds earlier is answered
   `unknown AID`, which looks like a presentation problem rather than a restart.

## Expected behaviour

A credential whose stored state has no AID is skipped, or recorded under its SAID alone, and the
revocation check continues. An unexpected condition in a background observer should not terminate
the HTTP service.

## Impact

Any integration that depends on revocation checking is unstable. Revocation is the property that
distinguishes a credential from a signed assertion, so an integration that cannot rely on it is
missing the reason to use vLEI at all.

## Our workaround

We read revocation directly from the issuer's transaction event log, via a witness
(`GET {witness}/query?typ=tel&vcid={said}`), and treat the verifier as one of three selectable
sources rather than the only one. That avoids the crash path entirely, at the cost of doing
ourselves what the verifier exists to do. We would rather use the service.

## Happy to help

We can supply the full reproduction repository, or test a patch against it.
