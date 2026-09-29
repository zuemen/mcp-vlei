Revocation observer crashes the verifier when a stored credential state has no AID (TypeError: None used as DB key)

### Summary

With `revocationCheck: true`, the revocation observer (`CredentialRevocationChecker`) can terminate the whole verifier process, and the HTTP API goes down with it.

When a presentation fails cryptographic verification, the verifier stores a `CRED_CRYPT_INVALID` state under the credential's SAID, and that state has `aid=None` ([verifying.py L466-L479](https://github.com/GLEIF-IT/vlei-verifier/blob/e9d175b988aef0c7ab7cc96f18247589c0959e01/src/verifier/core/verifying.py#L466-L479)). On the next observer tick, that `None` is used as a database key:

- in `process_revocations_from_event_log`, when the witness returns a `rev` event for the credential: `vdb.iss.pin(keys=(aid,), ...)` ([utils.py L241](https://github.com/GLEIF-IT/vlei-verifier/blob/e9d175b988aef0c7ab7cc96f18247589c0959e01/src/verifier/core/utils.py#L219-L245)).
- in `CredentialRevocationChecker._mark_as_revocation_check_failed`, on every other branch (no `witness_url`, witness unreachable, response not parseable, or an exception from the first site): `self.vdb.iss.get(keys=(aid,))` ([observing.py L55](https://github.com/GLEIF-IT/vlei-verifier/blob/e9d175b988aef0c7ab7cc96f18247589c0959e01/src/verifier/core/observing.py#L48-L59)).

keripy's `Komer._tokey` then raises `TypeError: sequence item 0: expected str instance, NoneType found`.

The first site sits inside `except Exception` ([observing.py L102-L105](https://github.com/GLEIF-IT/vlei-verifier/blob/e9d175b988aef0c7ab7cc96f18247589c0959e01/src/verifier/core/observing.py#L80-L110)). But the handler calls `_mark_as_revocation_check_failed`, which uses the same `None` key again. That second `TypeError` escapes `recur()`. hio's `Doist.do()` and `verifier.app.cli.verifier.main()` both re-raise it, so `verifier server start` exits.

Because `Habery`, `Reger` and `VerifierBaser` are all opened with `temp=True` ([start.py L203-L209](https://github.com/GLEIF-IT/vlei-verifier/blob/e9d175b988aef0c7ab7cc96f18247589c0959e01/src/verifier/app/cli/commands/server/start.py#L203-L209)), a restarted container comes back with empty databases. Roots of trust, resolved OOBIs and earlier presentations are all gone. A holder that was authorized a moment earlier then gets `401 {"msg": "unknown AID: ..."}` from `GET /authorizations/{aid}`.

### Affected versions

| Image | Built from (`.git/HEAD` in the image) | `None` key in `process_revocations_from_event_log` | `None` key in `_mark_as_revocation_check_failed` |
|---|---|---|---|
| `gleif/vlei-verifier:1.0.0`, pushed 2026-06-29, `sha256:a0cd3fb09a47...` | `e9d175b` (tag `1.0.0`) | `src/verifier/core/utils.py` L241 | `src/verifier/core/observing.py` L55 |
| `gleif/vlei-verifier:0.1.5`, pushed 2026-08-20, `sha256:9dbccc7d3601...` | `e16c64d` (tag `0.1.5`) | `utils.py` [L143](https://github.com/GLEIF-IT/vlei-verifier/blob/e16c64d444d7acf7fb6c15ac34f9990bb78e3eee/src/verifier/core/utils.py#L121-L147) | `observing.py` [L45](https://github.com/GLEIF-IT/vlei-verifier/blob/e16c64d444d7acf7fb6c15ac34f9990bb78e3eee/src/verifier/core/observing.py#L38-L49) |
| `main` @ `5850051` (2026-08-20) | n/a | identical to 1.0.0 | identical to 1.0.0 |

- Both images ship Python 3.12.3, with `keri==1.2.12` in `/keripy/venv` and `hio` 0.6.14.
- The body of `process_revocations_from_event_log` has not changed since tag `0.1.3`.
- Only deployments that turn the observer on are affected. Every config in the image leaves it off: it is either `false` or absent, and it defaults to `False`. The flag can only be set in the config file ([start.py L179](https://github.com/GLEIF-IT/vlei-verifier/blob/e9d175b988aef0c7ab7cc96f18247589c0959e01/src/verifier/app/cli/commands/server/start.py#L179), [L228-L233](https://github.com/GLEIF-IT/vlei-verifier/blob/e9d175b988aef0c7ab7cc96f18247589c0959e01/src/verifier/app/cli/commands/server/start.py#L228-L233)). There is no environment variable for it.

### Steps to reproduce

This needs only the published image: no witnesses, no credentials, no other files.

1. Write a config that turns the observer on and leaves everything else empty, so nothing is resolved at startup:

   ```bash
   cat > verifier-config-public.json <<'EOF'
   {
     "dt": "2022-01-20T12:57:59.823350+00:00",
     "iurls": [],
     "durls": [],
     "trustedLeis": [],
     "revocationCheck": true,
     "allowedSchemas": ["ECR_SCHEMA", "ECR_SCHEMA_PROD"]
   }
   EOF
   ```

2. Mount it over the shipped config. The mount must be writable: keripy's `Configer` opens the file with `r+b`, and if it cannot, it falls back to another path. The observer then never starts.

   ```bash
   docker run -d --name vv-repro -p 7676:7676 -e VERIFIER_MODE=test \
     -v "$PWD/verifier-config-public.json:/usr/local/var/vlei-verifier/scripts/keri/cf/verifier-config-public.json" \
     gleif/vlei-verifier:1.0.0
   ```

3. Present anything that does not verify, under any SAID. An empty body is enough:

   ```bash
   curl -s -w '\n%{http_code}\n' -X PUT \
     -H 'Content-Type: application/json+cesr' --data-binary '' \
     http://localhost:7676/presentations/EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
   # {"msg": "credential EAAA... from body of request did not cryptographically verify"}
   # 400
   ```

4. Wait for the observer. It is constructed without an `interval`, so it polls every 5 s:

   ```bash
   sleep 10
   docker inspect -f '{{.State.Status}} (exit {{.State.ExitCode}})' vv-repro
   docker logs vv-repro 2>&1 | tail -n 40
   ```

### Actual behaviour

The container exits. Reproduced live on 2026-09-24 by following the steps above verbatim against both published images (Docker Engine 28.0.4). The `PUT` returned `400`, and on the observer's next tick the "No witness URL provided" branch went straight into `_mark_as_revocation_check_failed`; a single, uncaught `TypeError` escaped `recur()` and the process exited with code 1.

On 1.0.0 (`sha256:a0cd3fb09a47…`), the tail of `docker logs` is:

```
2026-09-23 21:26:19,857 INFO verifier.core.observing: No witness URL provided for credential EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Traceback (most recent call last):
  File "/keripy/venv/bin/verifier", line 8, in <module>
    sys.exit(main())
  File "/usr/local/var/vlei-verifier/src/verifier/app/cli/verifier.py", line 45, in main
    raise ex
  File "/usr/local/var/vlei-verifier/src/verifier/app/cli/verifier.py", line 40, in main
    directing.runController(doers=doers, expire=0.0)
  File "/keripy/venv/lib/python3.12/site-packages/keri/app/directing.py", line 678, in runController
    doist.do(doers=doers)
  File "/keripy/venv/lib/python3.12/site-packages/hio/base/doing.py", line 156, in do
    self.recur()  # increments .tyme runs recur context
  File "/keripy/venv/lib/python3.12/site-packages/hio/base/doing.py", line 275, in recur
    tock = dog.send(self.tyme)  # yielded tock == 0.0 means re-run asap
  File "/keripy/venv/lib/python3.12/site-packages/hio/base/doing.py", line 568, in do
    self.done = self.recur(tyme=tyme)
  File "/usr/local/var/vlei-verifier/src/verifier/core/observing.py", line 44, in recur
    self._check_revocations()
  File "/usr/local/var/vlei-verifier/src/verifier/core/observing.py", line 110, in _check_revocations
    self._mark_as_revocation_check_failed(state.said, reason)
  File "/usr/local/var/vlei-verifier/src/verifier/core/observing.py", line 55, in _mark_as_revocation_check_failed
    if self.vdb.iss.get(keys=(aid,)):
  File "/keripy/venv/lib/python3.12/site-packages/keri/db/koming.py", line 329, in get
    key=self._tokey(keys))))
  File "/keripy/venv/lib/python3.12/site-packages/keri/db/koming.py", line 110, in _tokey
    return (self.sep.join(key.decode() if hasattr(key, "decode") else key
TypeError: sequence item 0: expected str instance, NoneType found
```

0.1.5 (`sha256:9dbccc7d3601…`) crashes identically; only the `observing.py` line numbers differ (`recur` at 34, `_check_revocations` at 88, `_mark_as_revocation_check_failed` at 45):

```
No witness URL provided for credential EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Traceback (most recent call last):
  File "/keripy/venv/bin/verifier", line 8, in <module>
    sys.exit(main())
  File "/usr/local/var/vlei-verifier/src/verifier/app/cli/verifier.py", line 45, in main
    raise ex
  File "/usr/local/var/vlei-verifier/src/verifier/app/cli/verifier.py", line 40, in main
    directing.runController(doers=doers, expire=0.0)
  File "/keripy/venv/lib/python3.12/site-packages/keri/app/directing.py", line 678, in runController
    doist.do(doers=doers)
  File "/keripy/venv/lib/python3.12/site-packages/hio/base/doing.py", line 156, in do
    self.recur()  # increments .tyme runs recur context
  File "/keripy/venv/lib/python3.12/site-packages/hio/base/doing.py", line 275, in recur
    tock = dog.send(self.tyme)  # yielded tock == 0.0 means re-run asap
  File "/keripy/venv/lib/python3.12/site-packages/hio/base/doing.py", line 568, in do
    self.done = self.recur(tyme=tyme)
  File "/usr/local/var/vlei-verifier/src/verifier/core/observing.py", line 34, in recur
    self._check_revocations()
  File "/usr/local/var/vlei-verifier/src/verifier/core/observing.py", line 88, in _check_revocations
    self._mark_as_revocation_check_failed(state.said, reason)
  File "/usr/local/var/vlei-verifier/src/verifier/core/observing.py", line 45, in _mark_as_revocation_check_failed
    if self.vdb.iss.get(keys=(aid,)):
  File "/keripy/venv/lib/python3.12/site-packages/keri/db/koming.py", line 329, in get
    key=self._tokey(keys))))
  File "/keripy/venv/lib/python3.12/site-packages/keri/db/koming.py", line 110, in _tokey
    return (self.sep.join(key.decode() if hasattr(key, "decode") else key
TypeError: sequence item 0: expected str instance, NoneType found
```

(The Python 3.12 `^^^^` caret lines are omitted from both blocks for brevity; they are the only difference from the raw logs.)

Adding `?witness_url=http://127.0.0.1:9` to the `PUT` (an address with nothing listening) goes through the `ConnectionError` branch (observing.py:101) instead and ends in the same place.

**The revocation path**, which is where we first ran into this: the credential is presented with `?witness_url=<witness>`, and its TEL on that witness holds a `rev` event. The observer then fails twice:

1. `process_revocations_from_event_log` raises at utils.py:241 (via `Komer.pin`, koming.py:308). The `except Exception` at observing.py:102 catches it and logs it as `Error checking witness for credential <SAID>: unexpected error`.
2. The handler's call at observing.py:105 hits observing.py:55 and raises again. This second error is uncaught ("During handling of the above exception, another exception occurred"), and the process exits.

In 0.1.5 the path is the same; the frames are utils.py:143 and observing.py:70, 80, 83, 45.

A successful presentation stores the holder's AID under the SAID. So the plain happy path (present a valid credential, then revoke it) takes the non-`None` branch and does not crash. The crash needs the state stored under that SAID to be the AID-less `CRED_CRYPT_INVALID` one. `verifying.py` writes that state only when nothing is stored for the SAID yet, and a later successful presentation normally replaces it.

In our environment, clients saw only connection errors while the verifier was down, so at first the cause looked like a network problem. After an automatic restart, the verifier answered `unknown AID` for a holder it had authorized seconds earlier.

Our environment for the revocation path:

| | |
|---|---|
| Verifier | `gleif/vlei-verifier:1.0.0`, `VERIFIER_MODE=test`, `VERIFY_ROOT_OF_TRUST=True`, `revocationCheck: true` |
| Witnesses | `weboftrust/keri:1.2.14`, `kli witness demo` |
| Schemas | `gleif/vlei:0.2.0` (`vLEI-server`) |
| Credentials | Self-configured root (installed with `POST /root_of_trust/{aid}`) -> QVI -> LE -> ECR, issued and revoked with `kli` 1.2.14 |
| Host | Windows 11, Docker Desktop 4.40.0 (Engine 28.0.4, Compose v2.34.0) |

### Expected behaviour

- A state with no AID is skipped, or marked failed under its SAID only.
- The observer logs the problem and keeps running.
- The HTTP API stays up.

In general, one bad record in a background poller should not be able to stop the service.

### Suggested fix

These three changes are independent of each other. We are happy to open a PR with a regression test; `tests/` has no coverage for `observing.py` today.

1. **Do not observe credentials that never verified.** In `_check_revocations`, skip `CRED_CRYPT_INVALID` the same way `Authorizer.processPresentations` already does through `_SKIP_ISS_STATES`. A credential that never verified has no account to revoke.
2. **Guard the AID-keyed operations** in both `process_revocations_from_event_log` and `_mark_as_revocation_check_failed`. Only call `iss.get/pin(keys=(aid,))`, `accts.rem` and `add_state_to_state_history(vdb, aid, ...)` when `aid` is set, and always write the SAID-keyed state. It may also be worth handling `cur_state is None`, in case the SAID-keyed record has already been removed.
3. **Contain the observer.** Catch exceptions per credential inside `_check_revocations`, or around `self._check_revocations()` in `recur()`, and log them. Then an unexpected condition costs one poll instead of the whole process.

Separately: is the `temp=True` for `Habery` / `Reger` / `VerifierBaser` intentional? With it, any crash also discards the roots of trust and every established presentation.

### Our workaround

We keep the verifier as one of several revocation sources, and read the issuer's TEL directly from a witness (`GET {witness}/query?typ=tel&vcid={said}`). We would rather rely on the verifier's own observer.
