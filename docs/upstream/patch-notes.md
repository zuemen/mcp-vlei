# Notes towards a fix

For `GLEIF-IT/vlei-verifier`, accompanying [`issue.md`](issue.md). Not submitted; notes for whoever
picks this up, us or upstream.

## Where the `None` comes from

`process_revocations_from_event_log` (`src/verifier/core/utils.py`) reads the state stored under the
credential's SAID and takes its `aid`:

```python
cur_state: CredProcessState = vdb.iss.get(keys=(said,))
aid = cur_state.aid
```

`CredProcessState.aid` is `Optional[str]`, and states are legitimately created without one. In
`verifying.py`, the `CRED_CRYPT_INVALID` path constructs a state keyed by SAID only, because at that
point the presenter's AID has not been established — the credential failed before it could be. A
presentation that fails cryptographic verification therefore leaves exactly the state that later
crashes the observer.

The function already anticipates this two lines down:

```python
if aid:
    cur_state = vdb.iss.get(keys=(aid,))
```

so the guard exists; it just does not extend to the writes that follow.

## Three candidate fixes

**1. Skip, and say so.** The smallest change, and the one we would propose first.

```python
if aid is None:
    logger.warning(
        "credential %s has no AID in its stored state; skipping revocation update", said
    )
    continue
```

A state without an AID belongs to a credential that never verified, so there is no account to
revoke. Skipping loses nothing. The log line matters: silence here is what made the original
behaviour hard to attribute.

**2. Key by SAID alone.** Write the revoked state under the SAID and skip only the AID-keyed write:

```python
rev_state = CredProcessState(aid=aid, said=said, info="Credential was revoked",
                             state=AUTH_REVOKED, witness_url=cur_state.witness_url)
if aid:
    vdb.iss.pin(keys=(aid,), val=rev_state)
    vdb.accts.rem(keys=(aid,))
    add_state_to_state_history(vdb, aid, rev_state)
vdb.iss.pin(keys=(said,), val=rev_state)
```

Preserves the record that the credential was revoked, which may matter for
`/presentations/history`. Slightly larger, and worth checking that `add_state_to_state_history`
is not called with a `None` key anywhere else.

**3. Contain the observer.** Independent of either, and arguably the more important change:
`CredentialRevocationChecker.recur` should not be able to terminate the service.

```python
def recur(self, tyme):
    if tyme - self.lastCheck >= self.interval:
        try:
            self._check_revocations()
        except Exception:
            logger.exception("revocation check failed; will retry at the next interval")
        self.lastCheck = tyme
    return False
```

A background poller that takes the HTTP service down with it turns any bug in its path into an
outage, and presents it to clients as a connection error. Fixing only the `None` key leaves the next
unexpected condition with the same blast radius.

## To confirm before opening a PR

- **Is `CRED_CRYPT_INVALID` the only source of AID-less states?** Grep for `CredProcessState(`; if
  others exist, fix 1 may hide a different problem rather than handle a known one.
- **Does `/presentations/history/{aid}` rely on the AID-keyed write?** If it does, fix 2 is the
  right one and fix 1 would create a gap in the history.
- **Is there a test for the revocation observer?** We did not find one. A regression test that
  presents an invalid credential, then revokes a valid one, would have caught this — and is worth
  contributing whichever fix is taken.
- **Does keripy's `koming` accept a `None` key anywhere by design?** If the intent is that it should
  raise, that is right, and the fix belongs entirely on the verifier's side.
- **Behaviour on restart.** Separately from this bug: the database is in-container and does not
  survive a restart, so any crash loses established presentations. Whether that is intended is worth
  asking in the same issue.
