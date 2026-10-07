"""Replay stores: each signature's nonce, claimed once (v0.3).

A v0.3 signature carries a random nonce. A verifier **claims** ``(signer AID, nonce)`` after the
signature verifies; a second claim of the same pair is a replay, refused as ``stale_signature``.

Two properties make a claim worth something:

* **Atomic.** "Is it there? Then add it" must be one operation, or two copies of one call that
  arrive together both pass. A lock around a dict in one process; ``INSERT OR IGNORE`` inside
  ``BEGIN IMMEDIATE`` for several processes sharing one SQLite file.
* **A memory that is honest about where it starts.** A store that loses its contents — a restart
  of an in-memory store — would accept a signature it had already accepted. Each store states
  ``memory_since``, the earliest instant from which it remembers every claim. A signature accepted
  before then had ``ts <= accepted_at + skew < memory_since + skew``, so a verifier that refuses
  ``ts < memory_since + skew`` never accepts one twice, whatever was lost
  (:func:`mcp_vlei.signing.verify_request`).

Several gateway instances that share an audience must share one store; each with its own memory
would accept a replay at its sibling. Redis ``SET key 1 NX PXAT <expires>`` or a unique key in a
shared database does it; this package ships the two stores a single host needs.
"""

from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Protocol, runtime_checkable

__all__ = ["ReplayStore", "MemoryReplayStore", "SqliteReplayStore"]

Clock = Callable[[], datetime]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _require_utc(what: str, moment: object) -> datetime:
    """``moment`` if it is a timezone-aware UTC datetime; ``ValueError`` otherwise.

    A naive datetime compared with an aware expiry raises ``TypeError`` at the first claim — a
    crash with no layer, in the middle of a call — and ``datetime.timestamp()`` reads it as local
    time. Checked when a store is built, so a wrong clock never gets as far as a request.
    """
    if not (isinstance(moment, datetime) and moment.tzinfo is not None
            and moment.utcoffset() == timedelta(0)):
        raise ValueError(f"{what} must be a timezone-aware UTC datetime, not {moment!r}")
    return moment


def _utc_clock(clock: Clock | None) -> Clock:
    """The store's clock, called once to check it answers in UTC (see :func:`_require_utc`)."""
    clock = clock or _utcnow
    _require_utc("the replay store's clock", clock())
    return clock


@runtime_checkable
class ReplayStore(Protocol):
    @property
    def memory_since(self) -> datetime:
        """The earliest instant from which this store remembers every claim (UTC)."""

    def claim(self, aid: str, nonce: str, expires_at: datetime) -> bool:
        """Record ``(aid, nonce)`` until ``expires_at``. True if it was new; False for a repeat."""


class MemoryReplayStore:
    """One process's memory. Lost on restart — which ``memory_since`` says.

    ``memory_since`` defaults to the moment of construction, so for ``skew`` seconds after a start
    every signature is refused as made before the memory began. A caller that knows nothing could
    have been accepted earlier (a test, a demonstration verifier inside one process) may say so.
    ``clock`` and ``memory_since`` must be timezone-aware UTC; anything else is a ``ValueError``
    here, not a failure at the first claim.
    """

    #: How often expired claims are swept out. A sweep walks every entry, so it runs at most once
    #: per interval rather than on every claim; an expired entry waiting for it already counts as
    #: absent, so the interval bounds only memory, never a decision.
    SWEEP_INTERVAL = timedelta(seconds=5)

    def __init__(self, *, memory_since: datetime | None = None, clock: Clock | None = None) -> None:
        self._clock = _utc_clock(clock)
        self._memory_since = (
            _require_utc("memory_since", memory_since) if memory_since is not None else self._clock()
        )
        self._seen: dict[tuple[str, str], datetime] = {}
        self._next_sweep: datetime | None = None
        self._lock = threading.Lock()

    @property
    def memory_since(self) -> datetime:
        return self._memory_since

    def claim(self, aid: str, nonce: str, expires_at: datetime) -> bool:
        now = self._clock()
        with self._lock:
            if self._next_sweep is None or now >= self._next_sweep:
                for key in [k for k, until in self._seen.items() if until < now]:
                    del self._seen[key]
                self._next_sweep = now + self.SWEEP_INTERVAL
            until = self._seen.get((aid, nonce))
            if until is not None and until >= now:
                return False
            self._seen[(aid, nonce)] = expires_at
            return True


class SqliteReplayStore:
    """Claims in a SQLite file: they survive a restart, and processes on one host share them.

    ``memory_since`` is written when the file is created and read back afterwards, so a restart
    costs nothing; deleting the file starts a new memory, which is safe. Put the file on a local
    filesystem (a Docker named volume, not a bind mount from a desktop host): SQLite's locking is
    only as good as the filesystem's. ``clock`` must answer in timezone-aware UTC (``ValueError``).
    """

    def __init__(self, path: str | Path, *, clock: Clock | None = None) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._clock = _utc_clock(clock)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(
            str(self.path), timeout=10.0, isolation_level=None, check_same_thread=False
        )
        self._db.execute("PRAGMA journal_mode=WAL")
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                self._db.execute(
                    "CREATE TABLE IF NOT EXISTS seen (aid TEXT NOT NULL, nonce TEXT NOT NULL, "
                    "expires_at REAL NOT NULL, PRIMARY KEY (aid, nonce))"
                )
                self._db.execute("CREATE INDEX IF NOT EXISTS seen_expiry ON seen (expires_at)")
                self._db.execute(
                    "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
                )
                self._db.execute(
                    "INSERT OR IGNORE INTO meta (key, value) VALUES ('memory_since', ?)",
                    (self._clock().astimezone(timezone.utc).isoformat(),),
                )
                (since,) = self._db.execute(
                    "SELECT value FROM meta WHERE key = 'memory_since'"
                ).fetchone()
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
        self._memory_since = datetime.fromisoformat(since)

    @property
    def memory_since(self) -> datetime:
        return self._memory_since

    def claim(self, aid: str, nonce: str, expires_at: datetime) -> bool:
        now = self._clock().timestamp()
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                self._db.execute("DELETE FROM seen WHERE expires_at < ?", (now,))
                cursor = self._db.execute(
                    "INSERT OR IGNORE INTO seen (aid, nonce, expires_at) VALUES (?, ?, ?)",
                    (aid, nonce, expires_at.timestamp()),
                )
                claimed = cursor.rowcount == 1
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
        return claimed

    def close(self) -> None:
        self._db.close()
