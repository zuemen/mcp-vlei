"""Replay stores: a nonce is claimed once, atomically, and a store says where its memory begins."""

from __future__ import annotations

import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from mcp_vlei.replay import MemoryReplayStore, ReplayStore, SqliteReplayStore

AID = "E" + "A" * 43
T0 = datetime(2026, 10, 4, 9, 0, 0, tzinfo=timezone.utc)
SRC = Path(__file__).resolve().parents[1] / "src"


class Clock:
    def __init__(self, at: datetime) -> None:
        self.at = at

    def __call__(self) -> datetime:
        return self.at


@pytest.fixture(params=["memory", "sqlite"])
def make_store(request, tmp_path):
    def make(clock: Clock):
        if request.param == "memory":
            return MemoryReplayStore(clock=clock)
        return SqliteReplayStore(tmp_path / "replay.sqlite3", clock=clock)
    return make


def test_both_stores_are_replay_stores(tmp_path):
    assert isinstance(MemoryReplayStore(), ReplayStore)
    assert isinstance(SqliteReplayStore(tmp_path / "r.sqlite3"), ReplayStore)


def test_a_nonce_is_claimed_once(make_store):
    store = make_store(Clock(T0))
    assert store.claim(AID, "n1", T0 + timedelta(seconds=90)) is True
    assert store.claim(AID, "n1", T0 + timedelta(seconds=90)) is False
    assert store.claim(AID, "n2", T0 + timedelta(seconds=90)) is True


def test_the_same_nonce_from_another_signer_is_another_claim(make_store):
    store = make_store(Clock(T0))
    assert store.claim(AID, "n1", T0 + timedelta(seconds=90))
    assert store.claim("E" + "B" * 43, "n1", T0 + timedelta(seconds=90))


def test_an_expired_claim_is_forgotten(make_store):
    """After `expires_at` the time check refuses the signature anyway; the entry only costs space."""
    clock = Clock(T0)
    store = make_store(clock)
    assert store.claim(AID, "n1", T0 + timedelta(seconds=90))
    clock.at = T0 + timedelta(seconds=91)
    assert store.claim(AID, "n1", T0 + timedelta(seconds=200)) is True


def test_memory_since_is_when_the_memory_began(make_store):
    assert make_store(Clock(T0)).memory_since == T0


def test_a_memory_store_can_say_its_memory_began_earlier():
    since = T0 - timedelta(days=1)
    assert MemoryReplayStore(memory_since=since, clock=Clock(T0)).memory_since == since


def test_a_restarted_sqlite_store_still_remembers(tmp_path):
    path = tmp_path / "replay.sqlite3"
    first = SqliteReplayStore(path, clock=Clock(T0))
    assert first.claim(AID, "n1", T0 + timedelta(seconds=90))
    first.close()

    again = SqliteReplayStore(path, clock=Clock(T0 + timedelta(seconds=30)))
    assert again.memory_since == T0, "the horizon is the file's, not the process's"
    assert again.claim(AID, "n1", T0 + timedelta(seconds=90)) is False


def test_a_deleted_file_starts_a_new_memory(tmp_path):
    path = tmp_path / "replay.sqlite3"
    SqliteReplayStore(path, clock=Clock(T0)).close()
    for leftover in tmp_path.glob("replay.sqlite3*"):
        leftover.unlink()
    later = T0 + timedelta(hours=1)
    assert SqliteReplayStore(path, clock=Clock(later)).memory_since == later


_CLAIM = (
    "import sys; from datetime import datetime, timezone; "
    "from mcp_vlei.replay import SqliteReplayStore; "
    "s = SqliteReplayStore(sys.argv[1]); "
    "print(s.claim('E' + 'A' * 43, 'shared-nonce', datetime(2099, 1, 1, tzinfo=timezone.utc)))"
)


def test_processes_sharing_one_file_let_exactly_one_claim_through(tmp_path):
    """Two gateway processes on one host, one replayed call arriving at both: one wins."""
    path = tmp_path / "replay.sqlite3"
    SqliteReplayStore(path).close()
    env = dict(os.environ, PYTHONPATH=str(SRC))
    runs = [subprocess.Popen([sys.executable, "-c", _CLAIM, str(path)], env=env,
                             stdout=subprocess.PIPE, text=True) for _ in range(4)]
    answers = sorted(run.communicate(timeout=60)[0].strip() for run in runs)
    assert answers == ["False", "False", "False", "True"]


def test_a_claim_expired_but_not_yet_swept_is_forgotten():
    """Sweeping is periodic, not per claim; an expired entry still waiting for the sweep is
    already gone as far as a claim is concerned."""
    clock = Clock(T0)
    store = MemoryReplayStore(clock=clock)
    assert store.claim(AID, "n1", T0 + timedelta(seconds=1))
    clock.at = T0 + timedelta(seconds=2)  # well inside one sweep interval
    assert store.claim(AID, "n1", T0 + timedelta(seconds=90)) is True
    assert store.claim(AID, "n1", T0 + timedelta(seconds=90)) is False


def test_the_memory_store_sweeps_at_most_once_per_interval():
    """A sweep walks every entry; once per claim made each claim cost the whole table."""
    clock = Clock(T0)
    store = MemoryReplayStore(clock=clock)
    for i in range(50):
        assert store.claim(AID, f"old{i}", T0 + timedelta(milliseconds=1))
    clock.at = T0 + timedelta(milliseconds=2)  # all 50 have expired; no interval has passed
    assert store.claim(AID, "new", T0 + timedelta(seconds=90))
    assert len(store._seen) == 51, "swept on a claim inside the interval"
    clock.at = T0 + MemoryReplayStore.SWEEP_INTERVAL + timedelta(seconds=1)
    assert store.claim(AID, "newer", T0 + timedelta(seconds=90))
    assert sorted(n for _, n in store._seen) == ["new", "newer"], "not swept once the interval passed"


def test_threads_claiming_one_nonce_let_exactly_one_through():
    """Two copies of one call arriving together at one process: one wins, under contention."""
    import threading

    store = MemoryReplayStore()
    expires = datetime.now(timezone.utc) + timedelta(minutes=5)
    start = threading.Barrier(16)
    wins: list[bool] = []

    def worker() -> None:
        start.wait()
        results = [store.claim(AID, "shared-nonce", expires) for _ in range(200)]
        wins.extend(r for r in results if r)

    threads = [threading.Thread(target=worker) for _ in range(16)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    assert wins == [True]


@pytest.mark.parametrize("moment", [
    datetime(2026, 10, 4, 9, 0, 0),  # naive: compared with an aware expiry it raises TypeError
    datetime(2026, 10, 4, 17, 0, 0, tzinfo=timezone(timedelta(hours=8))),
], ids=["naive", "not-utc"])
def test_a_clock_that_is_not_utc_is_refused_at_construction(make_store, moment):
    """A naive clock fails only at the first claim — a crash without a layer, mid-call — and
    SQLite's ``timestamp()`` would read it as local time. Refused when the store is built."""
    with pytest.raises(ValueError, match="UTC"):
        make_store(Clock(moment))


def test_a_memory_store_refuses_a_naive_memory_since():
    with pytest.raises(ValueError, match="UTC"):
        MemoryReplayStore(memory_since=datetime(2026, 1, 1), clock=Clock(T0))
