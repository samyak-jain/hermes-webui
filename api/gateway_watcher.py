"""
Hermes Web UI -- Gateway session watcher.

Background daemon thread that polls state.db every 5 seconds for changes
to gateway sessions (telegram, discord, slack, etc.). When changes are
detected, it pushes notifications to all subscribed SSE clients.

This enables real-time session list updates in the sidebar without
requiring any changes to hermes-agent.
"""
import hashlib
import logging
import os
import queue
import threading
import time
from contextlib import closing
from pathlib import Path

from api.config import HOME
from api.agent_sessions import (
    configure_state_db_read_deadline,
    open_state_db_readonly,
    read_importable_agent_session_rows,
)

logger = logging.getLogger(__name__)


# ── State hash tracking ─────────────────────────────────────────────────────

def _snapshot_hash(sessions: list) -> str:
    """Create a lightweight hash of session IDs and timestamps for change detection."""
    key = '|'.join(
        f"{s['session_id']}:{s.get('updated_at', 0)}:{s.get('message_count', 0)}"
        for s in sorted(sessions, key=lambda x: x['session_id'])
    )
    return hashlib.md5(key.encode(), usedforsecurity=False).hexdigest()


# Sources excluded from the WebUI sidebar projection. Must match the default
# ``exclude_sources`` used by ``read_importable_agent_session_rows`` so the
# cheap change-detection scan below sees exactly the same row set as the
# expensive projection (otherwise cron message churn would defeat the gate).
_WATCHER_EXCLUDED_SOURCES = ("cron", "webui")
_WATCHER_DB_READ_DEADLINE_SECONDS = 0.25
_WATCHER_SLOW_POLL_SECONDS = 0.20
_WATCHER_WARNING_INTERVAL_SECONDS = 60.0
_WATCHER_DEGRADED_AFTER_ERRORS = 3
_ROLLBACK_QUIET_SECONDS = 15.0
_ROLLBACK_ERROR_BACKOFF_SECONDS = 60.0
_ROLLBACK_JOURNAL_MODES = {"delete", "truncate", "persist"}


def _state_db_stat_fingerprint(db_path: Path) -> tuple[int, int] | None:
    """Return a lock-free change signal for rollback-journal observation."""
    try:
        stat = db_path.stat()
        return stat.st_mtime_ns, stat.st_size
    except OSError:
        return None


def _detect_journal_mode(db_path: Path) -> str:
    """Resolve the live journal mode once, preferring an operator override."""
    configured = os.getenv("HERMES_WEBUI_STATE_DB_JOURNAL_MODE", "").strip().lower()
    if configured in {"wal", *_ROLLBACK_JOURNAL_MODES}:
        return configured
    if Path(f"{db_path}-wal").exists():
        return "wal"
    try:
        with closing(open_state_db_readonly(db_path)) as conn:
            configure_state_db_read_deadline(
                conn,
                _WATCHER_DB_READ_DEADLINE_SECONDS,
            )
            row = conn.execute("PRAGMA journal_mode").fetchone()
            mode = str(row[0] if row else "").strip().lower()
            if mode in {"wal", *_ROLLBACK_JOURNAL_MODES}:
                return mode
    except Exception:
        logger.debug("Gateway watcher could not detect state.db journal mode")
    # Unknown/exotic filesystems get the conservative reader/writer policy.
    return "unknown"


def _cheap_change_fingerprint(db_path: Path) -> str | None:
    """Compute an indexed change fingerprint without aggregating ``messages``.

    The expensive projection (``read_importable_agent_session_rows``) runs a CTE
    plus a per-session ``MAX(messages.timestamp)`` aggregation over an oversampled
    candidate set every poll. On a large ``state.db`` (hundreds of sessions, tens
    of thousands of messages) that is ~10x the cost of a single ``sessions``-table
    scan, and the watcher runs it forever on a 5s timer even when nothing changed
    (issue #3506).

    This computes a fingerprint from a ``sessions``-table-only scan (no messages
    JOIN), scoped to the same non-cron/webui rows as the projection. To guarantee
    it never skips a change the projection would reflect, it hashes **every
    sessions-table column the projection reads or uses for visibility/collapse**
    -- not just the columns surfaced to the sidebar. That matters because the
    projection collapses compression lineage and hides/shows rows based on
    ``parent_session_id`` / ``ended_at`` / ``end_reason`` / ``source``, so a change
    to one of those alters *which rows* appear even when no displayed field on a
    given row moved.

    Same-count transcript rewrites can move ``last_activity`` without changing a
    ``sessions`` column.  Detect those with one indexed latest-timestamp lookup
    per visible session.  The previous implementation used ``LEFT JOIN`` +
    ``COUNT/MAX`` + ``GROUP BY`` across the entire messages table every five
    seconds.  On a network filesystem in rollback-journal mode that query held a
    SHARED lock for minutes and starved every gateway writer.

    Returns the fingerprint string, or ``None`` on any error / a pre-source
    schema. The watcher retains its last known snapshot and retries later when
    it cannot prove what changed.
    """
    # Columns the projection reads from the ``sessions`` table. ``id``/``source``
    # are always present (``source`` is required for the projection to run at
    # all); the rest are optional on older agent schemas and filtered below.
    _PROJECTION_SESSION_COLS = (
        'id', 'source', 'session_source', 'title', 'model', 'message_count',
        'started_at', 'ended_at', 'end_reason', 'parent_session_id', 'archived',
        'user_id', 'chat_id', 'chat_type', 'thread_id', 'session_key',
        'origin_chat_id', 'origin_user_id', 'platform',
    )
    try:
        with closing(open_state_db_readonly(db_path)) as conn:
            configure_state_db_read_deadline(
                conn,
                _WATCHER_DB_READ_DEADLINE_SECONDS,
            )
            cur = conn.cursor()
            cur.execute("PRAGMA table_info(sessions)")
            cols = {row[1] for row in cur.fetchall()}
            if 'source' not in cols:
                return None
            selectable = [c for c in _PROJECTION_SESSION_COLS if c in cols]
            placeholders = ", ".join("?" for _ in _WATCHER_EXCLUDED_SOURCES)
            latest_message_expr = "NULL"
            cur.execute("PRAGMA table_info(messages)")
            message_cols = {row[1] for row in cur.fetchall()}
            if {'session_id', 'timestamp'}.issubset(message_cols):
                cur.execute("PRAGMA index_list(messages)")
                message_indexes = {str(row[1]) for row in cur.fetchall()}
                if "idx_messages_session" not in message_indexes:
                    # Preserve compatibility with old/minimal agent schemas.
                    # message_count still detects normal appends. Same-count
                    # transcript rewrites require the current agent's covering
                    # index, but this background reader must never create that
                    # index or replace it with a full-table aggregate.
                    logger.debug(
                        "Gateway watcher using sessions-only fingerprint: "
                        "idx_messages_session is unavailable"
                    )
                else:
                    # ``idx_messages_session(session_id, timestamp)`` makes this
                    # an O(log N) covering-index seek per session. INDEXED BY is
                    # intentional so a future planner change cannot reintroduce
                    # a full messages scan.
                    latest_message_expr = (
                        "(SELECT m.timestamp FROM messages m "
                        "INDEXED BY idx_messages_session "
                        "WHERE m.session_id = s.id "
                        "ORDER BY m.timestamp DESC LIMIT 1)"
                    )
            cur.execute(
                f"SELECT {', '.join(f's.{c}' for c in selectable)}, "
                f"{latest_message_expr} AS latest_message_at "
                f"FROM sessions s "
                f"WHERE s.source IS NOT NULL AND s.source NOT IN ({placeholders}) "
                f"ORDER BY s.id",
                list(_WATCHER_EXCLUDED_SOURCES),
            )
            h = hashlib.md5(usedforsecurity=False)
            for row in cur.fetchall():
                h.update(repr(row).encode('utf-8', 'replace'))
                h.update(b'\x1e')
            return h.hexdigest()
    except Exception as exc:
        logger.debug("Gateway watcher fingerprint unavailable: %s", exc)
        return None


# ── DB resolution (shared pattern with state_sync.py) ──────────────────────

def _get_state_db_path(hermes_home: Path | None = None) -> Path:
    """Resolve state.db path for the active profile."""
    if hermes_home is not None:
        return Path(hermes_home).expanduser().resolve() / 'state.db'
    try:
        from api.profiles import get_active_hermes_home
        hermes_home = Path(get_active_hermes_home()).expanduser().resolve()
    except Exception:
        hermes_home = Path(os.getenv('HERMES_HOME', str(HOME / '.hermes'))).expanduser().resolve()
    return hermes_home / 'state.db'


def _get_agent_sessions_from_db(
    db_path: Path | None = None,
    *,
    read_deadline_seconds: float | None = None,
) -> list | None:
    """Read all non-webui sessions from state.db.

    Returns a list of session dicts, ``[]`` when the database does not exist,
    or ``None`` when an attempted read fails.
    """
    db_path = Path(db_path) if db_path is not None else _get_state_db_path()
    if not db_path.exists():
        return []

    try:
        sessions = []
        for row in read_importable_agent_session_rows(
            db_path,
            limit=200,
            log=logger,
            query_deadline_seconds=read_deadline_seconds,
        ):
            sessions.append({
                'session_id': row['id'],
                'title': row['title'] or 'Agent Session',
                'model': row['model'] or None,
                'message_count': row['message_count'] or row['actual_message_count'] or 0,
                'created_at': row['started_at'],
                'updated_at': row['last_activity'] or row['started_at'],
                'source': row['source'] or 'cli',
                'raw_source': row.get('raw_source'),
                'session_source': row.get('session_source'),
                'source_label': row.get('source_label'),
            })
        return sessions
    except Exception as exc:
        logger.debug("Gateway watcher session projection unavailable: %s", exc)
        return None


# ── GatewayWatcher ──────────────────────────────────────────────────────────

class GatewayWatcher:
    """Background thread that polls state.db for agent session changes.

    Usage:
        watcher = GatewayWatcher()
        watcher.start()
        q = watcher.subscribe()
        # ... receive change events via q.get() ...
        watcher.unsubscribe(q)
        watcher.stop()
    """

    POLL_INTERVAL = 5  # seconds between polls
    SUBSCRIBER_TIMEOUT = 30  # seconds before sending keepalive comment

    def __init__(
        self,
        *,
        hermes_home: Path | None = None,
        profile_name: str | None = None,
        state_db_path: Path | None = None,
        journal_mode: str | None = None,
    ):
        self._subscribers: list[queue.Queue] = []
        self._sub_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._hermes_home = Path(hermes_home).expanduser().resolve() if hermes_home else None
        self._state_db_path = (
            Path(state_db_path).expanduser().resolve()
            if state_db_path is not None
            else _get_state_db_path(self._hermes_home) if self._hermes_home is not None else _get_state_db_path()
        )
        self.profile_name = profile_name or ""
        self._journal_mode = (
            str(journal_mode).strip().lower()
            if journal_mode
            else _detect_journal_mode(self._state_db_path)
        )
        self._rollback_safe_polling = self._journal_mode != "wal"
        self._last_db_stat: tuple[int, int] | None = None
        self._processed_db_stat: tuple[int, int] | None = None
        self._last_db_change_at = time.monotonic()
        self._next_db_read_at = 0.0
        self._last_hash: str = ''
        self._last_sessions: list = []
        self._last_poll_ms = 0.0
        self._last_success_at = 0.0
        self._last_error = ""
        self._consecutive_errors = 0
        self._last_warning_at = 0.0
        # Indexed change fingerprint from the previous poll. When it is
        # unchanged we skip the full session projection entirely
        # (issue #3506). Empty string forces the first poll to run the full read.
        self._last_cheap_fp: str = ''

    def start(self):
        """Start the watcher daemon thread."""
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._poll_loop, daemon=True, name='gateway-watcher')
        self._thread.start()

    def is_alive(self) -> bool:
        """Return True when the poll thread is running.

        Public accessor used by ``/api/sessions/gateway/stream`` probe mode and
        the live SSE handler to detect a watcher instance whose poll thread
        died silently (e.g. uncaught exception in ``_poll_loop``).  Callers
        use this to decide whether to return 503 and trigger the client-side
        polling fallback, instead of handing out an SSE connection that would
        never emit events.
        """
        t = self._thread
        return t is not None and t.is_alive()

    def stop(self):
        """Stop the watcher thread."""
        self._stop_event.set()
        # Wake up any subscribers
        with self._sub_lock:
            for q in self._subscribers:
                try:
                    q.put(None)  # sentinel
                except Exception:
                    logger.debug("Failed to send sentinel to subscriber")
        if self._thread:
            self._thread.join(timeout=3)
            self._thread = None

    def subscribe(self) -> queue.Queue:
        """Subscribe to change events. Returns a queue.Queue.
        Events are dicts: {'type': 'sessions_changed', 'sessions': [...]}
        A None sentinel means the watcher is stopping.
        """
        q = queue.Queue(maxsize=10)
        with self._sub_lock:
            self._subscribers.append(q)
            # Stop-race safety: if stop() already ran (set _stop_event and drained
            # the then-current subscriber list) before we appended, this queue would
            # never receive the sentinel and the SSE loop would hang open with
            # keepalives but no events. Enqueue the sentinel ourselves so the handler
            # closes and reconnects to the live registry watcher. (#3629 / Codex gate)
            if self._stop_event.is_set():
                try:
                    q.put_nowait(None)
                except Exception:
                    logger.debug("Failed to send stop sentinel to late subscriber")
        return q

    def snapshot(self) -> list:
        """Return the last successfully observed session projection.

        SSE connection setup must never run a second unbounded ``state.db``
        projection. The watcher owns database observation; subscribers receive a
        shallow copy of its cache and a later change event if the first
        rollback-safe snapshot is still pending.
        """
        return list(self._last_sessions)

    def unsubscribe(self, q: queue.Queue):
        """Remove a subscriber queue."""
        with self._sub_lock:
            try:
                self._subscribers.remove(q)
            except ValueError:
                pass

    def _notify_subscribers(self, sessions: list):
        """Push change event to all subscribers."""
        event = {
            'type': 'sessions_changed',
            'sessions': sessions,
        }
        with self._sub_lock:
            dead = []
            for q in self._subscribers:
                try:
                    q.put_nowait(event)
                except queue.Full:
                    dead.append(q)  # remove slow consumers
                except Exception:
                    dead.append(q)
            for q in dead:
                try:
                    self._subscribers.remove(q)
                except ValueError:
                    pass
                # Send a None sentinel so the SSE handler unblocks, closes,
                # and lets the browser's EventSource auto-reconnect.
                try:
                    q.put_nowait(None)
                except Exception:
                    logger.debug("Failed to send sentinel to dead subscriber")

    def diagnostics(self) -> dict:
        with self._sub_lock:
            subscriber_count = len(self._subscribers)
        degraded = self._consecutive_errors >= _WATCHER_DEGRADED_AFTER_ERRORS
        return {
            # A single best-effort observation can collide with a legitimate
            # writer. Only persistent failures should fail deep health.
            "status": "degraded" if degraded else "ok",
            "profile": self.profile_name or "default",
            "journal_mode": self._journal_mode,
            "rollback_safe_polling": self._rollback_safe_polling,
            "alive": self.is_alive(),
            "subscriber_count": subscriber_count,
            "last_poll_ms": round(self._last_poll_ms, 1),
            "last_success_at": self._last_success_at or None,
            "consecutive_errors": self._consecutive_errors,
            "last_error": self._last_error or None,
        }

    def _record_poll_error(self, message: str, elapsed: float) -> None:
        self._last_poll_ms = elapsed * 1000
        self._last_error = message
        self._consecutive_errors += 1
        now = time.monotonic()
        if now - self._last_warning_at >= _WATCHER_WARNING_INTERVAL_SECONDS:
            self._last_warning_at = now
            logger.warning(
                "Gateway watcher state.db poll degraded after %.1fms: %s",
                self._last_poll_ms,
                message,
            )

    def _record_poll_success(self, elapsed: float) -> None:
        self._last_poll_ms = elapsed * 1000
        self._last_success_at = time.time()
        self._last_error = ""
        self._consecutive_errors = 0
        if elapsed >= _WATCHER_SLOW_POLL_SECONDS:
            now = time.monotonic()
            if now - self._last_warning_at >= _WATCHER_WARNING_INTERVAL_SECONDS:
                self._last_warning_at = now
                logger.warning(
                    "Gateway watcher state.db poll took %.1fms",
                    self._last_poll_ms,
                )

    def _poll_once(self) -> None:
        started = time.monotonic()
        db_path = self._state_db_path
        rollback_stat = None
        if self._rollback_safe_polling:
            now = time.monotonic()
            rollback_stat = _state_db_stat_fingerprint(db_path)
            if rollback_stat != self._last_db_stat:
                self._last_db_stat = rollback_stat
                self._last_db_change_at = now
                self._record_poll_success(time.monotonic() - started)
                return
            if rollback_stat == self._processed_db_stat:
                self._record_poll_success(time.monotonic() - started)
                return
            if (
                now < self._next_db_read_at
                or now - self._last_db_change_at < _ROLLBACK_QUIET_SECONDS
            ):
                self._record_poll_success(time.monotonic() - started)
                return

        cheap_fp = _cheap_change_fingerprint(db_path) if db_path.exists() else ''
        if cheap_fp is None:
            if self._rollback_safe_polling:
                self._next_db_read_at = (
                    time.monotonic() + _ROLLBACK_ERROR_BACKOFF_SECONDS
                )
            self._record_poll_error(
                "fingerprint read timed out or failed",
                time.monotonic() - started,
            )
            return
        if cheap_fp == self._last_cheap_fp:
            if self._rollback_safe_polling:
                # The file changed, but only outside the sidebar-visible
                # projection (for example a cron session). Mark this exact
                # committed image processed so rollback mode does not reopen
                # SQLite every five seconds for the same non-change.
                self._processed_db_stat = rollback_stat
                self._next_db_read_at = 0.0
            self._record_poll_success(time.monotonic() - started)
            return

        sessions = _get_agent_sessions_from_db(
            db_path,
            read_deadline_seconds=_WATCHER_DB_READ_DEADLINE_SECONDS,
        )
        if sessions is None:
            if self._rollback_safe_polling:
                self._next_db_read_at = (
                    time.monotonic() + _ROLLBACK_ERROR_BACKOFF_SECONDS
                )
            self._record_poll_error(
                "session projection read timed out or failed",
                time.monotonic() - started,
            )
            return

        current_hash = _snapshot_hash(sessions)
        self._last_cheap_fp = cheap_fp
        if self._rollback_safe_polling:
            self._processed_db_stat = rollback_stat
            self._next_db_read_at = 0.0
        if current_hash != self._last_hash:
            self._last_hash = current_hash
            self._last_sessions = sessions
            self._notify_subscribers(sessions)
        self._record_poll_success(time.monotonic() - started)

    def _poll_loop(self):
        """Main polling loop. Runs in a daemon thread."""
        while not self._stop_event.is_set():
            try:
                # Rollback-journal databases first wait for a quiet file
                # metadata window. WAL databases poll the indexed change
                # fingerprint directly. The full session projection runs only
                # after a real change (issue #3506).
                self._poll_once()
            except Exception:
                logger.debug("Error in gateway watcher poll loop", exc_info=True)

            # Sleep in small increments so we can stop promptly
            for _ in range(self.POLL_INTERVAL * 10):
                if self._stop_event.is_set():
                    return
                time.sleep(0.1)


# ── Module-level watcher registry ──────────────────────────────────────────

_watchers: dict[str, GatewayWatcher] = {}
_watcher_lock = threading.Lock()

def _resolve_watcher_target(
    *,
    profile_name: str | None = None,
    hermes_home: Path | None = None,
) -> tuple[str, Path | None]:
    """Resolve the watcher profile/home pair for the current request context."""
    resolved_profile = str(profile_name or "").strip()
    resolved_home = Path(hermes_home).expanduser().resolve() if hermes_home is not None else None

    try:
        from api.profiles import get_active_profile_name, get_hermes_home_for_profile

        if not resolved_profile:
            resolved_profile = get_active_profile_name() or "default"
        if resolved_home is None and resolved_profile:
            resolved_home = Path(get_hermes_home_for_profile(resolved_profile)).expanduser().resolve()
    except Exception:
        if resolved_home is None:
            try:
                resolved_home = _get_state_db_path().parent.resolve()
            except Exception:
                resolved_home = None

    return resolved_profile, resolved_home


def _watcher_registry_key(profile_name: str | None = None, hermes_home: Path | None = None) -> str:
    """Return the stable registry key for a watcher target."""
    if hermes_home is not None:
        return str(Path(hermes_home).expanduser().resolve())
    return str(profile_name or "").strip() or "__default__"


def _watcher_has_subscribers(watcher: GatewayWatcher) -> bool:
    subscribers = getattr(watcher, "_subscribers", None)
    sub_lock = getattr(watcher, "_sub_lock", None)
    if subscribers is None or sub_lock is None:
        return False
    with sub_lock:
        return bool(subscribers)


def _pop_idle_watchers_locked(*, exclude_key: str) -> list[GatewayWatcher]:
    stale: list[GatewayWatcher] = []
    for key, watcher in list(_watchers.items()):
        if key == exclude_key or _watcher_has_subscribers(watcher):
            continue
        if _watchers.get(key) is watcher:
            stale.append(_watchers.pop(key))
    return stale


def start_watcher(*, profile_name: str | None = None, hermes_home: Path | None = None):
    """Start the watcher for the resolved profile home (idempotent)."""
    resolved_profile, resolved_home = _resolve_watcher_target(
        profile_name=profile_name,
        hermes_home=hermes_home,
    )
    key = _watcher_registry_key(resolved_profile, resolved_home)
    with _watcher_lock:
        watcher = _watchers.get(key)
        if watcher is None or not watcher.is_alive():
            if watcher is not None:
                watcher.stop()
            watcher = GatewayWatcher(profile_name=resolved_profile, hermes_home=resolved_home)
            watcher.start()
            _watchers[key] = watcher
        return watcher


def stop_watcher(*, profile_name: str | None = None, hermes_home: Path | None = None):
    """Stop either one profile watcher or the entire registry."""
    with _watcher_lock:
        if profile_name is None and hermes_home is None:
            watchers = list(_watchers.values())
            _watchers.clear()
        else:
            resolved_profile, resolved_home = _resolve_watcher_target(
                profile_name=profile_name,
                hermes_home=hermes_home,
            )
            key = _watcher_registry_key(resolved_profile, resolved_home)
            watcher = _watchers.pop(key, None)
            watchers = [watcher] if watcher is not None else []
    for watcher in watchers:
        watcher.stop()


def restart_watcher_for_profile(name: str):
    """Restart only the watcher pinned to the target profile home."""
    from api.profiles import get_hermes_home_for_profile

    hermes_home = Path(get_hermes_home_for_profile(name)).expanduser().resolve()
    key = _watcher_registry_key(name, hermes_home)
    watcher = GatewayWatcher(profile_name=name, hermes_home=hermes_home)
    watcher.start()
    with _watcher_lock:
        existing = _watchers.pop(key, None)
        stale_watchers = [] if existing is not None else _pop_idle_watchers_locked(exclude_key=key)
        _watchers[key] = watcher
    for old_watcher in ([existing] if existing is not None else stale_watchers):
        old_watcher.stop()
    return watcher


def get_watcher(*, profile_name: str | None = None, hermes_home: Path | None = None) -> GatewayWatcher | None:
    """Get or lazily start the watcher for the resolved request profile."""
    resolved_profile, resolved_home = _resolve_watcher_target(
        profile_name=profile_name,
        hermes_home=hermes_home,
    )
    key = _watcher_registry_key(resolved_profile, resolved_home)
    with _watcher_lock:
        watcher = _watchers.get(key)
    if watcher is None or not watcher.is_alive():
        watcher = start_watcher(profile_name=resolved_profile, hermes_home=resolved_home)
    return watcher


def get_watcher_diagnostics() -> dict:
    """Return non-mutating watcher health for the deep health endpoint."""
    with _watcher_lock:
        watchers = list(_watchers.values())
    details = [watcher.diagnostics() for watcher in watchers]
    # Stopped watchers remain in the profile registry until the next lazy
    # restart. Their last observation error is useful diagnostics, but it must
    # not make the currently serving WebUI unhealthy.
    degraded = any(
        item.get("alive") and item.get("status") == "degraded"
        for item in details
    )
    return {
        "status": "degraded" if degraded else "ok",
        "watcher_count": len(details),
        "watchers": details,
    }
