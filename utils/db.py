"""
SQLite persistence layer for scan runs, findings, and phase transitions.

Schema
------
runs          — one row per run_id
target_status — one row per (run_id, target); tracks phases and final status
findings      — one row per deduplicated finding
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

__all__ = ["ScanDatabase"]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id       TEXT PRIMARY KEY,
    started_at   TEXT NOT NULL,
    finished_at  TEXT,
    status       TEXT NOT NULL DEFAULT 'running',
    config_json  TEXT,
    profile      TEXT
);

CREATE TABLE IF NOT EXISTS target_status (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id       TEXT NOT NULL,
    target       TEXT NOT NULL,
    phase        TEXT NOT NULL,
    status       TEXT NOT NULL,
    started_at   TEXT,
    finished_at  TEXT,
    artifact     TEXT,
    error        TEXT,
    FOREIGN KEY (run_id) REFERENCES runs(run_id),
    UNIQUE(run_id, target, phase)
);

CREATE TABLE IF NOT EXISTS findings (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id         TEXT NOT NULL,
    target         TEXT NOT NULL,
    template_id    TEXT,
    name           TEXT,
    severity       TEXT,
    url            TEXT,
    matched_at     TEXT,
    description    TEXT,
    tags           TEXT,       -- JSON array
    classification TEXT,       -- JSON object
    deduplicated   INTEGER DEFAULT 0,
    created_at     TEXT NOT NULL,
    raw_json       TEXT,
    FOREIGN KEY (run_id) REFERENCES runs(run_id)
);

CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_target_status ON target_status(run_id, target);
"""


class ScanDatabase:
    """
    Thin wrapper around SQLite for persisting scan state.

    Parameters
    ----------
    db_path:
        Path to the SQLite database file.  Parent directories are created
        automatically.
    """

    def __init__(self, db_path: str = "output/scans.db") -> None:
        self._path = Path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self._path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # ------------------------------------------------------------------
    # Runs
    # ------------------------------------------------------------------

    def create_run(
        self,
        run_id: str,
        config: Optional[dict[str, Any]] = None,
        profile: str = "quick",
    ) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO runs (run_id, started_at, config_json, profile) VALUES (?, ?, ?, ?)",
                (run_id, _now(), json.dumps(config or {}), profile),
            )
            self._conn.commit()

    def finish_run(self, run_id: str, status: str = "done") -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE runs SET finished_at = ?, status = ? WHERE run_id = ?",
                (_now(), status, run_id),
            )
            self._conn.commit()

    def get_run(self, run_id: str) -> Optional[dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
        return dict(row) if row else None

    # ------------------------------------------------------------------
    # Phase transitions
    # ------------------------------------------------------------------

    def upsert_phase(
        self,
        run_id: str,
        target: str,
        phase: str,
        status: str,
        started_at: Optional[str] = None,
        finished_at: Optional[str] = None,
        artifact: Optional[str] = None,
        error: Optional[str] = None,
    ) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO target_status
                    (run_id, target, phase, status, started_at, finished_at, artifact, error)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id, target, phase) DO UPDATE SET
                    status      = excluded.status,
                    started_at  = COALESCE(excluded.started_at, target_status.started_at),
                    finished_at = excluded.finished_at,
                    artifact    = excluded.artifact,
                    error       = excluded.error
                """,
                (run_id, target, phase, status, started_at, finished_at, artifact, error),
            )
            self._conn.commit()

    def get_completed_phases(self, run_id: str, target: str) -> set[str]:
        """Return the set of phases that are marked done for *target*."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT phase FROM target_status WHERE run_id = ? AND target = ? AND status = 'done'",
                (run_id, target),
            ).fetchall()
        return {row["phase"] for row in rows}

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def insert_finding(self, finding: dict[str, Any]) -> int:
        with self._lock:
            cur = self._conn.execute(
                """
                INSERT INTO findings
                    (run_id, target, template_id, name, severity, url, matched_at,
                     description, tags, classification, deduplicated, created_at, raw_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding.get("run_id", ""),
                    finding.get("target", ""),
                    finding.get("template-id", finding.get("template_id", "")),
                    finding.get("name", ""),
                    finding.get("severity", ""),
                    finding.get("url", ""),
                    finding.get("matched-at", finding.get("matched_at", "")),
                    finding.get("description", ""),
                    json.dumps(finding.get("tags", [])),
                    json.dumps(finding.get("classification", {})),
                    1 if finding.get("deduplicated") else 0,
                    _now(),
                    json.dumps(finding),
                ),
            )
            self._conn.commit()
        return cur.lastrowid  # type: ignore[return-value]

    def get_findings(
        self,
        run_id: str,
        target: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        query = "SELECT * FROM findings WHERE run_id = ?"
        params: list[Any] = [run_id]
        if target:
            query += " AND target = ?"
            params.append(target)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Housekeeping
    # ------------------------------------------------------------------

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "ScanDatabase":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
