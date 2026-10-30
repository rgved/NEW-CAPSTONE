"""
backend/memory/sqlite/database.py

SQLite initialisation and connection management.

Creates the tables used by the current MVP phases:
  - missions  (I1: new — source of truth for mission status)
  - routes
  - features
  - findings
  - reports
  - tasks

The findings table is extended in Phase 6 to persist structured security
observations while remaining backward compatible with the original schema.
"""
from __future__ import annotations

import sqlite3
from typing import Optional

from backend.config import DB_PATH
from backend.services.logger import get_logger

logger = get_logger(__name__)

# ── SQL ───────────────────────────────────────────────────────────────────────

_CREATE_USERS = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    email         TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    salt          TEXT    NOT NULL,
    created_at    TEXT    NOT NULL
);
"""

# I1: Proper missions table — replaces inferred mission IDs from tasks/reports.
_CREATE_MISSIONS = """
CREATE TABLE IF NOT EXISTS missions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    mission_id  TEXT    NOT NULL UNIQUE,
    target_url  TEXT    NOT NULL,
    status      TEXT    NOT NULL DEFAULT 'running',
    started_at  TEXT    NOT NULL,
    finished_at TEXT,
    username    TEXT
);
"""

_CREATE_ROUTES = """
CREATE TABLE IF NOT EXISTS routes (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    url          TEXT    NOT NULL,
    discovered_at DATETIME NOT NULL,
    mission_id   TEXT
);
"""

_CREATE_FEATURES = """
CREATE TABLE IF NOT EXISTS features (
    id                        INTEGER PRIMARY KEY AUTOINCREMENT,
    name                      TEXT    NOT NULL,
    analyzed                  BOOLEAN DEFAULT FALSE,
    routes                    TEXT    DEFAULT '[]',
    classification_confidence REAL    DEFAULT 0.0,
    mission_id                TEXT
);
"""

_CREATE_FINDINGS = """
CREATE TABLE IF NOT EXISTS findings (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id           TEXT,
    type                 TEXT NOT NULL DEFAULT 'unknown',
    title                TEXT NOT NULL,
    feature              TEXT NOT NULL DEFAULT 'unknown',
    severity             TEXT NOT NULL,
    security_confidence  REAL NOT NULL DEFAULT 0.0,
    evidence             TEXT NOT NULL DEFAULT '[]',
    description          TEXT NOT NULL DEFAULT '',
    reasoning            TEXT NOT NULL DEFAULT '',
    route_id             INTEGER,
    mission_id           TEXT
);
"""

_CREATE_REPORTS = """
CREATE TABLE IF NOT EXISTS reports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id   TEXT,
    mission_id  TEXT NOT NULL,
    target_url  TEXT NOT NULL,
    generated_at TEXT NOT NULL,
    report_json TEXT NOT NULL
);
"""

_CREATE_TASKS = """
CREATE TABLE IF NOT EXISTS tasks (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    action     TEXT     NOT NULL,
    status     TEXT     NOT NULL,
    created_at DATETIME NOT NULL,
    mission_id TEXT,
    target     TEXT
);
"""


# ── Public API ────────────────────────────────────────────────────────────────

def get_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """
    Open and return a SQLite connection.

    Row factory is set to sqlite3.Row so columns are accessible by name.
    Callers are responsible for closing the connection.
    """
    path = db_path or DB_PATH
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Optional[str] = None) -> None:
    """
    Create all required tables if they do not already exist.

    Safe to call multiple times — uses CREATE TABLE IF NOT EXISTS throughout.
    """
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        # I1: missions table first — other tables reference mission_id
        cursor.execute(_CREATE_USERS)
        _ensure_column(cursor, "users", "auth_provider", "TEXT NOT NULL DEFAULT 'local'")
        _ensure_column(cursor, "users", "avatar_url", "TEXT")
        _ensure_column(cursor, "users", "google_id", "TEXT")
        cursor.execute(_CREATE_MISSIONS)
        _ensure_column(cursor, "missions", "mission_id", "TEXT NOT NULL DEFAULT ''")
        _ensure_column(cursor, "missions", "target_url", "TEXT NOT NULL DEFAULT ''")
        _ensure_column(cursor, "missions", "status", "TEXT NOT NULL DEFAULT 'running'")
        _ensure_column(cursor, "missions", "started_at", "TEXT NOT NULL DEFAULT ''")
        _ensure_column(cursor, "missions", "finished_at", "TEXT")
        _ensure_column(cursor, "missions", "username", "TEXT")
        cursor.execute(_CREATE_ROUTES)
        _ensure_column(cursor, "routes", "mission_id", "TEXT")
        cursor.execute(_CREATE_FEATURES)
        _ensure_column(cursor, "features", "routes", "TEXT DEFAULT '[]'")
        _ensure_column(cursor, "features", "classification_confidence", "REAL DEFAULT 0.0")
        _ensure_column(cursor, "features", "mission_id", "TEXT")
        cursor.execute(_CREATE_FINDINGS)
        _ensure_column(cursor, "findings", "finding_id", "TEXT")
        _ensure_column(cursor, "findings", "type", "TEXT NOT NULL DEFAULT 'unknown'")
        _ensure_column(cursor, "findings", "feature", "TEXT NOT NULL DEFAULT 'unknown'")
        _ensure_column(cursor, "findings", "security_confidence", "REAL NOT NULL DEFAULT 0.0")
        _ensure_column(cursor, "findings", "evidence", "TEXT NOT NULL DEFAULT '[]'")
        _ensure_column(cursor, "findings", "description", "TEXT NOT NULL DEFAULT ''")
        _ensure_column(cursor, "findings", "reasoning", "TEXT NOT NULL DEFAULT ''")
        _ensure_column(cursor, "findings", "model_severity", "TEXT")
        _ensure_column(cursor, "findings", "route_id", "INTEGER")
        _ensure_column(cursor, "findings", "mission_id", "TEXT")
        cursor.execute(_CREATE_REPORTS)
        _ensure_column(cursor, "reports", "report_id", "TEXT")
        _ensure_column(cursor, "reports", "mission_id", "TEXT NOT NULL DEFAULT ''")
        _ensure_column(cursor, "reports", "target_url", "TEXT NOT NULL DEFAULT ''")
        _ensure_column(cursor, "reports", "generated_at", "TEXT NOT NULL DEFAULT ''")
        _ensure_column(cursor, "reports", "report_json", "TEXT NOT NULL DEFAULT '{}'")
        cursor.execute(_CREATE_TASKS)
        _ensure_column(cursor, "tasks", "mission_id", "TEXT")
        _ensure_column(cursor, "tasks", "target", "TEXT")
        cursor.execute("UPDATE missions SET username = 'ria_parmar' WHERE (username IS NULL OR username = '') AND EXISTS (SELECT 1 FROM users WHERE username = 'ria_parmar' OR email = 'riaaparmar5812@gmail.com')")
        conn.commit()
        logger.info("Database initialised at: %s", db_path or DB_PATH)
    finally:
        conn.close()


def _ensure_column(cursor: sqlite3.Cursor, table_name: str, column_name: str, column_definition: str) -> None:
    cursor.execute(f"PRAGMA table_info({table_name})")
    existing_columns = {row["name"] for row in cursor.fetchall()}
    if column_name not in existing_columns:
        cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_definition}")
