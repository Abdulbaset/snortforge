"""Repository interface for the team rule library.

Two backends sit behind one API so the UI never knows which is active:

  * SQLiteRepository  - default, a file in data/ (or in-memory for tests).
  * PostgresRepository - selected when SNORTFORGE_DB_URL is set to a
    postgresql:// connection string.

Use ``get_repository()`` to obtain the active backend. Switching to Postgres in
production needs only the env var; no UI code changes.
"""

from __future__ import annotations

import abc
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from storage.models import (
    POSTGRES_SCHEMA,
    SQLITE_SCHEMA,
    SavedRuleModel,
)

DEFAULT_SQLITE_PATH = Path(__file__).resolve().parent.parent / "data" / "library.db"
DB_URL_ENV = "SNORTFORGE_DB_URL"


def _now() -> datetime:
    return datetime.now(timezone.utc)


class RuleRepository(abc.ABC):
    """Abstract team-library repository."""

    @abc.abstractmethod
    def save(self, rule: SavedRuleModel) -> SavedRuleModel:
        """Insert a new rule, returning it with its assigned id."""

    @abc.abstractmethod
    def update(self, rule: SavedRuleModel) -> SavedRuleModel:
        """Update an existing rule; bumps rev and updated_at."""

    @abc.abstractmethod
    def get(self, rule_id: int) -> Optional[SavedRuleModel]:
        """Load a rule by primary key."""

    @abc.abstractmethod
    def list_all(self) -> List[SavedRuleModel]:
        """Return all saved rules, newest first."""

    @abc.abstractmethod
    def search(
        self,
        sid: Optional[int] = None,
        title: Optional[str] = None,
        mitre_tag: Optional[str] = None,
    ) -> List[SavedRuleModel]:
        """Search by SID, title substring, and/or MITRE tag (AND-combined)."""


# --- SQLite -------------------------------------------------------------------


class SQLiteRepository(RuleRepository):
    """SQLite-backed repository. Pass ':memory:' for tests."""

    def __init__(self, db_path: str | Path = DEFAULT_SQLITE_PATH):
        self._is_memory = str(db_path) == ":memory:"
        if not self._is_memory:
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False so Streamlit's threads can share the conn.
        self._conn = sqlite3.connect(
            str(db_path), check_same_thread=False
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SQLITE_SCHEMA)
        self._conn.commit()

    @staticmethod
    def _row_to_model(row: sqlite3.Row) -> SavedRuleModel:
        return SavedRuleModel(
            id=row["id"],
            sid=row["sid"],
            rev=row["rev"],
            title=row["title"],
            author=row["author"],
            raw_rule_text=row["raw_rule_text"],
            mitre_tags=json.loads(row["mitre_tags"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            notes=row["notes"],
        )

    def save(self, rule: SavedRuleModel) -> SavedRuleModel:
        now = _now()
        rule.created_at = rule.created_at or now
        rule.updated_at = now
        cur = self._conn.execute(
            """INSERT INTO saved_rules
               (sid, rev, title, author, raw_rule_text, mitre_tags,
                created_at, updated_at, notes)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                rule.sid,
                rule.rev,
                rule.title,
                rule.author,
                rule.raw_rule_text,
                json.dumps(rule.mitre_tags),
                rule.created_at.isoformat(),
                rule.updated_at.isoformat(),
                rule.notes,
            ),
        )
        self._conn.commit()
        rule.id = cur.lastrowid
        return rule

    def update(self, rule: SavedRuleModel) -> SavedRuleModel:
        if rule.id is None:
            raise ValueError("Cannot update a rule without an id.")
        rule.rev += 1
        rule.updated_at = _now()
        self._conn.execute(
            """UPDATE saved_rules
               SET sid=?, rev=?, title=?, author=?, raw_rule_text=?,
                   mitre_tags=?, updated_at=?, notes=?
               WHERE id=?""",
            (
                rule.sid,
                rule.rev,
                rule.title,
                rule.author,
                rule.raw_rule_text,
                json.dumps(rule.mitre_tags),
                rule.updated_at.isoformat(),
                rule.notes,
                rule.id,
            ),
        )
        self._conn.commit()
        return rule

    def get(self, rule_id: int) -> Optional[SavedRuleModel]:
        row = self._conn.execute(
            "SELECT * FROM saved_rules WHERE id=?", (rule_id,)
        ).fetchone()
        return self._row_to_model(row) if row else None

    def list_all(self) -> List[SavedRuleModel]:
        rows = self._conn.execute(
            "SELECT * FROM saved_rules ORDER BY updated_at DESC, id DESC"
        ).fetchall()
        return [self._row_to_model(r) for r in rows]

    def search(
        self,
        sid: Optional[int] = None,
        title: Optional[str] = None,
        mitre_tag: Optional[str] = None,
    ) -> List[SavedRuleModel]:
        clauses, params = [], []
        if sid is not None:
            clauses.append("sid = ?")
            params.append(sid)
        if title:
            clauses.append("title LIKE ?")
            params.append(f"%{title}%")
        if mitre_tag:
            # mitre_tags is JSON text; a substring match on the tag id is
            # sufficient for the library search.
            clauses.append("mitre_tags LIKE ?")
            params.append(f"%{mitre_tag}%")
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = self._conn.execute(
            f"SELECT * FROM saved_rules{where} ORDER BY updated_at DESC, id DESC",
            params,
        ).fetchall()
        return [self._row_to_model(r) for r in rows]


# --- PostgreSQL ---------------------------------------------------------------


class PostgresRepository(RuleRepository):
    """PostgreSQL-backed repository. Same schema/behaviour as SQLite.

    Imports psycopg lazily so SQLite-only environments (and tests) do not need
    a Postgres driver loaded.
    """

    def __init__(self, dsn: str):
        import psycopg  # lazy import

        self._psycopg = psycopg
        self._dsn = dsn
        self._conn = psycopg.connect(dsn)
        with self._conn.cursor() as cur:
            cur.execute(POSTGRES_SCHEMA)
        self._conn.commit()

    @staticmethod
    def _row_to_model(row) -> SavedRuleModel:
        return SavedRuleModel(
            id=row[0],
            sid=row[1],
            rev=row[2],
            title=row[3],
            author=row[4],
            raw_rule_text=row[5],
            mitre_tags=json.loads(row[6]),
            created_at=row[7],
            updated_at=row[8],
            notes=row[9],
        )

    _COLS = (
        "id, sid, rev, title, author, raw_rule_text, mitre_tags, "
        "created_at, updated_at, notes"
    )

    def save(self, rule: SavedRuleModel) -> SavedRuleModel:
        now = _now()
        rule.created_at = rule.created_at or now
        rule.updated_at = now
        with self._conn.cursor() as cur:
            cur.execute(
                """INSERT INTO saved_rules
                   (sid, rev, title, author, raw_rule_text, mitre_tags,
                    created_at, updated_at, notes)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                   RETURNING id""",
                (
                    rule.sid,
                    rule.rev,
                    rule.title,
                    rule.author,
                    rule.raw_rule_text,
                    json.dumps(rule.mitre_tags),
                    rule.created_at,
                    rule.updated_at,
                    rule.notes,
                ),
            )
            rule.id = cur.fetchone()[0]
        self._conn.commit()
        return rule

    def update(self, rule: SavedRuleModel) -> SavedRuleModel:
        if rule.id is None:
            raise ValueError("Cannot update a rule without an id.")
        rule.rev += 1
        rule.updated_at = _now()
        with self._conn.cursor() as cur:
            cur.execute(
                """UPDATE saved_rules
                   SET sid=%s, rev=%s, title=%s, author=%s, raw_rule_text=%s,
                       mitre_tags=%s, updated_at=%s, notes=%s
                   WHERE id=%s""",
                (
                    rule.sid,
                    rule.rev,
                    rule.title,
                    rule.author,
                    rule.raw_rule_text,
                    json.dumps(rule.mitre_tags),
                    rule.updated_at,
                    rule.notes,
                    rule.id,
                ),
            )
        self._conn.commit()
        return rule

    def get(self, rule_id: int) -> Optional[SavedRuleModel]:
        with self._conn.cursor() as cur:
            cur.execute(
                f"SELECT {self._COLS} FROM saved_rules WHERE id=%s", (rule_id,)
            )
            row = cur.fetchone()
        return self._row_to_model(row) if row else None

    def list_all(self) -> List[SavedRuleModel]:
        with self._conn.cursor() as cur:
            cur.execute(
                f"SELECT {self._COLS} FROM saved_rules "
                "ORDER BY updated_at DESC, id DESC"
            )
            rows = cur.fetchall()
        return [self._row_to_model(r) for r in rows]

    def search(
        self,
        sid: Optional[int] = None,
        title: Optional[str] = None,
        mitre_tag: Optional[str] = None,
    ) -> List[SavedRuleModel]:
        clauses, params = [], []
        if sid is not None:
            clauses.append("sid = %s")
            params.append(sid)
        if title:
            clauses.append("title ILIKE %s")
            params.append(f"%{title}%")
        if mitre_tag:
            clauses.append("mitre_tags LIKE %s")
            params.append(f"%{mitre_tag}%")
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._conn.cursor() as cur:
            cur.execute(
                f"SELECT {self._COLS} FROM saved_rules{where} "
                "ORDER BY updated_at DESC, id DESC",
                params,
            )
            rows = cur.fetchall()
        return [self._row_to_model(r) for r in rows]


# --- Factory ------------------------------------------------------------------


def get_repository() -> RuleRepository:
    """Return the active repository based on environment.

    If SNORTFORGE_DB_URL is set to a postgres DSN, use PostgreSQL; otherwise use
    the default SQLite file. The UI calls only this function, so swapping
    backends in production is a connection-string change with no UI edits.
    """
    dsn = os.environ.get(DB_URL_ENV, "").strip()
    if dsn.startswith("postgres"):
        return PostgresRepository(dsn)
    return SQLiteRepository()
