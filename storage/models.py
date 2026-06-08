"""Storage models and DB schema for the team rule library."""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel


class SavedRuleModel(BaseModel):
    """A saved rule in the team library."""

    id: Optional[int] = None
    sid: int
    rev: int
    title: str
    author: str
    raw_rule_text: str
    mitre_tags: List[str]
    created_at: datetime
    updated_at: datetime
    notes: Optional[str] = None


# Schema is intentionally portable between SQLite and PostgreSQL. The few
# dialect differences (autoincrement key, timestamp type) are handled by the
# per-backend DDL below rather than by changing this model.

SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS saved_rules (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    sid           INTEGER NOT NULL,
    rev           INTEGER NOT NULL,
    title         TEXT    NOT NULL,
    author        TEXT    NOT NULL,
    raw_rule_text TEXT    NOT NULL,
    mitre_tags    TEXT    NOT NULL,
    created_at    TEXT    NOT NULL,
    updated_at    TEXT    NOT NULL,
    notes         TEXT
);
"""

POSTGRES_SCHEMA = """
CREATE TABLE IF NOT EXISTS saved_rules (
    id            SERIAL PRIMARY KEY,
    sid           INTEGER NOT NULL,
    rev           INTEGER NOT NULL,
    title         TEXT    NOT NULL,
    author        TEXT    NOT NULL,
    raw_rule_text TEXT    NOT NULL,
    mitre_tags    TEXT    NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL,
    updated_at    TIMESTAMPTZ NOT NULL,
    notes         TEXT
);
"""
