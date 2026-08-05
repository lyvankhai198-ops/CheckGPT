"""SQLite database for activation keys and user tokens."""
from __future__ import annotations

import os
import random
import sqlite3
import string
import uuid
from datetime import datetime, timedelta

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "checker_data.db")


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with _conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS activation_keys (
                key_code  TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                expires_at TEXT,
                used_by   TEXT,
                used_at   TEXT,
                note      TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS user_tokens (
                id         TEXT PRIMARY KEY,
                user_id    TEXT NOT NULL,
                label      TEXT NOT NULL,
                token      TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_user_tokens_uid ON user_tokens(user_id);
        """)


def _now() -> str:
    return datetime.utcnow().isoformat()


# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------

def _gen_key() -> str:
    chars = string.ascii_uppercase + string.digits
    return "-".join("".join(random.choices(chars, k=4)) for _ in range(4))


def create_keys(count: int = 1, expires_days: int | None = None, note: str = "") -> list[str]:
    now = _now()
    expires = (datetime.utcnow() + timedelta(days=expires_days)).isoformat() if expires_days else None
    keys: list[str] = []
    with _conn() as conn:
        for _ in range(count):
            key = _gen_key()
            conn.execute(
                "INSERT INTO activation_keys (key_code, created_at, expires_at, note) VALUES (?,?,?,?)",
                (key, now, expires, note),
            )
            keys.append(key)
    return keys


def activate_key(key_code: str, user_id: str) -> dict:
    key_code = key_code.upper().strip().replace(" ", "")
    with _conn() as conn:
        row = conn.execute(
            "SELECT * FROM activation_keys WHERE key_code = ?", (key_code,)
        ).fetchone()
        if not row:
            return {"ok": False, "error": "Key không tồn tại"}
        if row["used_by"]:
            if row["used_by"] == user_id:
                return {"ok": True, "error": None}   # same user re-activates → ok
            return {"ok": False, "error": "Key đã được sử dụng"}
        if row["expires_at"] and datetime.fromisoformat(row["expires_at"]) < datetime.utcnow():
            return {"ok": False, "error": "Key đã hết hạn"}
        conn.execute(
            "UPDATE activation_keys SET used_by=?, used_at=? WHERE key_code=?",
            (user_id, _now(), key_code),
        )
    return {"ok": True, "error": None}


def is_activated(user_id: str) -> bool:
    with _conn() as conn:
        row = conn.execute(
            "SELECT expires_at FROM activation_keys WHERE used_by=?", (user_id,)
        ).fetchone()
        if not row:
            return False
        if row["expires_at"] and datetime.fromisoformat(row["expires_at"]) < datetime.utcnow():
            return False
        return True


def list_keys(limit: int = 100) -> list[dict]:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT key_code, created_at, expires_at, used_by, used_at, note "
            "FROM activation_keys ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# User token vault
# ---------------------------------------------------------------------------

def add_user_token(user_id: str, label: str, token: str) -> dict:
    tid = str(uuid.uuid4())[:8]
    with _conn() as conn:
        conn.execute(
            "INSERT INTO user_tokens (id, user_id, label, token, created_at) VALUES (?,?,?,?,?)",
            (tid, user_id, label, token, _now()),
        )
    return {"id": tid, "label": label}


def get_user_tokens(user_id: str) -> list[dict]:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT id, label, token, created_at FROM user_tokens WHERE user_id=? ORDER BY created_at DESC",
            (user_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def delete_user_token(user_id: str, token_id: str) -> bool:
    with _conn() as conn:
        cur = conn.execute(
            "DELETE FROM user_tokens WHERE id=? AND user_id=?", (token_id, user_id)
        )
        return cur.rowcount > 0
