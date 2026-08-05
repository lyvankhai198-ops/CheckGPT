"""SQLite database for bot activation keys and user management."""
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
                key_code   TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                expires_at TEXT,
                max_uses   INTEGER,
                use_count  INTEGER NOT NULL DEFAULT 0,
                note       TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS bot_users (
                user_id      TEXT PRIMARY KEY,
                username     TEXT,
                key_code     TEXT NOT NULL,
                activated_at TEXT NOT NULL,
                FOREIGN KEY (key_code) REFERENCES activation_keys(key_code)
            );
        """)
        # Migrations — add columns added after initial deploy (safe to re-run)
        for sql in [
            "ALTER TABLE activation_keys ADD COLUMN max_uses INTEGER",
            "ALTER TABLE activation_keys ADD COLUMN use_count INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE activation_keys ADD COLUMN note TEXT DEFAULT ''",
        ]:
            try:
                conn.execute(sql)
            except Exception:
                pass  # column already exists


def _now() -> str:
    return datetime.utcnow().isoformat()


# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------

def _gen_key() -> str:
    chars = string.ascii_uppercase + string.digits
    return "-".join("".join(random.choices(chars, k=4)) for _ in range(4))


def create_keys(count: int = 1, expires_minutes: int | None = None,
                max_uses: int | None = 1, note: str = "") -> list[str]:
    """Generate activation keys.

    max_uses=1       → single-use (one user per key, default)
    max_uses=N       → up to N users can activate with the same key
    max_uses=None    → unlimited uses
    expires_minutes  → None = never expires; otherwise expires after N minutes
    """
    now = _now()
    expires = (datetime.utcnow() + timedelta(minutes=expires_minutes)).isoformat() if expires_minutes else None
    keys: list[str] = []
    with _conn() as conn:
        for _ in range(count):
            key = _gen_key()
            conn.execute(
                "INSERT INTO activation_keys (key_code, created_at, expires_at, max_uses, note) VALUES (?,?,?,?,?)",
                (key, now, expires, max_uses, note),
            )
            keys.append(key)
    return keys


def activate_key(key_code: str, user_id: str, username: str = "") -> dict:
    """Activate a key for a Telegram user."""
    key_code = key_code.upper().strip().replace(" ", "")
    with _conn() as conn:
        # If user already activated any key → check if still valid
        existing = conn.execute(
            "SELECT k.expires_at FROM bot_users u "
            "JOIN activation_keys k ON u.key_code = k.key_code "
            "WHERE u.user_id = ?", (user_id,)
        ).fetchone()
        if existing:
            if existing["expires_at"] and datetime.fromisoformat(existing["expires_at"]) < datetime.utcnow():
                # Expired — allow re-activation with new key (fall through)
                conn.execute("DELETE FROM bot_users WHERE user_id = ?", (user_id,))
            else:
                return {"ok": True, "msg": "already_active"}

        row = conn.execute(
            "SELECT * FROM activation_keys WHERE key_code = ?", (key_code,)
        ).fetchone()
        if not row:
            return {"ok": False, "error": "Key không tồn tại"}
        if row["expires_at"] and datetime.fromisoformat(row["expires_at"]) < datetime.utcnow():
            return {"ok": False, "error": "Key đã hết hạn"}
        max_uses = row["max_uses"]
        use_count = row["use_count"]
        if max_uses is not None and use_count >= max_uses:
            return {"ok": False, "error": "Key đã đạt giới hạn sử dụng"}

        conn.execute(
            "INSERT INTO bot_users (user_id, username, key_code, activated_at) VALUES (?,?,?,?)",
            (user_id, username or "", key_code, _now()),
        )
        conn.execute(
            "UPDATE activation_keys SET use_count = use_count + 1 WHERE key_code = ?",
            (key_code,),
        )
    return {"ok": True, "msg": "activated"}


def is_activated(user_id: str) -> bool:
    with _conn() as conn:
        row = conn.execute(
            "SELECT k.expires_at FROM bot_users u "
            "JOIN activation_keys k ON u.key_code = k.key_code "
            "WHERE u.user_id = ?",
            (user_id,),
        ).fetchone()
        if not row:
            return False
        if row["expires_at"] and datetime.fromisoformat(row["expires_at"]) < datetime.utcnow():
            return False
        return True


def revoke_user(user_id: str) -> bool:
    with _conn() as conn:
        cur = conn.execute("DELETE FROM bot_users WHERE user_id = ?", (user_id,))
        return cur.rowcount > 0


def list_keys(limit: int = 200) -> list[dict]:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT key_code, created_at, expires_at, max_uses, use_count, note "
            "FROM activation_keys ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]


def list_users(limit: int = 500) -> list[dict]:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT u.user_id, u.username, u.key_code, u.activated_at, "
            "       k.expires_at, k.note "
            "FROM bot_users u "
            "JOIN activation_keys k ON u.key_code = k.key_code "
            "ORDER BY u.activated_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            if d["expires_at"] and datetime.fromisoformat(d["expires_at"]) < datetime.utcnow():
                d["status"] = "expired"
            else:
                d["status"] = "active"
            result.append(d)
        return result


def delete_key(key_code: str) -> bool:
    with _conn() as conn:
        # Also remove users that used this key
        conn.execute("DELETE FROM bot_users WHERE key_code = ?", (key_code,))
        cur = conn.execute("DELETE FROM activation_keys WHERE key_code = ?", (key_code,))
        return cur.rowcount > 0
