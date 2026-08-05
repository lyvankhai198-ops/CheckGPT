from __future__ import annotations

import asyncio
import logging
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from aiogram import Bot, Dispatcher, F
from aiogram.filters import CommandStart, Command
from aiogram.types import Message

from app.checker import check_account, check_session_token

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger("tgbot")

TOKEN = os.environ["TELEGRAM_BOT_TOKEN"]
CONCURRENCY = 3

bot = Bot(token=TOKEN)
dp = Dispatcher()

EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")

WELCOME = (
    "🔍 <b>ChatGPT Account Checker Bot</b>\n\n"
    "Gửi danh sách tài khoản, mỗi dòng một tài khoản:\n\n"
    "<b>Mode Email/Pass (1 dòng):</b>\n"
    "<code>email|password|totp_secret</code>\n"
    "<code>email|password</code>\n\n"
    "<b>Mode Email/Pass (3 dòng):</b>\n"
    "<code>email\npassword\ntotp_secret</code>\n\n"
    "<b>Mode Token/Session:</b>\n"
    "<code>eyJxxx...</code>  (JWT Bearer)\n"
    "<code>session_token_value</code>\n\n"
    "/help — xem hướng dẫn lại"
)


# ---------------------------------------------------------------------------
# Input parsing
# ---------------------------------------------------------------------------

def _normalize_pipe_spaces(line: str) -> str:
    """Remove spaces around | so 'a | b | c' becomes 'a|b|c'."""
    return re.sub(r"\s*\|\s*", "|", line.strip())


def _is_email(s: str) -> bool:
    return bool(EMAIL_RE.match(s.strip()))


def _looks_like_token(s: str) -> bool:
    """Heuristic: JWT (starts with eyJ) or long opaque string (no @ and no |)."""
    s = s.strip()
    return (s.startswith("eyJ") or (len(s) > 20 and "|" not in s and "@" not in s))


def parse_input(raw: str) -> tuple[str, list[dict], list[str]]:
    """
    Detect mode and parse input.

    Returns:
        mode: "account" | "token"
        accounts: list of dicts with keys email/password/totp (account mode)
                  or token (token mode)
        errors: list of human-readable error strings
    """
    # --- Step 1: split into non-empty lines, normalize pipe spaces ---
    raw_lines = [_normalize_pipe_spaces(l) for l in raw.splitlines() if l.strip()]

    if not raw_lines:
        return "account", [], []

    # --- Step 2: quick mode detection ---
    # If any line contains an @ sign, treat as account mode.
    has_email_line = any(_is_email(l.split("|")[0]) for l in raw_lines)
    if not has_email_line:
        # Token mode: every non-empty line is a token
        tokens = []
        errors = []
        for idx, line in enumerate(raw_lines, 1):
            if _looks_like_token(line):
                tokens.append({"token": line, "orig_line": idx})
            else:
                errors.append(f"Dòng {idx}: Không nhận ra định dạng — <code>{line[:60]}</code>")
        return "token", tokens, errors

    # --- Step 3: Account mode – group lines into accounts ---
    accounts: list[dict] = []
    errors: list[str] = []

    i = 0
    while i < len(raw_lines):
        line = raw_lines[i]
        parts = [p.strip() for p in line.split("|")]
        first = parts[0] if parts else ""

        # Case A: line has pipes → try to parse as single-line account
        if "|" in line:
            if not _is_email(first):
                errors.append(
                    f"Dòng {i+1}: Phần trước dấu | không phải email — "
                    f"<code>{line[:60]}</code>"
                )
                i += 1
                continue

            email = first
            password = parts[1] if len(parts) > 1 else ""
            totp = parts[2] if len(parts) > 2 else ""

            if not password:
                errors.append(f"Dòng {i+1}: Thiếu mật khẩu — <code>{line[:60]}</code>")
                i += 1
                continue

            accounts.append({"email": email, "password": password, "totp": totp, "orig_line": i + 1})
            i += 1

        # Case B: line is just an email → try to consume next 1–2 lines as pass/totp
        elif _is_email(first):
            email = first
            start_line = i + 1
            password = ""
            totp = ""

            # consume next line as password (if it's not an email and has no pipe)
            if i + 1 < len(raw_lines):
                nxt = raw_lines[i + 1]
                if "|" not in nxt and not _is_email(nxt.split("|")[0]):
                    password = nxt.strip()
                    i += 1

                    # consume the line after as totp (same conditions)
                    if i + 1 < len(raw_lines):
                        nxt2 = raw_lines[i + 1]
                        if "|" not in nxt2 and not _is_email(nxt2.split("|")[0]):
                            totp = nxt2.strip()
                            i += 1

            if not password:
                errors.append(
                    f"Dòng {start_line}: Email <code>{email}</code> không có mật khẩu kèm theo"
                )
            else:
                accounts.append({"email": email, "password": password, "totp": totp, "orig_line": start_line})

            i += 1

        # Case C: not an email, no pipe → unrecognized
        else:
            errors.append(
                f"Dòng {i+1}: Không nhận ra định dạng — <code>{line[:60]}</code>"
            )
            i += 1

    return "account", accounts, errors


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def _mask(s: str, show: int = 2) -> str:
    if not s:
        return "—"
    return s[:show] + "*" * max(3, len(s) - show)


def _preview_account(a: dict, idx: int) -> str:
    totp_part = f" | {_mask(a['totp'])}" if a.get("totp") else ""
    return f"{idx}. <code>{a['email']}</code> | {_mask(a['password'])}{totp_part}"


def _preview_token(t: dict, idx: int) -> str:
    tok = t["token"]
    return f"{idx}. <code>{tok[:12]}...{tok[-6:]}</code>"


def _status_emoji(status: str) -> str:
    return {"live": "✅", "die": "❌", "deactivated": "🚫", "locked": "🔒"}.get(status, "❓")


def _format_result(r: dict, idx: int) -> str:
    emoji = _status_emoji(r.get("status", "die"))
    status = r.get("status", "die").upper()
    if r.get("status") == "live":
        plan = r.get("plan") or "Free"
        user = r.get("user") or r.get("email") or ""
        return f"{idx}. {emoji} <b>{status}</b> [{plan}] — <code>{user}</code>"
    else:
        err = r.get("error") or ""
        inp = (r.get("email") or r.get("input") or "")[:40]
        return f"{idx}. {emoji} <b>{status}</b> — <code>{inp}</code>" + (f"\n    ↳ {err}" if err else "")


# ---------------------------------------------------------------------------
# Bot handlers
# ---------------------------------------------------------------------------

@dp.message(CommandStart())
@dp.message(Command("help"))
async def cmd_start(message: Message):
    await message.answer(WELCOME, parse_mode="HTML")


@dp.message(F.text)
async def handle_accounts(message: Message):
    raw = message.text.strip()
    if not raw:
        return

    mode, items, errors = parse_input(raw)
    total = len(items)

    # --- Show parse errors first ---
    if errors:
        err_text = "⚠️ <b>Dòng không hợp lệ (bỏ qua):</b>\n" + "\n".join(errors)
        await message.answer(err_text, parse_mode="HTML")

    if total == 0:
        if not errors:
            await message.answer("❌ Không nhận diện được tài khoản nào. Gửi /help để xem hướng dẫn.", parse_mode="HTML")
        return

    # --- Preview: show what was recognized, mask sensitive fields ---
    mode_label = "Email/Pass" if mode == "account" else "Token/Session"
    if mode == "account":
        preview_lines = [_preview_account(a, i + 1) for i, a in enumerate(items)]
    else:
        preview_lines = [_preview_token(t, i + 1) for i, t in enumerate(items)]

    preview_text = (
        f"📋 <b>Đã nhận diện {total} tài khoản</b> (mode: <b>{mode_label}</b>):\n"
        + "\n".join(preview_lines)
        + "\n\n⏳ Đang kiểm tra..."
    )
    status_msg = await message.answer(preview_text, parse_mode="HTML")

    # --- Run checks concurrently ---
    semaphore = asyncio.Semaphore(CONCURRENCY)
    results: dict[int, dict] = {}
    completed = 0
    live_count = 0

    async def process(idx: int, item: dict):
        nonlocal completed, live_count
        async with semaphore:
            if mode == "account":
                r = await check_account(item["email"], item["password"], item.get("totp", ""))
            else:
                r = await check_session_token(item["token"])

            results[idx] = r
            completed += 1
            if r.get("status") == "live":
                live_count += 1

            done_lines = [_format_result(results[i], i + 1) for i in range(total) if i in results]
            pending = total - completed
            progress = "\n".join(done_lines)
            if pending > 0:
                progress += f"\n\n⏳ Còn lại: {pending}/{total}..."

            try:
                await status_msg.edit_text(progress, parse_mode="HTML")
            except Exception:
                pass

    await asyncio.gather(*[asyncio.create_task(process(i, item)) for i, item in enumerate(items)])

    # --- Final summary ---
    die_count = total - live_count
    summary = "\n".join(_format_result(results[i], i + 1) for i in range(total))
    summary += f"\n\n📊 <b>Tổng:</b> {total} | ✅ Live: {live_count} | ❌ Die: {die_count}"

    try:
        await status_msg.edit_text(summary, parse_mode="HTML")
    except Exception:
        await message.answer(summary, parse_mode="HTML")


async def main():
    logger.info("Telegram bot starting...")
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
