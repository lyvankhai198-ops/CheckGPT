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
from app.db import activate_key, init_db, is_activated

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger("tgbot")

TOKEN = os.environ["TELEGRAM_BOT_TOKEN"]
CONCURRENCY = 3

bot = Bot(token=TOKEN)
dp = Dispatcher()

EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")

WELCOME = (
    "🔍 <b>ChatGPT Account Checker Bot</b>\n\n"
    "Gửi danh sách tài khoản để kiểm tra:\n\n"
    "<b>Email/Pass (1 dòng):</b>\n"
    "<code>email|password|totp</code>\n"
    "<code>email|password</code>\n\n"
    "<b>Email/Pass (3 dòng):</b>\n"
    "<code>email\npassword\ntotp</code>\n\n"
    "<b>Token/Session:</b>\n"
    "<code>eyJxxx...</code>\n\n"
    "<b>Lệnh:</b>\n"
    "/activate KEY — kích hoạt key\n"
    "/help — xem lại hướng dẫn"
)

NOT_ACTIVATED = (
    "🔐 Bạn chưa kích hoạt.\n\n"
    "Dùng lệnh:\n<code>/activate YOUR-KEY-HERE</code>"
)


# ---------------------------------------------------------------------------
# Helpers — user ID as string
# ---------------------------------------------------------------------------

def uid(message: Message) -> str:
    return str(message.from_user.id)


# ---------------------------------------------------------------------------
# Input parsing (same logic as before)
# ---------------------------------------------------------------------------

def _normalize_pipe(line: str) -> str:
    return re.sub(r"\s*\|\s*", "|", line.strip())


def _is_email(s: str) -> bool:
    return bool(EMAIL_RE.match(s.strip()))


def _looks_like_token(s: str) -> bool:
    s = s.strip()
    return s.startswith("eyJ") or (len(s) > 20 and "|" not in s and "@" not in s)


def parse_input(raw: str) -> tuple[str, list[dict], list[str]]:
    raw_lines = [_normalize_pipe(l) for l in raw.splitlines() if l.strip()]
    if not raw_lines:
        return "account", [], []

    has_email = any(_is_email(l.split("|")[0]) for l in raw_lines)
    if not has_email:
        tokens, errors = [], []
        for idx, line in enumerate(raw_lines, 1):
            if _looks_like_token(line):
                tokens.append({"token": line, "orig_line": idx})
            else:
                errors.append(f"Dòng {idx}: Không nhận ra định dạng — <code>{line[:60]}</code>")
        return "token", tokens, errors

    accounts, errors = [], []
    i = 0
    while i < len(raw_lines):
        line = raw_lines[i]
        parts = [p.strip() for p in line.split("|")]
        first = parts[0] if parts else ""

        if "|" in line:
            if not _is_email(first):
                errors.append(f"Dòng {i+1}: Phần trước | không phải email — <code>{line[:60]}</code>")
                i += 1
                continue
            password = parts[1] if len(parts) > 1 else ""
            totp = parts[2] if len(parts) > 2 else ""
            if not password:
                errors.append(f"Dòng {i+1}: Thiếu mật khẩu — <code>{line[:60]}</code>")
                i += 1
                continue
            accounts.append({"email": first, "password": password, "totp": totp, "orig_line": i + 1})
            i += 1

        elif _is_email(first):
            email = first
            start = i + 1
            password = totp = ""
            if i + 1 < len(raw_lines):
                nxt = raw_lines[i + 1]
                if "|" not in nxt and not _is_email(nxt.split("|")[0]):
                    password = nxt.strip()
                    i += 1
                    if i + 1 < len(raw_lines):
                        nxt2 = raw_lines[i + 1]
                        if "|" not in nxt2 and not _is_email(nxt2.split("|")[0]):
                            totp = nxt2.strip()
                            i += 1
            if not password:
                errors.append(f"Dòng {start}: Email <code>{email}</code> không có mật khẩu")
            else:
                accounts.append({"email": email, "password": password, "totp": totp, "orig_line": start})
            i += 1

        else:
            errors.append(f"Dòng {i+1}: Không nhận ra — <code>{line[:60]}</code>")
            i += 1

    return "account", accounts, errors


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------

def _mask(s: str, show: int = 2) -> str:
    return (s[:show] + "*" * max(3, len(s) - show)) if s else "—"


def _status_emoji(status: str) -> str:
    return {"live": "✅", "die": "❌", "deactivated": "🚫", "locked": "🔒"}.get(status, "❓")


def _fmt_result(r: dict, idx: int) -> str:
    emoji = _status_emoji(r.get("status", "die"))
    status = r.get("status", "die").upper()
    if r.get("status") == "live":
        plan = r.get("plan") or "Free"
        user = r.get("user") or r.get("email") or ""
        return f"{idx}. {emoji} <b>{status}</b> [{plan}] — <code>{user}</code>"
    err = r.get("error") or ""
    inp = (r.get("email") or r.get("input") or "")[:40]
    return f"{idx}. {emoji} <b>{status}</b> — <code>{inp}</code>" + (f"\n    ↳ {err}" if err else "")


def _preview_account(a: dict, idx: int) -> str:
    totp_part = f" | {_mask(a['totp'])}" if a.get("totp") else ""
    return f"{idx}. <code>{a['email']}</code> | {_mask(a['password'])}{totp_part}"


def _preview_token(t: dict, idx: int) -> str:
    tok = t["token"]
    return f"{idx}. <code>{tok[:12]}...{tok[-6:]}</code>"


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

@dp.message(CommandStart())
@dp.message(Command("help"))
async def cmd_help(message: Message):
    await message.answer(WELCOME, parse_mode="HTML")


@dp.message(Command("activate"))
async def cmd_activate(message: Message):
    parts = (message.text or "").split(maxsplit=1)
    if len(parts) < 2 or not parts[1].strip():
        await message.answer("Dùng: <code>/activate YOUR-KEY</code>", parse_mode="HTML")
        return

    key = parts[1].strip()
    result = activate_key(key, uid(message))
    if result["ok"]:
        await message.answer(
            "✅ <b>Kích hoạt thành công!</b>\nBạn có thể bắt đầu check tài khoản.",
            parse_mode="HTML",
        )
    else:
        await message.answer(f"❌ {result['error']}", parse_mode="HTML")


# ---------------------------------------------------------------------------
# Main message handler — check accounts
# ---------------------------------------------------------------------------

@dp.message(F.text)
async def handle_accounts(message: Message):
    if not is_activated(uid(message)):
        await message.answer(NOT_ACTIVATED, parse_mode="HTML")
        return

    raw = message.text.strip()
    mode, items, errors = parse_input(raw)
    total = len(items)

    if errors:
        err_text = "⚠️ <b>Dòng không hợp lệ (bỏ qua):</b>\n" + "\n".join(errors)
        await message.answer(err_text, parse_mode="HTML")

    if total == 0:
        if not errors:
            await message.answer("❌ Không nhận diện được tài khoản. /help để xem hướng dẫn.", parse_mode="HTML")
        return

    mode_label = "Email/Pass" if mode == "account" else "Token/Session"
    preview_lines = [
        _preview_account(a, i + 1) if mode == "account" else _preview_token(a, i + 1)
        for i, a in enumerate(items)
    ]
    status_msg = await message.answer(
        f"📋 <b>Đã nhận diện {total} tài khoản</b> (mode: <b>{mode_label}</b>):\n"
        + "\n".join(preview_lines) + "\n\n⏳ Đang kiểm tra...",
        parse_mode="HTML",
    )

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

            done = [_fmt_result(results[i], i + 1) for i in range(total) if i in results]
            pending = total - completed
            text = "\n".join(done)
            if pending > 0:
                text += f"\n\n⏳ Còn lại: {pending}/{total}..."
            try:
                await status_msg.edit_text(text, parse_mode="HTML")
            except Exception:
                pass

    await asyncio.gather(*[asyncio.create_task(process(i, item)) for i, item in enumerate(items)])

    summary = "\n".join(_fmt_result(results[i], i + 1) for i in range(total))
    summary += f"\n\n📊 <b>Tổng:</b> {total} | ✅ Live: {live_count} | ❌ Die: {total - live_count}"
    try:
        await status_msg.edit_text(summary, parse_mode="HTML")
    except Exception:
        await message.answer(summary, parse_mode="HTML")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def main():
    init_db()
    logger.info("Telegram bot starting...")
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
