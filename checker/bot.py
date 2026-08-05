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
    "<b>Mode Email/Pass:</b>\n"
    "<code>email|password</code>\n"
    "<code>email|password|totp_secret</code>\n\n"
    "<b>Mode Token/Session:</b>\n"
    "<code>eyJxxx...</code>  (JWT Bearer)\n"
    "<code>session_token_value</code>\n\n"
    "Bot tự nhận biết mode dựa trên định dạng.\n"
    "/help — xem hướng dẫn lại"
)


def _detect_mode(lines: list[str]) -> str:
    """Auto-detect: if any line has @ and |, treat as account mode."""
    for line in lines:
        parts = line.split("|")
        if len(parts) >= 2 and EMAIL_RE.match(parts[0].strip()):
            return "account"
    return "token"


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


@dp.message(CommandStart())
@dp.message(Command("help"))
async def cmd_start(message: Message):
    await message.answer(WELCOME, parse_mode="HTML")


@dp.message(F.text)
async def handle_accounts(message: Message):
    raw = message.text.strip()
    lines = [l.strip() for l in raw.splitlines() if l.strip()]

    if not lines:
        return

    mode = _detect_mode(lines)
    total = len(lines)

    status_msg = await message.answer(
        f"⏳ Đang kiểm tra <b>{total}</b> tài khoản (mode: <b>{'Email/Pass' if mode == 'account' else 'Token'}</b>)...",
        parse_mode="HTML",
    )

    semaphore = asyncio.Semaphore(CONCURRENCY)
    results: dict[int, dict] = {}
    completed = 0
    live_count = 0

    async def process(idx: int, line: str):
        nonlocal completed, live_count
        async with semaphore:
            if mode == "account":
                parts = [p.strip() for p in line.split("|")]
                if len(parts) >= 3:
                    r = await check_account(parts[0], parts[1], parts[2])
                elif len(parts) == 2:
                    r = await check_account(parts[0], parts[1], "")
                else:
                    r = {"input": line[:50], "status": "die", "error": "Sai định dạng (cần email|pass)", "email": None, "user": None, "plan": None}
            else:
                r = await check_session_token(line)

            results[idx] = r
            completed += 1
            if r.get("status") == "live":
                live_count += 1

            # Update progress every result
            done_lines = [_format_result(results[i], i + 1) for i in range(total) if i in results]
            pending = total - completed
            progress_text = "\n".join(done_lines)
            if pending > 0:
                progress_text += f"\n\n⏳ Còn lại: {pending}/{total}..."

            try:
                await status_msg.edit_text(progress_text, parse_mode="HTML")
            except Exception:
                pass

    tasks = [asyncio.create_task(process(i, line)) for i, line in enumerate(lines)]
    await asyncio.gather(*tasks)

    # Final summary
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
