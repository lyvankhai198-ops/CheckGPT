from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel

from app.checker import check_account, check_session_token
from app.db import (
    activate_key, add_user_token, create_keys, delete_user_token,
    get_user_tokens, init_db, is_activated, list_keys,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger("main")

EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "")


# ---------------------------------------------------------------------------
# App lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    logger.info("ChatGPT Account Checker started (DB initialised)")
    yield
    logger.info("Shutting down")


app = FastAPI(title="ChatGPT Account Checker", lifespan=lifespan)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_session_id(x_session_id: str | None) -> str | None:
    return (x_session_id or "").strip() or None


def _require_session(x_session_id: str | None) -> str:
    sid = _get_session_id(x_session_id)
    if not sid:
        raise HTTPException(status_code=401, detail="Thiếu X-Session-ID header")
    if not is_activated(sid):
        raise HTTPException(status_code=403, detail="Chưa kích hoạt. Vui lòng nhập key.")
    return sid


def _require_admin(authorization: str | None) -> None:
    if not ADMIN_SECRET:
        raise HTTPException(status_code=503, detail="ADMIN_SECRET chưa được cấu hình")
    token = (authorization or "").removeprefix("Bearer ").strip()
    if token != ADMIN_SECRET:
        raise HTTPException(status_code=401, detail="Sai admin secret")


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class CheckRequest(BaseModel):
    mode: str
    raw_text: str
    concurrency: int = 3


class ActivateRequest(BaseModel):
    key: str
    session_id: str


class TokenSaveRequest(BaseModel):
    label: str
    token: str


class GenerateKeysRequest(BaseModel):
    count: int = 1
    expires_days: int | None = None
    note: str = ""


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@app.post("/api/activate")
async def api_activate(req: ActivateRequest):
    result = activate_key(req.key, req.session_id)
    if result["ok"]:
        return {"ok": True}
    raise HTTPException(status_code=400, detail=result["error"])


@app.get("/api/session")
async def api_session(x_session_id: str | None = Header(default=None)):
    sid = _get_session_id(x_session_id)
    if not sid:
        return {"activated": False}
    return {"activated": is_activated(sid)}


# ---------------------------------------------------------------------------
# My Tokens routes
# ---------------------------------------------------------------------------

@app.get("/api/my-tokens")
async def api_list_tokens(x_session_id: str | None = Header(default=None)):
    sid = _require_session(x_session_id)
    tokens = get_user_tokens(sid)
    # Never expose the full token to the list view — show only prefix
    safe = [
        {"id": t["id"], "label": t["label"],
         "preview": t["token"][:16] + "...", "created_at": t["created_at"]}
        for t in tokens
    ]
    return {"tokens": safe}


@app.post("/api/my-tokens")
async def api_save_token(req: TokenSaveRequest, x_session_id: str | None = Header(default=None)):
    sid = _require_session(x_session_id)
    if not req.label.strip():
        raise HTTPException(status_code=400, detail="Nhãn không được để trống")
    if not req.token.strip():
        raise HTTPException(status_code=400, detail="Token không được để trống")
    result = add_user_token(sid, req.label.strip(), req.token.strip())
    return result


@app.delete("/api/my-tokens/{token_id}")
async def api_delete_token(token_id: str, x_session_id: str | None = Header(default=None)):
    sid = _require_session(x_session_id)
    ok = delete_user_token(sid, token_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Không tìm thấy token")
    return {"ok": True}


@app.post("/api/my-tokens/{token_id}/use")
async def api_use_token(token_id: str, x_session_id: str | None = Header(default=None)):
    """Return the full token value for use in the checker."""
    sid = _require_session(x_session_id)
    tokens = get_user_tokens(sid)
    for t in tokens:
        if t["id"] == token_id:
            return {"token": t["token"]}
    raise HTTPException(status_code=404, detail="Không tìm thấy token")


# ---------------------------------------------------------------------------
# Admin routes
# ---------------------------------------------------------------------------

@app.post("/api/admin/generate-keys")
async def api_generate_keys(
    req: GenerateKeysRequest,
    authorization: str | None = Header(default=None),
):
    _require_admin(authorization)
    if req.count < 1 or req.count > 500:
        raise HTTPException(status_code=400, detail="count phải từ 1 đến 500")
    keys = create_keys(count=req.count, expires_days=req.expires_days, note=req.note)
    return {"keys": keys, "count": len(keys)}


@app.get("/api/admin/keys")
async def api_list_keys(
    authorization: str | None = Header(default=None),
):
    _require_admin(authorization)
    return {"keys": list_keys()}


# ---------------------------------------------------------------------------
# Checker routes  (require activation)
# ---------------------------------------------------------------------------

@app.post("/api/check")
async def check_accounts_sse(req: CheckRequest, x_session_id: str | None = Header(default=None)):
    _require_session(x_session_id)

    lines = [l.strip() for l in req.raw_text.strip().splitlines() if l.strip()]
    if not lines:
        return {"error": "no input", "results": []}

    async def event_stream():
        yield f"data: {json.dumps({'type': 'start', 'total': len(lines)})}\n\n"

        semaphore = asyncio.Semaphore(req.concurrency)
        results = []
        completed = 0

        async def process_line(index: int, line: str):
            nonlocal completed
            async with semaphore:
                if req.mode == "account":
                    parts = [p.strip() for p in line.split("|")]
                    if len(parts) >= 3:
                        result = await check_account(parts[0], parts[1], parts[2])
                    elif len(parts) == 2:
                        result = await check_account(parts[0], parts[1], "")
                    else:
                        result = {
                            "input": line[:50], "status": "error",
                            "error": "invalid format (need email|pass|2fa)",
                            "email": None, "user": None, "plan": None,
                        }
                else:
                    result = await check_session_token(line)

                result["index"] = index
                completed += 1
                result["completed"] = completed
                results.append(result)
                return result

        tasks = [asyncio.create_task(process_line(i, line)) for i, line in enumerate(lines)]
        for coro in asyncio.as_completed(tasks):
            result = await coro
            yield f"data: {json.dumps({'type': 'result', 'data': result})}\n\n"

        live_count = sum(1 for r in results if r.get("status") == "live")
        die_count = len(results) - live_count
        yield f"data: {json.dumps({'type': 'done', 'total': len(results), 'live': live_count, 'die': die_count})}\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@app.post("/api/check-single")
async def check_single(req: CheckRequest, x_session_id: str | None = Header(default=None)):
    _require_session(x_session_id)

    lines = [l.strip() for l in req.raw_text.strip().splitlines() if l.strip()]
    if not lines:
        return {"error": "no input"}
    line = lines[0]
    if req.mode == "account":
        parts = [p.strip() for p in line.split("|")]
        if len(parts) >= 3:
            return await check_account(parts[0], parts[1], parts[2])
        elif len(parts) == 2:
            return await check_account(parts[0], parts[1], "")
        return {"error": "invalid format"}
    return await check_session_token(line)


# ---------------------------------------------------------------------------
# Static / UI
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def serve_ui():
    import sys
    if getattr(sys, "frozen", False):
        import os as _os
        base_dir = getattr(sys, "_MEIPASS", _os.path.dirname(_os.path.abspath(__file__)))
        static_path = _os.path.join(base_dir, "static", "index.html")
    else:
        static_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static", "index.html")
    with open(static_path, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


@app.get("/health")
async def health():
    return {"status": "ok", "time": time.time()}
