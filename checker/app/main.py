from __future__ import annotations

import asyncio
import json
import logging
import os
import time

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from contextlib import asynccontextmanager
from pydantic import BaseModel

from app.checker import check_account, check_session_token
from app.db import (
    activate_key, create_keys, delete_key, init_db,
    is_activated, list_keys, list_users, revoke_user,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger("main")

ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "")


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    logger.info("ChatGPT Account Checker started (DB initialised)")
    yield


app = FastAPI(title="ChatGPT Account Checker", lifespan=lifespan)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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
    user_id: str
    username: str = ""


class GenerateKeysRequest(BaseModel):
    count: int = 1
    expires_days: int | None = None
    max_uses: int | None = 1   # 1 = single-use; None = unlimited
    note: str = ""


# ---------------------------------------------------------------------------
# Bot auth endpoint  (called by bot only, not by web users)
# ---------------------------------------------------------------------------

@app.post("/api/activate")
async def api_activate(req: ActivateRequest):
    result = activate_key(req.key, req.user_id, req.username)
    if result["ok"]:
        return {"ok": True, "msg": result.get("msg", "activated")}
    raise HTTPException(status_code=400, detail=result["error"])


# ---------------------------------------------------------------------------
# Checker routes  (open — no activation required on web)
# ---------------------------------------------------------------------------

@app.post("/api/check")
async def check_accounts_sse(req: CheckRequest):
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
async def check_single(req: CheckRequest):
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
# Admin API  (protected by ADMIN_SECRET)
# ---------------------------------------------------------------------------

@app.post("/api/admin/generate-keys")
async def api_generate_keys(
    req: GenerateKeysRequest,
    authorization: str | None = Header(default=None),
):
    _require_admin(authorization)
    if req.count < 1 or req.count > 500:
        raise HTTPException(status_code=400, detail="count phải từ 1 đến 500")
    keys = create_keys(
        count=req.count,
        expires_days=req.expires_days,
        max_uses=req.max_uses,
        note=req.note,
    )
    return {"keys": keys, "count": len(keys)}


@app.get("/api/admin/keys")
async def api_list_keys(authorization: str | None = Header(default=None)):
    _require_admin(authorization)
    return {"keys": list_keys()}


@app.delete("/api/admin/keys/{key_code}")
async def api_delete_key(key_code: str, authorization: str | None = Header(default=None)):
    _require_admin(authorization)
    ok = delete_key(key_code.upper())
    if not ok:
        raise HTTPException(status_code=404, detail="Key không tồn tại")
    return {"ok": True}


@app.get("/api/admin/users")
async def api_list_users(authorization: str | None = Header(default=None)):
    _require_admin(authorization)
    return {"users": list_users()}


@app.delete("/api/admin/users/{user_id}")
async def api_revoke_user(user_id: str, authorization: str | None = Header(default=None)):
    _require_admin(authorization)
    ok = revoke_user(user_id)
    if not ok:
        raise HTTPException(status_code=404, detail="User không tồn tại")
    return {"ok": True}


# ---------------------------------------------------------------------------
# Static pages
# ---------------------------------------------------------------------------

def _read_static(name: str) -> str:
    base = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")
    with open(os.path.join(base, name), "r", encoding="utf-8") as f:
        return f.read()


@app.get("/", response_class=HTMLResponse)
async def serve_ui():
    return HTMLResponse(content=_read_static("index.html"))


@app.get("/admin", response_class=HTMLResponse)
async def serve_admin():
    return HTMLResponse(content=_read_static("admin.html"))


@app.get("/health")
async def health():
    return {"status": "ok", "time": time.time()}
