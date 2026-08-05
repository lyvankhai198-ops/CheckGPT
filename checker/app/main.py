from __future__ import annotations

import asyncio
import json
import logging
import re
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from app.checker import check_account, check_session_token

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger("main")

EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
BASE32_RE = re.compile(r"^[A-Z2-7]+=*$", re.I)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("ChatGPT Account Checker started")
    yield
    logger.info("Shutting down")


app = FastAPI(title="ChatGPT Account Checker", lifespan=lifespan)


class CheckRequest(BaseModel):
    mode: str
    raw_text: str
    concurrency: int = 3


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
                        email, password, totp = parts[0], parts[1], parts[2]
                        result = await check_account(email, password, totp)
                    elif len(parts) == 2:
                        email, password = parts[0], parts[1]
                        result = await check_account(email, password, "")
                    else:
                        result = {
                            "input": line[:50],
                            "status": "error",
                            "error": "invalid format (need email|pass|2fa)",
                            "email": None,
                            "user": None,
                            "plan": None,
                        }
                else:
                    result = await check_session_token(line)

                result["index"] = index
                completed += 1
                result["completed"] = completed
                results.append(result)
                return result

        tasks = []
        for i, line in enumerate(lines):
            task = asyncio.create_task(process_line(i, line))
            tasks.append(task)

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
            result = await check_account(parts[0], parts[1], parts[2])
        elif len(parts) == 2:
            result = await check_account(parts[0], parts[1], "")
        else:
            return {"error": "invalid format"}
    else:
        result = await check_session_token(line)

    return result


@app.get("/", response_class=HTMLResponse)
async def serve_ui():
    import os, sys
    if getattr(sys, 'frozen', False):
        base_dir = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
        static_path = os.path.join(base_dir, "static", "index.html")
    else:
        static_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static", "index.html")
    with open(static_path, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


@app.get("/health")
async def health():
    return {"status": "ok", "time": time.time()}
