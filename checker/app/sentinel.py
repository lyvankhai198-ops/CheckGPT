from __future__ import annotations

import base64
import json
import logging
import random
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Final

_SENTINEL_REQ_URL: Final[str] = "https://sentinel.openai.com/backend-api/sentinel/req"
_SENTINEL_REFERER: Final[str] = "https://sentinel.openai.com/backend-api/sentinel/frame.html"
_SENTINEL_SDK_URL: Final[str] = "https://sentinel.openai.com/sentinel/20260124ceb8/sdk.js"
_MAX_POW_ATTEMPTS: Final[int] = 500_000
_ERROR_PREFIX: Final[str] = "wQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D"
_SENTINEL_UA: Final[str] = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"
)

_NAV_PROPS: Final[tuple[str, ...]] = (
    "vendorSub", "productSub", "vendor", "maxTouchPoints", "scheduling",
    "userActivation", "doNotTrack", "geolocation", "connection", "plugins",
    "mimeTypes", "pdfViewerEnabled", "webkitTemporaryStorage",
    "webkitPersistentStorage", "hardwareConcurrency", "cookieEnabled",
    "credentials", "mediaDevices", "permissions", "locks", "ink",
)
_CHOICE_12: Final[tuple[str, ...]] = (
    "location", "implementation", "URL", "documentURI", "compatMode",
)
_CHOICE_13: Final[tuple[str, ...]] = (
    "Object", "Function", "Array", "Number", "parseFloat", "undefined",
)
_CHOICE_17: Final[tuple[int, ...]] = (4, 8, 12, 16)


def _fnv1a_32(text: str) -> str:
    h = 2166136261
    for ch in text:
        h ^= ord(ch)
        h = (h * 16777619) & 0xFFFFFFFF
    h ^= h >> 16
    h = (h * 2246822507) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * 3266489909) & 0xFFFFFFFF
    h ^= h >> 16
    return f"{h:08x}"


def _b64_encode_config(config: list[Any]) -> str:
    raw = json.dumps(config, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def _build_config(user_agent: str) -> list[Any]:
    now = datetime.now(timezone.utc)
    date_str = now.strftime("%a %b %d %Y %H:%M:%S GMT+0000 (Coordinated Universal Time)")
    perf_now = random.uniform(1000.0, 50000.0)
    time_origin = (now.timestamp() * 1000.0) - perf_now
    nav_prop = random.choice(_NAV_PROPS)
    sid = str(uuid.uuid4())

    return [
        "1920x1080",
        date_str,
        4_294_705_152,
        random.random(),
        user_agent,
        _SENTINEL_SDK_URL,
        None,
        None,
        "en-US",
        "en-US,en",
        random.random(),
        f"{nav_prop}\u2212undefined",
        random.choice(_CHOICE_12),
        random.choice(_CHOICE_13),
        perf_now,
        sid,
        "",
        random.choice(_CHOICE_17),
        time_origin,
    ]


def _solve_pow(seed: str, difficulty: str, user_agent: str) -> str:
    config = _build_config(user_agent)
    start = time.perf_counter()
    dlen = len(difficulty)

    for nonce in range(_MAX_POW_ATTEMPTS):
        config[3] = nonce
        config[9] = int((time.perf_counter() - start) * 1000)
        encoded = _b64_encode_config(config)
        digest = _fnv1a_32(seed + encoded)
        if dlen <= len(digest) and digest[:dlen] <= difficulty:
            return f"gAAAAAB{encoded}~S"

    none_b64 = base64.b64encode(b'"None"').decode("ascii")
    return f"gAAAAAB{_ERROR_PREFIX}{none_b64}"


def _generate_requirements_token(user_agent: str) -> str:
    config = _build_config(user_agent)
    config[3] = 1
    config[9] = int(random.uniform(5, 50))
    return f"gAAAAAC{_b64_encode_config(config)}"


async def _fetch_challenge(
    http_client: Any,
    device_id: str,
    flow: str,
    request_p: str,
    logger: logging.Logger,
) -> dict[str, Any] | None:
    body = json.dumps({"p": request_p, "id": device_id, "flow": flow})
    headers = {
        "Accept": "*/*",
        "Referer": _SENTINEL_REFERER,
        "Origin": "https://sentinel.openai.com",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "Content-Type": "text/plain;charset=UTF-8",
    }
    try:
        response = await http_client.post(_SENTINEL_REQ_URL, data=body, headers=headers)
    except Exception as exc:
        logger.info("[sentinel] /req transport error: %s", exc)
        return None

    if response.status_code != 200:
        logger.info("[sentinel] /req HTTP %s", response.status_code)
        return None

    try:
        return response.json()
    except ValueError as exc:
        logger.info("[sentinel] /req invalid JSON: %s", exc)
        return None


async def get_sentinel_token(
    http_client: Any,
    device_id: str,
    flow: str,
    logger: logging.Logger,
) -> str:
    did = device_id or str(uuid.uuid4())
    req_p = _generate_requirements_token(_SENTINEL_UA)

    challenge = await _fetch_challenge(http_client, did, flow, req_p, logger)
    if challenge is None:
        logger.info("[sentinel] challenge fetch failed → fallback token")
        return json.dumps({"p": req_p, "t": "", "c": "", "id": did, "flow": flow})

    c_value = (challenge.get("token") or "").strip()
    pow_info = challenge.get("proofofwork") or {}
    required = bool(pow_info.get("required"))
    seed = pow_info.get("seed") or ""

    if required and seed:
        difficulty = pow_info.get("difficulty") or "0"
        p_value = _solve_pow(seed, difficulty, _SENTINEL_UA)
    else:
        p_value = req_p

    token = json.dumps({"p": p_value, "t": "", "c": c_value, "id": did, "flow": flow})
    logger.info("[sentinel] token built (PoW, len=%d)", len(token))
    return token


__all__ = ["get_sentinel_token"]
