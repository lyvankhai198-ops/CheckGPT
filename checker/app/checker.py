from __future__ import annotations

import asyncio
import logging
import re
import time
import uuid
from typing import Any, Final
from urllib.parse import urljoin

import pyotp
from curl_cffi.requests import AsyncSession

from app.sentinel import get_sentinel_token

logger = logging.getLogger("checker")

IMPERSONATE = "chrome136"

_CHATGPT_BASE: Final[str] = "https://chatgpt.com"
_AUTH_BASE: Final[str] = "https://auth.openai.com"

_URL_AUTH_LOGIN: Final[str] = f"{_CHATGPT_BASE}/auth/login"
_URL_CSRF: Final[str] = f"{_CHATGPT_BASE}/api/auth/csrf"
_URL_SIGNIN_OPENAI: Final[str] = f"{_CHATGPT_BASE}/api/auth/signin/openai"
_URL_SESSION: Final[str] = f"{_CHATGPT_BASE}/api/auth/session"

_URL_AUTHORIZE_CONTINUE: Final[str] = f"{_AUTH_BASE}/api/accounts/authorize/continue"
_URL_PASSWORD_VERIFY: Final[str] = f"{_AUTH_BASE}/api/accounts/password/verify"
_URL_MFA_ISSUE: Final[str] = f"{_AUTH_BASE}/api/accounts/mfa/issue_challenge"
_URL_MFA_VERIFY: Final[str] = f"{_AUTH_BASE}/api/accounts/mfa/verify"

_MFA_CHALLENGE_RE: Final[re.Pattern[str]] = re.compile(r"/mfa-challenge/([a-f0-9]+)")
_MAX_REDIRECT_HOPS: Final[int] = 12
_CALLBACK_VERIFY_ATTEMPTS: Final[int] = 3
_HTTP_RETRY_ATTEMPTS: Final[int] = 3
_SESSION_TOKEN_COOKIE_BASE: Final[str] = "__Secure-next-auth.session-token"

_KEYWORDS_ACCOUNT_DEACTIVATED: Final[tuple[str, ...]] = (
    "deleted or deactivated",
    "has been deactivated",
    "does not have an account",
)


class LoginError(Exception):
    def __init__(self, code: str = "", reason: str | None = None, message: str = "") -> None:
        self.code = code or (reason or "login_network_error")
        self.reason = reason or code or "login_network_error"
        super().__init__(message or self.code)


def _nav_headers(referer: str, fetch_site: str) -> dict[str, str]:
    return {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9,nl;q=0.8",
        "Referer": referer,
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": fetch_site,
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
    }


def _json_headers(referer: str, origin: str) -> dict[str, str]:
    return {
        "Accept": "application/json",
        "Accept-Language": "en-US,en;q=0.9,nl;q=0.8",
        "Referer": referer,
        "Origin": origin,
    }


def _has_session_token(client: Any) -> bool:
    for c in client.cookies.jar:
        if c.name == _SESSION_TOKEN_COOKIE_BASE and c.value:
            return True
        if c.name == f"{_SESSION_TOKEN_COOKIE_BASE}.0" and c.value:
            return True
    return False


def _first_cookie(client: Any, name: str) -> str | None:
    for c in client.cookies.jar:
        if c.name == name and c.value:
            return c.value
    return None


def _short(s: str, n: int = 200) -> str:
    return s if len(s) <= n else s[:n] + "…"


async def _get_follow(client: Any, url: str, headers: dict, max_hops: int = _MAX_REDIRECT_HOPS) -> tuple[Any, str]:
    current = url
    for _ in range(max_hops):
        response = await client.get(current, headers=headers, allow_redirects=False)
        if response.status_code in (301, 302, 303, 307, 308):
            location = response.headers.get("location")
            if not location:
                break
            current = urljoin(current, location)
            continue
        return response, current
    raise LoginError(reason="network_error")


async def _prime(client: Any) -> None:
    if _first_cookie(client, "__cf_bm"):
        return
    logger.info("[login] [0/9] prime chatgpt.com")
    headers = _nav_headers(f"{_CHATGPT_BASE}/", "same-origin")
    for attempt in range(_HTTP_RETRY_ATTEMPTS):
        try:
            r = await client.get(_URL_AUTH_LOGIN, headers=headers, allow_redirects=True)
            if r.status_code < 400:
                return
            if r.status_code == 403 and attempt < _HTTP_RETRY_ATTEMPTS - 1:
                await asyncio.sleep((attempt + 1) * 5.0)
                continue
            return
        except Exception as e:
            logger.warning("[login] prime error: %s", e)
            if attempt < _HTTP_RETRY_ATTEMPTS - 1:
                await asyncio.sleep(2)
                continue
            raise LoginError(reason="network_error") from e


async def _get_csrf(client: Any) -> str:
    logger.info("[login] [1/9] CSRF token")
    headers = _json_headers(f"{_CHATGPT_BASE}/auth/login", _CHATGPT_BASE)
    for attempt in range(_HTTP_RETRY_ATTEMPTS):
        try:
            r = await client.get(_URL_CSRF, headers=headers, allow_redirects=False)
            if r.status_code == 403 and attempt < _HTTP_RETRY_ATTEMPTS - 1:
                await asyncio.sleep((attempt + 1) * 5.0)
                continue
            if r.status_code != 200:
                raise LoginError(reason="network_error")
            data = r.json()
            csrf = data.get("csrfToken", "")
            if not csrf:
                raise LoginError(reason="network_error", message="empty CSRF")
            return csrf
        except LoginError:
            raise
        except Exception as e:
            if attempt < _HTTP_RETRY_ATTEMPTS - 1:
                await asyncio.sleep(2)
                continue
            raise LoginError(reason="network_error", message=f"CSRF: {e}") from e
    raise LoginError(reason="network_error")


async def _step_auth_url(client: Any, csrf: str, device_id: str, login_hint: str) -> str:
    logger.info("[login] [2/9] authorize URL")
    params = [
        ("prompt", "login"),
        ("ext-passkey-client-capabilities", "01001"),
        ("screen_hint", "login_or_signup"),
    ]
    if device_id:
        params.append(("ext-oai-did", device_id))
    if login_hint:
        params.append(("login_hint", login_hint))

    headers = _json_headers(f"{_CHATGPT_BASE}/auth/login", _CHATGPT_BASE)
    form = {"csrfToken": csrf, "callbackUrl": f"{_CHATGPT_BASE}/", "json": "true"}

    r = await client.post(
        _URL_SIGNIN_OPENAI, params=params, data=form,
        headers=headers, allow_redirects=False,
    )
    if r.status_code != 200:
        raise LoginError(reason="network_error", message=f"signin {r.status_code}")
    body = r.json()
    auth_url = body.get("url", "")
    if not auth_url or "auth.openai.com" not in auth_url:
        raise LoginError(reason="network_error", message="no auth URL")
    return auth_url


async def _bootstrap(client: Any, email: str, use_hint: bool) -> tuple[str, str]:
    default_did = str(uuid.uuid4())
    await _prime(client)
    csrf = await _get_csrf(client)
    hint = email if use_hint else ""
    auth_url = await _step_auth_url(client, csrf, default_did, hint)

    logger.info("[login] [3/9] OAuth init (GET authorize)")
    headers = _nav_headers(f"{_CHATGPT_BASE}/", "cross-site")
    _, landing = await _get_follow(client, auth_url, headers)
    device_id = _first_cookie(client, "oai-did") or default_did
    return device_id, landing


def _detect_flow(landing: str) -> str | None:
    if "/log-in/password" in landing:
        return "password"
    if "/email-verification" in landing:
        return "otp"
    return None


async def _authorize_continue(client: Any, email: str, sentinel: str, device_id: str) -> dict:
    headers = _json_headers(f"{_AUTH_BASE}/log-in", _AUTH_BASE)
    if sentinel:
        headers["openai-sentinel-token"] = sentinel
    if device_id:
        headers["oai-device-id"] = device_id
    payload = {"username": {"value": email, "kind": "email"}, "screen_hint": "login"}
    r = await client.post(_URL_AUTHORIZE_CONTINUE, json=payload, headers=headers, allow_redirects=False)
    if r.status_code != 200:
        raise LoginError(reason="network_error", message=f"authorize/continue {r.status_code}")
    return r.json()


async def _password_verify(client: Any, password: str, device_id: str, sentinel: str) -> dict:
    logger.info("[login] [4/9] password/verify")
    headers = _json_headers(f"{_AUTH_BASE}/log-in/password", _AUTH_BASE)
    if device_id:
        headers["oai-device-id"] = device_id
    if sentinel:
        headers["openai-sentinel-token"] = sentinel

    r = await client.post(
        _URL_PASSWORD_VERIFY, json={"password": password},
        headers=headers, allow_redirects=False,
    )

    if r.status_code in (401, 403):
        body_lower = r.text.lower()
        if any(k in body_lower for k in ("mfa_required", "totp_required", "mfa")):
            raise LoginError(reason="mfa_required")
        if any(k in body_lower for k in _KEYWORDS_ACCOUNT_DEACTIVATED):
            raise LoginError(reason="account_deactivated")
        if any(k in body_lower for k in ("account_locked", "account_disabled", "banned", "suspended")):
            raise LoginError(reason="account_locked")
        raise LoginError(reason="invalid_credential", message=f"password {r.status_code}")

    if r.status_code != 200:
        raise LoginError(reason="network_error", message=f"password {r.status_code}")
    return r.json()


async def _mfa_issue(client: Any, challenge_id: str, device_id: str) -> None:
    headers = _json_headers(f"{_AUTH_BASE}/mfa-challenge", _AUTH_BASE)
    if device_id:
        headers["oai-device-id"] = device_id
    try:
        await client.post(
            _URL_MFA_ISSUE,
            json={"id": challenge_id, "type": "totp", "force_fresh_challenge": False},
            headers=headers, allow_redirects=False,
        )
    except Exception:
        pass


async def _mfa_verify(client: Any, challenge_id: str, code: str, device_id: str) -> dict:
    logger.info("[login] [5/9] MFA verify (TOTP)")
    headers = _json_headers(f"{_AUTH_BASE}/mfa-challenge", _AUTH_BASE)
    if device_id:
        headers["oai-device-id"] = device_id
    r = await client.post(
        _URL_MFA_VERIFY,
        json={"id": challenge_id, "type": "totp", "code": code},
        headers=headers, allow_redirects=False,
    )
    if r.status_code != 200:
        if r.status_code in (400, 401, 403):
            raise LoginError(reason="mfa_required", message="TOTP code wrong")
        raise LoginError(reason="network_error", message=f"MFA {r.status_code}")
    return r.json()


async def _follow_to_callback(client: Any, start_url: str) -> str | None:
    current = start_url
    headers = _nav_headers(f"{_CHATGPT_BASE}/", "cross-site")
    for _ in range(_MAX_REDIRECT_HOPS):
        if "/api/auth/callback/openai" in current and "code=" in current:
            return current
        try:
            r = await client.get(current, headers=headers, allow_redirects=False)
        except Exception:
            return None
        if r.status_code in (301, 302, 303, 307, 308):
            location = r.headers.get("location")
            if not location:
                return None
            current = urljoin(current, location)
            if "/api/auth/callback/openai" in current and "code=" in current:
                return current
        else:
            return None
    return None


async def _consume_callback(client: Any, callback_url: str) -> bool:
    if "code=" not in callback_url:
        return False
    headers = _nav_headers(f"{_AUTH_BASE}/", "cross-site")
    current = callback_url
    for _ in range(_MAX_REDIRECT_HOPS):
        try:
            r = await client.get(current, headers=headers, allow_redirects=False)
        except Exception:
            return _has_session_token(client)
        if _has_session_token(client):
            return True
        if r.status_code in (301, 302, 303, 307, 308):
            location = r.headers.get("location")
            if not location:
                break
            current = urljoin(current, location)
        else:
            break
    return _has_session_token(client)


async def _consume_callback_verified(client: Any, callback_url: str) -> bool:
    if "code=" not in callback_url:
        return False
    for attempt in range(_CALLBACK_VERIFY_ATTEMPTS):
        await _consume_callback(client, callback_url)
        if _has_session_token(client):
            logger.info("[login] [6/9] callback verified (attempt %d)", attempt + 1)
            return True
        if attempt < _CALLBACK_VERIFY_ATTEMPTS - 1:
            await asyncio.sleep(1.0)
    return False


async def _get_session(client: Any) -> dict:
    logger.info("[login] [9/9] GET /api/auth/session")
    headers = _json_headers(f"{_CHATGPT_BASE}/", _CHATGPT_BASE)
    r = await client.get(_URL_SESSION, headers=headers, allow_redirects=False)
    if r.status_code != 200:
        raise LoginError(reason="network_error", message=f"session {r.status_code}")
    return r.json()


def _extract_access_token(payload: dict) -> str | None:
    for key in ("accessToken", "access_token"):
        t = payload.get(key)
        if isinstance(t, str) and t:
            return t
    user = payload.get("user")
    if isinstance(user, dict):
        for key in ("accessToken", "access_token"):
            t = user.get(key)
            if isinstance(t, str) and t:
                return t
    return None


async def check_account(email: str, password: str, totp_secret: str) -> dict:
    result = {
        "input": f"{email}|***|***",
        "email": email,
        "status": "die",
        "user": None,
        "plan": None,
        "error": None,
    }

    try:
        client = AsyncSession(impersonate=IMPERSONATE, timeout=30)
        try:
            device_id, landing = await _bootstrap(client, email, True)
            logger.info("[login] landing: %s", _short(landing, 100))
            flow = _detect_flow(landing)

            if flow is None:
                device_id, landing2 = await _bootstrap(client, email, False)
                flow = _detect_flow(landing2)

                if flow is None:
                    sentinel = await get_sentinel_token(client, device_id, "login", logger)
                    ac_data = await _authorize_continue(client, email, sentinel, device_id)
                    page_info = ac_data.get("page") or {}
                    page_type = (page_info.get("type") or "").strip()
                    continue_url = (ac_data.get("continue_url") or "").strip()
                    if page_type == "login_password" or "/log-in/password" in continue_url:
                        flow = "password"
                    elif "email" in page_type or "/email-verification" in continue_url:
                        flow = "otp"

            if flow is None:
                result["error"] = "cannot determine login flow"
                return result

            if flow == "otp":
                result["error"] = "account uses passwordless OTP (not supported)"
                return result

            sentinel = await get_sentinel_token(client, device_id, "login", logger)
            pwd_data = await _password_verify(client, password, device_id, sentinel)
            page_info = pwd_data.get("page") or {}
            page_type = (page_info.get("type") or "").strip()
            continue_url = (pwd_data.get("continue_url") or "").strip()

            if "mfa" in page_type or "mfa" in continue_url:
                match = _MFA_CHALLENGE_RE.search(continue_url)
                if not match:
                    result["error"] = "MFA required but no challenge ID"
                    return result
                challenge_id = match.group(1)
                if not totp_secret:
                    result["error"] = "MFA required but no TOTP secret provided"
                    return result
                await _mfa_issue(client, challenge_id, device_id)
                try:
                    code = pyotp.TOTP(totp_secret).now()
                except Exception as e:
                    result["error"] = f"invalid TOTP secret: {e}"
                    return result
                mfa_data = await _mfa_verify(client, challenge_id, code, device_id)
                continue_url = (mfa_data.get("continue_url") or "").strip()

            if continue_url.startswith("/"):
                continue_url = urljoin(_AUTH_BASE, continue_url)

            if continue_url and "auth.openai.com" in continue_url and "code=" not in continue_url:
                csrf2 = await _get_csrf(client)
                auth_url2 = await _step_auth_url(client, csrf2, "", "")
                cb = await _follow_to_callback(client, auth_url2)
                if cb:
                    await _consume_callback_verified(client, cb)
            elif continue_url:
                cb = await _follow_to_callback(client, continue_url)
                if cb:
                    await _consume_callback_verified(client, cb)
            else:
                csrf2 = await _get_csrf(client)
                auth_url2 = await _step_auth_url(client, csrf2, "", "")
                cb = await _follow_to_callback(client, auth_url2)
                if cb:
                    await _consume_callback_verified(client, cb)

            if not _has_session_token(client):
                result["error"] = "login flow finished but no session cookie"
                return result

            session = await _get_session(client)
            access_token = _extract_access_token(session)
            if not access_token:
                result["error"] = "no access_token in session"
                return result

            result["status"] = "live"
            user = session.get("user") or {}
            result["user"] = user.get("name") or user.get("email", email)
            result["email"] = user.get("email", email)

            try:
                me_headers = {
                    "Accept": "application/json",
                    "Authorization": f"Bearer {access_token}",
                    "Referer": "https://chatgpt.com/",
                }
                me_res = await client.get("https://chatgpt.com/backend-api/me", headers=me_headers)
                if me_res.status_code == 200:
                    me_data = me_res.json()
                    plan = _detect_plan_from_data(session, me_data)
                else:
                    plan = _detect_plan_from_data(session, {})
            except Exception:
                plan = _detect_plan_from_data(session, {})
            result["plan"] = plan

        except LoginError as e:
            result["error"] = e.reason or str(e)
            if "deactivated" in str(e.reason):
                result["status"] = "deactivated"
            elif "locked" in str(e.reason):
                result["status"] = "locked"
        except Exception as e:
            result["error"] = str(e)[:300]
        finally:
            try:
                await client.close()
            except Exception:
                pass

    except Exception as e:
        result["error"] = f"client init: {e}"

    return result


def _detect_plan_from_data(session: dict, me_data: dict) -> str:
    if isinstance(session, dict):
        sub_plan = str(session.get("subscription_plan", "")).lower()
        acc_obj = session.get("account") or {}
        acc_plan = str(acc_obj.get("planType", "") or acc_obj.get("plan_type", "")).lower()
        
        for p in (sub_plan, acc_plan):
            if p in ("plus", "chatgptplusplan"):
                return "Plus"
            if p in ("team", "chatgptteamplan"):
                return "Team"
            if p in ("pro", "chatgptproplan"):
                return "Pro"

        accounts = session.get("accounts")
        if isinstance(accounts, dict):
            for acc in accounts.values():
                if isinstance(acc, dict):
                    inner_acc = acc.get("account") or acc
                    pt = str(inner_acc.get("plan_type", "") or inner_acc.get("planType", "") or inner_acc.get("structure", "")).lower()
                    if pt in ("plus", "chatgptplusplan"):
                        return "Plus"
                    if pt in ("team", "chatgptteamplan"):
                        return "Team"
                    if pt in ("pro", "chatgptproplan"):
                        return "Pro"

        entitlements = session.get("entitlements", [])
        if isinstance(entitlements, list):
            for ent in entitlements:
                ent_str = str(ent).lower()
                if "chatgptplusplan" in ent_str or '"plan_type": "plus"' in ent_str or "'plan_type': 'plus'" in ent_str:
                    return "Plus"
                if "chatgptteamplan" in ent_str or '"plan_type": "team"' in ent_str or "'plan_type': 'team'" in ent_str:
                    return "Team"
                if "chatgptproplan" in ent_str or '"plan_type": "pro"' in ent_str or "'plan_type': 'pro'" in ent_str:
                    return "Pro"

    if isinstance(me_data, dict):
        plan_type = str(me_data.get("plan_type", "")).lower()
        if plan_type in ("plus", "chatgptplusplan"):
            return "Plus"
        if plan_type in ("team", "chatgptteamplan"):
            return "Team"
        if plan_type in ("pro", "chatgptproplan"):
            return "Pro"

        accounts = me_data.get("accounts", {})
        acc_list = accounts.values() if isinstance(accounts, dict) else (accounts if isinstance(accounts, list) else [])
        for acc in acc_list:
            if isinstance(acc, dict):
                inner_acc = acc.get("account") or acc
                p = str(inner_acc.get("plan_type", "") or inner_acc.get("planType", "") or inner_acc.get("structure", "")).lower()
                if p in ("plus", "chatgptplusplan"):
                    return "Plus"
                if p in ("team", "chatgptteamplan"):
                    return "Team"
                if p in ("pro", "chatgptproplan"):
                    return "Pro"

        entitlements = me_data.get("entitlements", [])
        if isinstance(entitlements, list):
            for ent in entitlements:
                if isinstance(ent, dict):
                    has_ent = ent.get("has_entitlement", False)
                    pt = str(ent.get("plan_type", "") or ent.get("subscription_id", "") or ent.get("id", "")).lower()
                    if (has_ent or pt) and pt != "free":
                        if "plus" in pt:
                            return "Plus"
                        if "team" in pt:
                            return "Team"
                        if "pro" in pt:
                            return "Pro"

    combined_str = (str(session) + " " + str(me_data)).lower()
    if "chatgptplusplan" in combined_str or '"plan_type": "plus"' in combined_str or "'plan_type': 'plus'" in combined_str or '"plan_type":"plus"' in combined_str or '"plantype": "plus"' in combined_str:
        return "Plus"
    if "chatgptteamplan" in combined_str or '"plan_type": "team"' in combined_str or "'plan_type': 'team'" in combined_str or '"plan_type":"team"' in combined_str or '"plantype": "team"' in combined_str:
        return "Team"
    if "chatgptproplan" in combined_str or '"plan_type": "pro"' in combined_str or "'plan_type': 'pro'" in combined_str or '"plan_type":"pro"' in combined_str or '"plantype": "pro"' in combined_str:
        return "Pro"

    return "Free"


async def check_session_token(token: str) -> dict:
    token = token.strip()
    result = {
        "input": token[:30] + "..." if len(token) > 30 else token,
        "email": None,
        "status": "die",
        "user": None,
        "plan": None,
        "error": None,
    }

    try:
        client = AsyncSession(impersonate=IMPERSONATE, timeout=30)
        try:
            if token.startswith("eyJ"):
                headers = {
                    "Accept": "application/json",
                    "Authorization": f"Bearer {token}",
                    "Accept-Language": "en-US,en;q=0.9",
                }
                r = await client.get(
                    "https://chatgpt.com/backend-api/me",
                    headers=headers,
                )
                if r.status_code == 200:
                    data = r.json()
                    result["status"] = "live"
                    result["user"] = data.get("name") or data.get("email", "")
                    result["email"] = data.get("email", "")
                    result["plan"] = _detect_plan_from_data({}, data)
                elif r.status_code == 401:
                    result["error"] = "token expired or invalid"
                elif r.status_code == 403:
                    result["error"] = "access forbidden"
                else:
                    result["error"] = f"HTTP {r.status_code}"
            else:
                client.cookies.set(
                    _SESSION_TOKEN_COOKIE_BASE, token, domain="chatgpt.com",
                )
                await _prime(client)
                headers = _json_headers(f"{_CHATGPT_BASE}/", _CHATGPT_BASE)
                r = await client.get(_URL_SESSION, headers=headers)
                if r.status_code == 200:
                    data = r.json()
                    if data.get("user"):
                        user = data["user"]
                        result["status"] = "live"
                        result["user"] = user.get("name") or user.get("email", "")
                        result["email"] = user.get("email", "")
                        result["plan"] = _detect_plan_from_data(data, {})
                    else:
                        result["error"] = "session expired"
                else:
                    result["error"] = f"HTTP {r.status_code}"
        finally:
            try:
                await client.close()
            except Exception:
                pass
    except Exception as e:
        result["error"] = str(e)[:200]

    return result
