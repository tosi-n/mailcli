from __future__ import annotations

import base64
import datetime as dt
import json
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any, Optional

import httpx

from app.settings import settings


INVOICE_KEYWORDS = ("invoice", "receipt")
ALLOWED_MIMETYPES = (
    "application/pdf",
    "image/jpeg",
    "image/png",
    "application/octet-stream",
)


def _now_ts() -> int:
    return int(time.time())


def _calc_expires_at(token: dict[str, Any]) -> dict[str, Any]:
    if "expires_in" in token and "expires_at" not in token:
        token["expires_at"] = _now_ts() + int(token["expires_in"])
    return token


def build_redirect_uri(provider: str) -> str:
    # OAuth redirects to the Stimulir backend (public ingress), not this service.
    base = settings.BACKEND_PUBLIC_ORIGIN.rstrip("/")
    if provider == "gmail":
        return f"{base}/api/v1/tool-mail/oauth/callback/gmail"
    if provider == "outlook":
        return f"{base}/api/v1/tool-mail/oauth/callback/outlook"
    raise ValueError(f"unknown provider: {provider}")


def build_gmail_authorize_url(state: str) -> str:
    params = {
        "client_id": settings.GMAIL_CLIENT_ID,
        "redirect_uri": build_redirect_uri("gmail"),
        "response_type": "code",
        "scope": settings.GMAIL_SCOPE,
        "access_type": "offline",
        "prompt": "consent",
        "include_granted_scopes": "true",
        "state": state,
    }
    return f"{settings.GMAIL_AUTHORIZATION_URL}?{urllib.parse.urlencode(params)}"


def build_outlook_authorize_url(state: str) -> str:
    params = {
        "client_id": settings.MICROSOFT_CLIENT_ID,
        "redirect_uri": build_redirect_uri("outlook"),
        "response_type": "code",
        "response_mode": "query",
        "scope": settings.MICROSOFT_SCOPE,
        "state": state,
    }
    return f"{settings.MICROSOFT_AUTHORIZATION_URL}?{urllib.parse.urlencode(params)}"


async def exchange_gmail_code(code: str) -> dict[str, Any]:
    data = {
        "code": code,
        "client_id": settings.GMAIL_CLIENT_ID,
        "client_secret": settings.GMAIL_CLIENT_SECRET,
        "redirect_uri": build_redirect_uri("gmail"),
        "grant_type": "authorization_code",
    }
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(settings.GMAIL_TOKEN_URL, data=data)
        resp.raise_for_status()
        return _calc_expires_at(resp.json())


async def refresh_gmail_token(refresh_token: str) -> dict[str, Any]:
    data = {
        "client_id": settings.GMAIL_CLIENT_ID,
        "client_secret": settings.GMAIL_CLIENT_SECRET,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
    }
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(settings.GMAIL_TOKEN_URL, data=data)
        resp.raise_for_status()
        tok = resp.json()
        tok["refresh_token"] = refresh_token
        return _calc_expires_at(tok)


async def exchange_outlook_code(code: str) -> dict[str, Any]:
    data = {
        "client_id": settings.MICROSOFT_CLIENT_ID,
        "client_secret": settings.MICROSOFT_CLIENT_SECRET,
        "code": code,
        "redirect_uri": build_redirect_uri("outlook"),
        "grant_type": "authorization_code",
        "scope": settings.MICROSOFT_SCOPE,
    }
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(settings.MICROSOFT_TOKEN_URL, data=data)
        resp.raise_for_status()
        return _calc_expires_at(resp.json())


async def refresh_outlook_token(refresh_token: str) -> dict[str, Any]:
    data = {
        "client_id": settings.MICROSOFT_CLIENT_ID,
        "client_secret": settings.MICROSOFT_CLIENT_SECRET,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
        "scope": settings.MICROSOFT_SCOPE,
    }
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(settings.MICROSOFT_TOKEN_URL, data=data)
        resp.raise_for_status()
        tok = resp.json()
        tok["refresh_token"] = refresh_token
        return _calc_expires_at(tok)


async def gmail_api_get(path: str, token: dict[str, Any], params: dict[str, Any] | None = None) -> dict[str, Any]:
    url = urllib.parse.urljoin(settings.GMAIL_BASE_URL, path)
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get(url, headers={"Authorization": f"Bearer {token['access_token']}"}, params=params)
        resp.raise_for_status()
        return resp.json()


async def gmail_api_post(path: str, token: dict[str, Any], json_body: dict[str, Any]) -> dict[str, Any]:
    url = urllib.parse.urljoin(settings.GMAIL_BASE_URL, path)
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(url, headers={"Authorization": f"Bearer {token['access_token']}"}, json=json_body)
        resp.raise_for_status()
        return resp.json()


async def outlook_api_get(path: str, token: dict[str, Any], params: dict[str, Any] | None = None, headers: dict[str, str] | None = None) -> dict[str, Any]:
    url = urllib.parse.urljoin(settings.MICROSOFT_BASE_URL, path)
    h = {"Authorization": f"Bearer {token['access_token']}"}
    if headers:
        h.update(headers)
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get(url, headers=h, params=params)
        resp.raise_for_status()
        return resp.json()


async def outlook_api_post(path: str, token: dict[str, Any], json_body: dict[str, Any]) -> dict[str, Any]:
    url = urllib.parse.urljoin(settings.MICROSOFT_BASE_URL, path)
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(url, headers={"Authorization": f"Bearer {token['access_token']}"}, json=json_body)
        resp.raise_for_status()
        return resp.json()


def decode_pubsub_gmail_data(data_b64: str) -> dict[str, Any]:
    raw = base64.b64decode(data_b64)
    return json.loads(raw.decode("utf-8"))


def is_invoice_message(subject: str, snippet: str) -> bool:
    s = (subject or "").lower()
    sn = (snippet or "").lower()
    return any(k in s for k in INVOICE_KEYWORDS) or any(k in sn for k in INVOICE_KEYWORDS)


def iter_gmail_parts(part: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    stack = [part]
    while stack:
        p = stack.pop()
        out.append(p)
        for child in p.get("parts", []) or []:
            stack.append(child)
    return out


def is_supported_attachment(mime_type: str, filename: str) -> bool:
    if mime_type not in ALLOWED_MIMETYPES:
        return False
    if mime_type == "application/octet-stream" and not (filename or "").lower().endswith(".pdf"):
        return False
    return True

