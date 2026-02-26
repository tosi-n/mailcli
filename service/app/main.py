from __future__ import annotations

import base64
import datetime as dt
import email
import json
import os
import time
import urllib.parse
from email.header import decode_header
from email.utils import getaddresses
from typing import Any
from uuid import UUID

import boto3
import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.crypto import TokenCipher
from app.db import MailConnection, OAuthState, init_db, session_scope
from app.internal_auth import require_internal_api_key
from app.providers import (
    build_gmail_authorize_url,
    build_outlook_authorize_url,
    decode_pubsub_gmail_data,
    exchange_gmail_code,
    exchange_outlook_code,
    gmail_api_get,
    gmail_api_post,
    is_invoice_message,
    is_supported_attachment,
    iter_gmail_parts,
    outlook_api_get,
    outlook_api_post,
    refresh_gmail_token,
    refresh_outlook_token,
)
from app.settings import settings


app = FastAPI(title="mailcli", version="0.1.0")


@app.on_event("startup")
async def _startup() -> None:
    os.makedirs("/data", exist_ok=True)
    await init_db()


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


class AuthorizeUrlIn(BaseModel):
    business_profile_id: UUID
    user_id: UUID
    referrer_url: str | None = None


class ExchangeIn(BaseModel):
    callback_url: str


class DisconnectIn(BaseModel):
    business_profile_id: UUID
    user_id: UUID


class OAuthStatusOut(BaseModel):
    status: str
    connected_email: str | None = None


class MailSearchIn(BaseModel):
    business_profile_id: UUID
    provider: str
    query: str | None = None
    from_ts: int | None = None
    to_ts: int | None = None
    max_results: int = 10


def _cipher() -> TokenCipher:
    return TokenCipher(settings.MAILCLI_TOKEN_ENCRYPTION_KEY)


def _token_expires_at(token: dict[str, Any]) -> int:
    v = token.get("expires_at")
    if isinstance(v, (int, float)):
        return int(v)
    if isinstance(v, str) and v.isdigit():
        return int(v)
    return 0


async def _create_oauth_state(
    db: AsyncSession,
    provider: str,
    payload: dict[str, Any],
    ttl_seconds: int = 900,
) -> str:
    state = base64.urlsafe_b64encode(os.urandom(24)).decode("utf-8").rstrip("=")
    expires_at = dt.datetime.now(dt.UTC) + dt.timedelta(seconds=ttl_seconds)
    db.add(OAuthState(state=state, provider=provider, payload=payload, expires_at=expires_at))
    await db.commit()
    return state


async def _consume_oauth_state(db: AsyncSession, provider: str, state: str) -> dict[str, Any]:
    res = await db.execute(select(OAuthState).where(OAuthState.state == state, OAuthState.provider == provider))
    row = res.scalars().first()
    if not row:
        raise HTTPException(status_code=400, detail="Invalid OAuth state")
    expires_at = row.expires_at
    now_utc = dt.datetime.now(dt.UTC)
    # SQLite returns naive datetimes by default; compare using matching tz-awareness.
    if isinstance(expires_at, dt.datetime) and expires_at.tzinfo is None:
        now_ref = now_utc.replace(tzinfo=None)
    else:
        now_ref = now_utc
    if expires_at < now_ref:
        await db.execute(delete(OAuthState).where(OAuthState.state == state))
        await db.commit()
        raise HTTPException(status_code=400, detail="Expired OAuth state")
    payload = dict(row.payload or {})
    await db.execute(delete(OAuthState).where(OAuthState.state == state))
    await db.commit()
    return payload


def _parse_callback_url(callback_url: str) -> dict[str, str]:
    bits = urllib.parse.urlparse(callback_url)
    q = urllib.parse.parse_qs(bits.query)
    code = (q.get("code") or [None])[0]
    state = (q.get("state") or [None])[0]
    if not code or not state:
        raise HTTPException(status_code=400, detail="Missing code/state")
    out: dict[str, str] = {"code": str(code), "state": str(state)}
    realm_id = (q.get("realmId") or [None])[0]
    if realm_id:
        out["realmId"] = str(realm_id)
    return out


def _provider_http_error_detail(exc: httpx.HTTPStatusError, provider: str) -> str:
    status = exc.response.status_code if exc.response is not None else 0
    detail: str | None = None
    try:
        payload = exc.response.json() if exc.response is not None else {}
        if isinstance(payload, dict):
            detail = payload.get("error_description") or payload.get("error")
            if detail and payload.get("error_description") and payload.get("error"):
                detail = f"{payload.get('error')}: {payload.get('error_description')}"
    except Exception:
        detail = None
    if not detail and exc.response is not None:
        body = (exc.response.text or "").strip()
        if body:
            detail = body[:512]
    if not detail:
        detail = f"HTTP {status}"
    return f"{provider} OAuth exchange failed: {detail}"


async def _maybe_refresh_token(provider: str, token: dict[str, Any]) -> dict[str, Any]:
    # Refresh if within 60 seconds of expiry.
    if _token_expires_at(token) > int(time.time()) + 60:
        return token
    refresh = token.get("refresh_token")
    if not refresh:
        return token
    if provider == "gmail":
        return await refresh_gmail_token(str(refresh))
    if provider == "outlook":
        return await refresh_outlook_token(str(refresh))
    return token


async def _load_connection(db: AsyncSession, business_profile_id: UUID, provider: str) -> MailConnection | None:
    res = await db.execute(
        select(MailConnection).where(
            MailConnection.business_profile_id == str(business_profile_id),
            MailConnection.provider == provider,
        )
    )
    return res.scalars().first()


async def _upsert_connection(
    db: AsyncSession,
    *,
    business_profile_id: UUID,
    user_id: UUID,
    provider: str,
    token: dict[str, Any],
    connected_email: str | None = None,
    metadata_patch: dict[str, Any] | None = None,
) -> MailConnection:
    cipher = _cipher()
    enc = cipher.encrypt_json(token)
    now = dt.datetime.now(dt.UTC)
    existing = await _load_connection(db, business_profile_id, provider)
    if existing:
        meta = dict(existing.metadata_json or {})
        if metadata_patch:
            meta.update(metadata_patch)
        await db.execute(
            update(MailConnection)
            .where(MailConnection.id == existing.id)
            .values(
                user_id=str(user_id),
                token_encrypted=enc,
                connected_email=connected_email or existing.connected_email,
                metadata_json=meta,
                updated_at=now,
            )
        )
        await db.commit()
        await db.refresh(existing)
        return existing

    conn = MailConnection(
        business_profile_id=str(business_profile_id),
        user_id=str(user_id),
        provider=provider,
        token_encrypted=enc,
        connected_email=connected_email,
        metadata_json=metadata_patch or {},
        created_at=now,
        updated_at=now,
    )
    db.add(conn)
    await db.commit()
    await db.refresh(conn)
    return conn


async def _delete_connection(db: AsyncSession, business_profile_id: UUID, provider: str) -> None:
    await db.execute(
        delete(MailConnection).where(
            MailConnection.business_profile_id == str(business_profile_id),
            MailConnection.provider == provider,
        )
    )
    await db.commit()


async def _backend_upload_file(
    *,
    business_profile_id: UUID,
    provider: str,
    filename: str,
    content_type: str,
    data: bytes,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    files = {"file": (filename, data, content_type)}
    form: dict[str, str] = {
        "business_profile_id": str(business_profile_id),
        "provider": provider,
        "filename": filename,
    }
    if metadata:
        form["metadata_json"] = json.dumps(metadata)

    async with httpx.AsyncClient(timeout=120.0) as client:
        headers: dict[str, str] = {}
        if settings.MAILCLI_INTERNAL_API_KEY:
            headers["X-Internal-API-Key"] = settings.MAILCLI_INTERNAL_API_KEY
        resp = await client.post(
            settings.BACKEND_INTERNAL_UPLOAD_URL,
            headers=headers,
            data=form,
            files=files,
        )
        resp.raise_for_status()
        out = resp.json()
        url = out.get("url")
        if not url:
            raise HTTPException(status_code=500, detail="Backend upload returned no url")
        return {
            "url": str(url),
            "document_id": out.get("document_id"),
            "bucket": out.get("bucket"),
            "key": out.get("key"),
        }


@app.post("/internal/oauth/gmail/authorize-url", dependencies=[Depends(require_internal_api_key)])
async def gmail_authorize_url(body: AuthorizeUrlIn) -> dict[str, str]:
    async for db in session_scope():
        state = await _create_oauth_state(
            db,
            "gmail",
            {
                "business_profile_id": str(body.business_profile_id),
                "user_id": str(body.user_id),
                "referrer_url": body.referrer_url or "",
            },
        )
        return {"authorization_url": build_gmail_authorize_url(state)}


@app.post("/internal/oauth/outlook/authorize-url", dependencies=[Depends(require_internal_api_key)])
async def outlook_authorize_url(body: AuthorizeUrlIn) -> dict[str, str]:
    async for db in session_scope():
        state = await _create_oauth_state(
            db,
            "outlook",
            {
                "business_profile_id": str(body.business_profile_id),
                "user_id": str(body.user_id),
                "referrer_url": body.referrer_url or "",
            },
        )
        return {"authorization_url": build_outlook_authorize_url(state)}


@app.post("/internal/oauth/gmail/exchange", dependencies=[Depends(require_internal_api_key)])
async def gmail_exchange(body: ExchangeIn) -> dict[str, Any]:
    bits = _parse_callback_url(body.callback_url)
    async for db in session_scope():
        state_payload = await _consume_oauth_state(db, "gmail", bits["state"])
        bp_id = UUID(state_payload["business_profile_id"])
        user_id = UUID(state_payload["user_id"])

        try:
            token = await exchange_gmail_code(bits["code"])
        except httpx.HTTPStatusError as exc:
            raise HTTPException(status_code=400, detail=_provider_http_error_detail(exc, "gmail")) from exc

        # Capture connected email and initialize history id.
        email_profile = await gmail_api_get("/gmail/v1/users/me/profile", token)
        connected_email = email_profile.get("emailAddress")

        history_id: str | None = None
        if settings.GMAIL_SUBSCRIPTION_TOPIC:
            try:
                watch_resp = await gmail_api_post(
                    "/gmail/v1/users/me/watch",
                    token,
                    {
                        "topicName": settings.GMAIL_SUBSCRIPTION_TOPIC,
                        "labelIds": ["INBOX"],
                        "labelFilterBehavior": "INCLUDE",
                    },
                )
                history_id = watch_resp.get("historyId")
            except Exception:
                history_id = None

        await _upsert_connection(
            db,
            business_profile_id=bp_id,
            user_id=user_id,
            provider="gmail",
            token=token,
            connected_email=connected_email,
            metadata_patch={"gmail_history_id": history_id} if history_id else {},
        )
        return {"connected": True, "connected_email": connected_email}


@app.post("/internal/oauth/outlook/exchange", dependencies=[Depends(require_internal_api_key)])
async def outlook_exchange(body: ExchangeIn) -> dict[str, Any]:
    bits = _parse_callback_url(body.callback_url)
    async for db in session_scope():
        state_payload = await _consume_oauth_state(db, "outlook", bits["state"])
        bp_id = UUID(state_payload["business_profile_id"])
        user_id = UUID(state_payload["user_id"])

        try:
            token = await exchange_outlook_code(bits["code"])
        except httpx.HTTPStatusError as exc:
            raise HTTPException(status_code=400, detail=_provider_http_error_detail(exc, "outlook")) from exc
        me = await outlook_api_get("/v1.0/me", token)
        connected_email = me.get("mail") or me.get("userPrincipalName")

        subscription_id: str | None = None
        try:
            exp = dt.datetime.now(dt.UTC) + dt.timedelta(minutes=settings.MICROSOFT_SUBSCRIPTION_EXPIRES_IN_MINUTES)
            backend_public = settings.BACKEND_PUBLIC_ORIGIN.rstrip("/")
            notif_url = f"{backend_public}/api/v1/tool-mail/webhooks/outlook?bpId={bp_id}&userId={user_id}"
            lifecycle_url = f"{backend_public}/api/v1/tool-mail/webhooks/outlook-lifecycle?bpId={bp_id}&userId={user_id}"
            sub = await outlook_api_post(
                "/v1.0/subscriptions",
                token,
                {
                    "changeType": "created",
                    "notificationUrl": notif_url,
                    "lifecycleNotificationUrl": lifecycle_url,
                    "resource": "me/mailFolders/Inbox/messages",
                    "expirationDateTime": exp.isoformat(),
                    "clientState": settings.MICROSOFT_CLIENT_STATE,
                },
            )
            subscription_id = sub.get("id")
        except Exception:
            subscription_id = None

        await _upsert_connection(
            db,
            business_profile_id=bp_id,
            user_id=user_id,
            provider="outlook",
            token=token,
            connected_email=connected_email,
            metadata_patch={"subscription_id": subscription_id} if subscription_id else {},
        )
        return {"connected": True, "connected_email": connected_email, "subscription_id": subscription_id}


@app.get(
    "/internal/oauth/{provider}/status",
    dependencies=[Depends(require_internal_api_key)],
    response_model=OAuthStatusOut,
)
async def oauth_status(provider: str, business_profile_id: UUID) -> OAuthStatusOut:
    if provider not in {"gmail", "outlook"}:
        raise HTTPException(status_code=400, detail="Unsupported provider")
    async for db in session_scope():
        conn = await _load_connection(db, business_profile_id, provider)
        if not conn:
            return OAuthStatusOut(status="not_connected", connected_email=None)
        return OAuthStatusOut(status="connected", connected_email=conn.connected_email)


@app.post("/internal/oauth/{provider}/disconnect", dependencies=[Depends(require_internal_api_key)])
async def oauth_disconnect(provider: str, body: DisconnectIn) -> dict[str, Any]:
    if provider not in {"gmail", "outlook"}:
        raise HTTPException(status_code=400, detail="Unsupported provider")
    async for db in session_scope():
        await _delete_connection(db, body.business_profile_id, provider)
        return {"disconnected": True}


@app.post("/internal/webhooks/gmail", dependencies=[Depends(require_internal_api_key)])
async def webhook_gmail(request: Request) -> dict[str, Any]:
    payload = await request.json()
    msg = payload.get("message") or {}
    data_b64 = msg.get("data")
    if not data_b64:
        return {"processed": 0, "reason": "missing_message_data"}

    decoded = decode_pubsub_gmail_data(str(data_b64))
    email_addr = decoded.get("emailAddress")
    history_id = decoded.get("historyId")
    if not email_addr or not history_id:
        return {"processed": 0, "reason": "missing_email_or_history"}

    async for db in session_scope():
        res = await db.execute(
            select(MailConnection).where(
                MailConnection.provider == "gmail",
                MailConnection.connected_email == str(email_addr),
            )
        )
        conn = res.scalars().first()
        if not conn:
            return {"processed": 0, "reason": "no_connection_for_email"}

        token = _cipher().decrypt_json(conn.token_encrypted)
        token = await _maybe_refresh_token("gmail", token)

        prev_history = (conn.metadata_json or {}).get("gmail_history_id")
        if not prev_history:
            await _upsert_connection(
                db,
                business_profile_id=UUID(conn.business_profile_id),
                user_id=UUID(conn.user_id),
                provider="gmail",
                token=token,
                connected_email=conn.connected_email,
                metadata_patch={"gmail_history_id": str(history_id)},
            )
            return {"processed": 0, "reason": "initialized_history"}

        hist = await gmail_api_get(
            "/gmail/v1/users/me/history",
            token,
            params={"startHistoryId": str(prev_history)},
        )
        message_ids: set[str] = set()
        for h in hist.get("history", []) or []:
            for added in h.get("messagesAdded", []) or []:
                mid = (added.get("message") or {}).get("id")
                if mid:
                    message_ids.add(str(mid))

        processed_attachments: list[dict[str, Any]] = []
        for mid in sorted(message_ids):
            msg_details = await gmail_api_get(f"/gmail/v1/users/me/messages/{mid}", token)
            snippet = msg_details.get("snippet", "")
            mpayload = msg_details.get("payload", {}) or {}
            subject = ""
            for hdr in mpayload.get("headers", []) or []:
                if hdr.get("name") == "Subject":
                    subject = hdr.get("value") or ""
                    break

            if not is_invoice_message(subject, snippet):
                continue

            for p in iter_gmail_parts(mpayload):
                filename = p.get("filename") or ""
                if not filename:
                    continue
                body = p.get("body") or {}
                attachment_id = body.get("attachmentId")
                if not attachment_id:
                    continue
                mime_type = p.get("mimeType") or "application/octet-stream"
                if not is_supported_attachment(str(mime_type), str(filename)):
                    continue

                att = await gmail_api_get(
                    f"/gmail/v1/users/me/messages/{mid}/attachments/{attachment_id}",
                    token,
                )
                data = att.get("data") or ""
                if not data:
                    continue
                blob = base64.urlsafe_b64decode(str(data).encode("utf-8"))
                upload = await _backend_upload_file(
                    business_profile_id=UUID(conn.business_profile_id),
                    provider="gmail",
                    filename=str(filename),
                    content_type=str(mime_type),
                    data=blob,
                    metadata={"message_id": mid, "subject": subject},
                )
                processed_attachments.append(
                    {
                        "message_id": mid,
                        "filename": str(filename),
                        "content_type": str(mime_type),
                        "url": upload.get("url"),
                        "document_id": upload.get("document_id"),
                        "bucket": upload.get("bucket"),
                        "key": upload.get("key"),
                    }
                )

        await _upsert_connection(
            db,
            business_profile_id=UUID(conn.business_profile_id),
            user_id=UUID(conn.user_id),
            provider="gmail",
            token=token,
            connected_email=conn.connected_email,
            metadata_patch={"gmail_history_id": str(history_id)},
        )

        return {
            "provider": "gmail",
            "business_profile_id": conn.business_profile_id,
            "processed": len(processed_attachments),
            "attachments": processed_attachments,
        }


@app.post("/internal/webhooks/outlook", dependencies=[Depends(require_internal_api_key)])
async def webhook_outlook(
    request: Request,
    bpId: UUID | None = None,
    userId: UUID | None = None,  # noqa: ARG001
) -> dict[str, Any]:
    payload = await request.json()
    if not bpId:
        return {"processed": 0, "reason": "missing_bpId"}

    async for db in session_scope():
        conn = await _load_connection(db, bpId, "outlook")
        if not conn:
            return {"processed": 0, "reason": "no_connection"}

        token = _cipher().decrypt_json(conn.token_encrypted)
        token = await _maybe_refresh_token("outlook", token)

        notifications = payload.get("value") or []
        out: list[dict[str, Any]] = []
        for n in notifications:
            rid = (n.get("resourceData") or {}).get("id")
            if not rid:
                continue
            msg = await outlook_api_get(
                f"/v1.0/me/messages/{rid}",
                token,
                params={"$expand": "attachments"},
            )
            subject = msg.get("subject") or ""
            atts = msg.get("attachments") or []
            for a in atts:
                if a.get("@odata.type") != "#microsoft.graph.fileAttachment":
                    continue
                filename = a.get("name") or "attachment"
                mime_type = a.get("contentType") or "application/octet-stream"
                if not is_supported_attachment(str(mime_type), str(filename)):
                    continue
                content_b64 = a.get("contentBytes") or ""
                if not content_b64:
                    continue
                blob = base64.b64decode(str(content_b64).encode("utf-8"))
                upload = await _backend_upload_file(
                    business_profile_id=bpId,
                    provider="outlook",
                    filename=str(filename),
                    content_type=str(mime_type),
                    data=blob,
                    metadata={"message_id": str(rid), "subject": str(subject)},
                )
                out.append(
                    {
                        "message_id": str(rid),
                        "filename": str(filename),
                        "content_type": str(mime_type),
                        "url": upload.get("url"),
                        "document_id": upload.get("document_id"),
                        "bucket": upload.get("bucket"),
                        "key": upload.get("key"),
                    }
                )

        await _upsert_connection(
            db,
            business_profile_id=bpId,
            user_id=UUID(conn.user_id),
            provider="outlook",
            token=token,
            connected_email=conn.connected_email,
        )

        return {
            "provider": "outlook",
            "business_profile_id": str(bpId),
            "processed": len(out),
            "attachments": out,
        }


@app.post("/internal/webhooks/outlook-lifecycle", dependencies=[Depends(require_internal_api_key)])
async def webhook_outlook_lifecycle(
    request: Request,
    bpId: UUID | None = None,  # noqa: ARG001
    userId: UUID | None = None,  # noqa: ARG001
) -> dict[str, Any]:
    # v1: accept and log; renewal/reauth flows can be added later.
    _ = await request.json()
    return {"status": "ok"}


def _parse_forwarding_bp_id(to_email: str) -> UUID | None:
    # Expected: <prefix>+<business_profile_id>@<domain>
    try:
        local, domain = to_email.split("@", 1)
        if settings.EMAIL_FORWARD_DOMAIN and domain.lower() != settings.EMAIL_FORWARD_DOMAIN.lower():
            return None
        if "+" not in local:
            return None
        prefix, suffix = local.split("+", 1)
        if prefix != settings.EMAIL_FORWARD_PREFIX:
            return None
        return UUID(suffix)
    except Exception:
        return None


@app.post("/internal/webhooks/email-forwarding-ses", dependencies=[Depends(require_internal_api_key)])
async def webhook_email_forwarding_ses(request: Request) -> dict[str, Any]:
    payload = await request.json()
    msg_type = payload.get("Type") or payload.get("type")

    if msg_type == "SubscriptionConfirmation":
        subscribe_url = payload.get("SubscribeURL") or payload.get("subscribe_url") or payload.get("SubscribeUrl")
        if not subscribe_url:
            return {"status": "ignored", "reason": "missing_subscribe_url"}
        async with httpx.AsyncClient(timeout=30.0) as client:
            await client.get(str(subscribe_url))
        return {"status": "confirmed"}

    if msg_type != "Notification":
        return {"status": "ignored", "reason": "unsupported_type"}

    message_raw = payload.get("Message") or payload.get("message") or "{}"
    try:
        message_json = json.loads(str(message_raw))
        bucket = message_json["receipt"]["action"]["bucketName"]
        key = message_json["receipt"]["action"]["objectKey"]
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid SNS payload: {e}")

    expected_bucket = (settings.AWS_SES_S3_BUCKET_NAME or "").strip()
    if expected_bucket and str(bucket).lower() != expected_bucket.lower():
        # Return 200 to prevent SNS retries for unexpected buckets.
        return {"processed": 0, "reason": "bucket_mismatch", "bucket": str(bucket)}

    if not (settings.AWS_SES_REGION and settings.AWS_SES_ACCESS_KEY_ID and settings.AWS_SES_SECRET_ACCESS_KEY):
        raise HTTPException(status_code=500, detail="SES S3 credentials not configured")

    # objectKey is URL-encoded in some SES/SNS setups.
    key = urllib.parse.unquote_plus(str(key))

    s3 = boto3.client(
        "s3",
        region_name=settings.AWS_SES_REGION,
        aws_access_key_id=settings.AWS_SES_ACCESS_KEY_ID,
        aws_secret_access_key=settings.AWS_SES_SECRET_ACCESS_KEY,
    )
    obj = s3.get_object(Bucket=str(bucket), Key=key)
    raw_email: bytes = obj["Body"].read()

    em = email.message_from_bytes(raw_email)

    to_header = em.get("To") or ""
    to_addresses = [addr for _, addr in getaddresses([to_header]) if addr]
    to_email = to_addresses[0] if to_addresses else ""
    bp_id = _parse_forwarding_bp_id(to_email)
    if not bp_id:
        return {"processed": 0, "reason": "could_not_map_business_profile", "to_email": to_email}

    attachments: list[dict[str, Any]] = []
    for part in em.walk():
        filename = part.get_filename()
        if filename:
            decoded = decode_header(filename)
            filename = "".join(
                [(t.decode(enc or "utf-8") if isinstance(t, bytes) else str(t)) for t, enc in decoded]
            )
        content_type = part.get_content_type()
        disp = part.get_content_disposition()
        if disp != "attachment" and not filename:
            continue
        if not filename:
            filename = "attachment"
        if not is_supported_attachment(str(content_type), str(filename)):
            continue
        blob = part.get_payload(decode=True) or b""
        if not blob:
            continue
        upload = await _backend_upload_file(
            business_profile_id=bp_id,
            provider="email_forwarding_ses",
            filename=str(filename),
            content_type=str(content_type),
            data=blob,
            metadata={"s3_bucket": str(bucket), "s3_key": key, "to_email": to_email},
        )
        attachments.append(
            {
                "filename": str(filename),
                "content_type": str(content_type),
                "url": upload.get("url"),
                "document_id": upload.get("document_id"),
                "bucket": upload.get("bucket"),
                "key": upload.get("key"),
            }
        )

    return {
        "provider": "email_forwarding_ses",
        "business_profile_id": str(bp_id),
        "processed": len(attachments),
        "attachments": attachments,
    }


def _format_gmail_query(query: str | None, from_ts: int | None, to_ts: int | None) -> str:
    parts: list[str] = []
    if query and query.strip():
        parts.append(query.strip())
    else:
        parts.append("(invoice OR receipt OR statement)")
    if from_ts:
        dt_from = dt.datetime.fromtimestamp(int(from_ts), tz=dt.UTC).strftime("%Y/%m/%d")
        parts.append(f"after:{dt_from}")
    if to_ts:
        dt_to = dt.datetime.fromtimestamp(int(to_ts), tz=dt.UTC).strftime("%Y/%m/%d")
        parts.append(f"before:{dt_to}")
    return " ".join(parts).strip()


def _message_matches_query(subject: str, snippet: str, query: str | None) -> bool:
    if not query:
        return True
    q = query.lower()
    hay = f"{subject} {snippet}".lower()
    tokens = [t for t in q.replace("(", " ").replace(")", " ").replace("OR", " ").split() if len(t) > 2]
    if not tokens:
        return True
    return any(token in hay for token in tokens)


@app.post("/internal/mail/search", dependencies=[Depends(require_internal_api_key)])
async def mail_search(body: MailSearchIn) -> dict[str, Any]:
    provider = (body.provider or "").strip().lower()
    if provider not in {"gmail", "outlook"}:
        raise HTTPException(status_code=400, detail="Unsupported provider")

    max_results = max(1, min(int(body.max_results or 10), 25))

    async for db in session_scope():
        conn = await _load_connection(db, body.business_profile_id, provider)
        if not conn:
            return {
                "provider": provider,
                "status": "not_connected",
                "matches": [],
            }

        token = _cipher().decrypt_json(conn.token_encrypted)
        token = await _maybe_refresh_token(provider, token)

        matches: list[dict[str, Any]] = []

        if provider == "gmail":
            gmail_query = _format_gmail_query(body.query, body.from_ts, body.to_ts)
            listing = await gmail_api_get(
                "/gmail/v1/users/me/messages",
                token,
                params={
                    "q": gmail_query,
                    "maxResults": max_results,
                },
            )
            for item in listing.get("messages", []) or []:
                mid = item.get("id")
                if not mid:
                    continue
                msg = await gmail_api_get(
                    f"/gmail/v1/users/me/messages/{mid}",
                    token,
                    params={"format": "full"},
                )
                payload = msg.get("payload") or {}
                snippet = str(msg.get("snippet") or "")
                subject = ""
                for hdr in payload.get("headers", []) or []:
                    if hdr.get("name") == "Subject":
                        subject = str(hdr.get("value") or "")
                        break
                if not _message_matches_query(subject, snippet, body.query):
                    continue

                attachments: list[dict[str, Any]] = []
                for part in iter_gmail_parts(payload):
                    filename = part.get("filename") or ""
                    if not filename:
                        continue
                    pbody = part.get("body") or {}
                    attachment_id = pbody.get("attachmentId")
                    if not attachment_id:
                        continue
                    mime_type = part.get("mimeType") or "application/octet-stream"
                    if not is_supported_attachment(str(mime_type), str(filename)):
                        continue

                    att = await gmail_api_get(
                        f"/gmail/v1/users/me/messages/{mid}/attachments/{attachment_id}",
                        token,
                    )
                    data = att.get("data") or ""
                    if not data:
                        continue
                    blob = base64.urlsafe_b64decode(str(data).encode("utf-8"))
                    upload = await _backend_upload_file(
                        business_profile_id=body.business_profile_id,
                        provider="gmail",
                        filename=str(filename),
                        content_type=str(mime_type),
                        data=blob,
                        metadata={"message_id": str(mid), "subject": subject, "search_query": body.query or ""},
                    )
                    attachments.append(
                        {
                            "filename": str(filename),
                            "content_type": str(mime_type),
                            "url": upload.get("url"),
                            "document_id": upload.get("document_id"),
                            "bucket": upload.get("bucket"),
                            "key": upload.get("key"),
                        }
                    )

                matches.append(
                    {
                        "provider_message_id": str(mid),
                        "subject": subject,
                        "snippet": snippet,
                        "received_at": msg.get("internalDate"),
                        "attachments": attachments,
                    }
                )
        else:
            # Outlook Graph cannot reliably combine custom lexical search + attachment expansion
            # across all tenants, so fetch recent messages and filter client-side for v1.
            params: dict[str, Any] = {
                "$top": max_results,
                "$orderby": "receivedDateTime DESC",
                "$select": "id,subject,bodyPreview,receivedDateTime",
            }
            if body.from_ts or body.to_ts:
                clauses: list[str] = []
                if body.from_ts:
                    start_iso = dt.datetime.fromtimestamp(int(body.from_ts), tz=dt.UTC).isoformat()
                    clauses.append(f"receivedDateTime ge {start_iso}")
                if body.to_ts:
                    end_iso = dt.datetime.fromtimestamp(int(body.to_ts), tz=dt.UTC).isoformat()
                    clauses.append(f"receivedDateTime le {end_iso}")
                if clauses:
                    params["$filter"] = " and ".join(clauses)

            listing = await outlook_api_get("/v1.0/me/messages", token, params=params)
            for item in listing.get("value", []) or []:
                mid = item.get("id")
                if not mid:
                    continue
                subject = str(item.get("subject") or "")
                snippet = str(item.get("bodyPreview") or "")
                if not _message_matches_query(subject, snippet, body.query):
                    continue
                msg = await outlook_api_get(
                    f"/v1.0/me/messages/{mid}",
                    token,
                    params={"$expand": "attachments"},
                )
                attachments: list[dict[str, Any]] = []
                for a in msg.get("attachments") or []:
                    if a.get("@odata.type") != "#microsoft.graph.fileAttachment":
                        continue
                    filename = a.get("name") or "attachment"
                    mime_type = a.get("contentType") or "application/octet-stream"
                    if not is_supported_attachment(str(mime_type), str(filename)):
                        continue
                    content_b64 = a.get("contentBytes") or ""
                    if not content_b64:
                        continue
                    blob = base64.b64decode(str(content_b64).encode("utf-8"))
                    upload = await _backend_upload_file(
                        business_profile_id=body.business_profile_id,
                        provider="outlook",
                        filename=str(filename),
                        content_type=str(mime_type),
                        data=blob,
                        metadata={"message_id": str(mid), "subject": subject, "search_query": body.query or ""},
                    )
                    attachments.append(
                        {
                            "filename": str(filename),
                            "content_type": str(mime_type),
                            "url": upload.get("url"),
                            "document_id": upload.get("document_id"),
                            "bucket": upload.get("bucket"),
                            "key": upload.get("key"),
                        }
                    )

                matches.append(
                    {
                        "provider_message_id": str(mid),
                        "subject": subject,
                        "snippet": snippet,
                        "received_at": item.get("receivedDateTime"),
                        "attachments": attachments,
                    }
                )

        await _upsert_connection(
            db,
            business_profile_id=body.business_profile_id,
            user_id=UUID(conn.user_id),
            provider=provider,
            token=token,
            connected_email=conn.connected_email,
        )

        return {
            "provider": provider,
            "status": "ok",
            "query": body.query or "",
            "matches": matches,
        }
