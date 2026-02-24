from __future__ import annotations

from fastapi import Header, HTTPException

from app.settings import settings


async def require_internal_api_key(x_internal_api_key: str | None = Header(default=None, alias="X-Internal-API-Key")) -> None:
    if not settings.MAILCLI_INTERNAL_API_KEY:
        # Optional in private-network deployments.
        return
    if x_internal_api_key != settings.MAILCLI_INTERNAL_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid internal API key")
