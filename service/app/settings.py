from __future__ import annotations

import json
import logging
from typing import Any

import boto3
from pydantic_settings import BaseSettings

logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    # Internal auth
    MAILCLI_INTERNAL_API_KEY: str = ""

    # Token encryption (Fernet base64 key; 32 bytes)
    MAILCLI_TOKEN_ENCRYPTION_KEY: str

    # DB
    MAILCLI_DATABASE_URL: str = "sqlite+aiosqlite:////data/mailcli.db"

    # Stimulir backend
    BACKEND_INTERNAL_UPLOAD_URL: str = "http://backend:8000/api/v1/internal/media/upload"
    BACKEND_PUBLIC_ORIGIN: str = "http://localhost:8000"

    # Gmail OAuth + API
    GMAIL_CLIENT_ID: str = ""
    GMAIL_CLIENT_SECRET: str = ""
    GMAIL_SCOPE: str = "https://www.googleapis.com/auth/gmail.readonly"
    GMAIL_AUTHORIZATION_URL: str = "https://accounts.google.com/o/oauth2/v2/auth"
    GMAIL_TOKEN_URL: str = "https://oauth2.googleapis.com/token"
    GMAIL_BASE_URL: str = "https://gmail.googleapis.com"
    GMAIL_SUBSCRIPTION_TOPIC: str = ""

    # Outlook OAuth + API
    MICROSOFT_CLIENT_ID: str = ""
    MICROSOFT_CLIENT_SECRET: str = ""
    MICROSOFT_SCOPE: str = "User.Read Mail.Read offline_access"
    MICROSOFT_AUTHORIZATION_URL: str = "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize"
    MICROSOFT_TOKEN_URL: str = "https://login.microsoftonline.com/organizations/oauth2/v2.0/token"
    MICROSOFT_BASE_URL: str = "https://graph.microsoft.com"
    MICROSOFT_CLIENT_STATE: str = ""
    MICROSOFT_SUBSCRIPTION_EXPIRES_IN_MINUTES: int = int(6.5 * 24 * 60)

    # SES forwarding
    AWS_SES_REGION: str = ""
    AWS_SES_S3_BUCKET_NAME: str = ""
    AWS_SES_ACCESS_KEY_ID: str = ""
    AWS_SES_SECRET_ACCESS_KEY: str = ""
    EMAIL_FORWARD_PREFIX: str = "documents"
    EMAIL_FORWARD_DOMAIN: str = ""

    # Optional direct AWS Secrets Manager hydration for local/dev runtime.
    MAILCLI_USE_AWS_SECRETS_MANAGER: bool = False
    MAILCLI_AWS_SECRETS_MANAGER_SECRET_IDS: str = ""
    AWS_SECRETS_MANAGER_SECRET_IDS: str = ""
    AWS_REGION: str = "eu-west-2"


def _parse_secret_string(secret_string: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    try:
        raw = json.loads(secret_string)
        if isinstance(raw, dict):
            for key, value in raw.items():
                if key:
                    parsed[str(key)] = "" if value is None else str(value)
            return parsed
    except json.JSONDecodeError:
        pass

    for line in secret_string.splitlines():
        item = line.strip()
        if not item or item.startswith("#") or "=" not in item:
            continue
        key, value = item.split("=", 1)
        parsed[key.strip()] = value.strip().strip("\"'")
    return parsed


def _secret_ids(cfg: Settings) -> list[str]:
    raw = cfg.MAILCLI_AWS_SECRETS_MANAGER_SECRET_IDS or cfg.AWS_SECRETS_MANAGER_SECRET_IDS
    return [item.strip() for item in raw.split(",") if item.strip()]


def _hydrate_from_aws(cfg: Settings) -> Settings:
    if not cfg.MAILCLI_USE_AWS_SECRETS_MANAGER:
        return cfg
    ids = _secret_ids(cfg)
    if not ids:
        logger.warning("MAILCLI_USE_AWS_SECRETS_MANAGER=true but no secret ids configured")
        return cfg

    client = boto3.client("secretsmanager", region_name=cfg.AWS_REGION)
    merged: dict[str, str] = {}
    for secret_id in ids:
        try:
            resp = client.get_secret_value(SecretId=secret_id)
        except Exception as exc:  # pragma: no cover - network/credentials dependent
            logger.warning("Unable to read AWS secret %s: %s", secret_id, exc)
            continue
        payload = resp.get("SecretString")
        if not payload:
            continue
        merged.update(_parse_secret_string(str(payload)))

    if not merged:
        logger.warning("No values loaded from AWS Secrets Manager for mailcli")
        return cfg

    overrides: dict[str, Any] = {}
    for field_name in cfg.model_fields:
        if field_name in {
            "MAILCLI_USE_AWS_SECRETS_MANAGER",
            "MAILCLI_AWS_SECRETS_MANAGER_SECRET_IDS",
            "AWS_SECRETS_MANAGER_SECRET_IDS",
            "AWS_REGION",
        }:
            continue
        current = getattr(cfg, field_name)
        if isinstance(current, str) and current:
            continue
        from_secret = merged.get(field_name)
        if from_secret not in (None, ""):
            overrides[field_name] = from_secret

    if overrides:
        logger.info("Applied %d mailcli settings from AWS Secrets Manager", len(overrides))
        return cfg.model_copy(update=overrides)
    return cfg


settings = _hydrate_from_aws(Settings())
