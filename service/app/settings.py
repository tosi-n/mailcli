from __future__ import annotations

from pydantic_settings import BaseSettings


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


settings = Settings()
