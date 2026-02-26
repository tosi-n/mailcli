# mailcli

Internal tool-service (FastAPI) for mail ingestion used by `stimulir-console`.

Scope (v1):
- Gmail OAuth + best-effort watch subscription
- Outlook OAuth + best-effort Microsoft Graph subscriptions (notification + lifecycle)
- AWS SES -> S3 -> SNS email forwarding ingestion

This service is self-contained and focused on internal mail ingestion workflows.

## Run (local)

API:
```bash
docker build -t mailcli:dev -f service/Dockerfile .
docker run --rm -p 8000:8000 --env-file .env mailcli:dev
```

Worker (optional; skeleton in v1):
```bash
docker build -t mailcli-worker:dev -f worker/Dockerfile .
docker run --rm --env-file .env mailcli-worker:dev
```

## Internal API (called by stimulir backend)
- `POST /internal/oauth/gmail/authorize-url`
- `POST /internal/oauth/outlook/authorize-url`
- `POST /internal/oauth/gmail/exchange`
- `POST /internal/oauth/outlook/exchange`
- `GET /internal/oauth/{provider}/status?business_profile_id=...`
- `POST /internal/oauth/{provider}/disconnect`
- `POST /internal/webhooks/gmail`
- `POST /internal/webhooks/outlook`
- `POST /internal/webhooks/outlook-lifecycle`
- `POST /internal/webhooks/email-forwarding-ses`

All internal endpoints require `X-Internal-API-Key: $MAILCLI_INTERNAL_API_KEY`.

## Required env
Minimum:
- `MAILCLI_INTERNAL_API_KEY`
- `MAILCLI_TOKEN_ENCRYPTION_KEY` (Fernet key; base64 32 bytes)
- `MAILCLI_DATABASE_URL` (optional; defaults to `sqlite+aiosqlite:////data/mailcli.db`)
- `BACKEND_INTERNAL_UPLOAD_URL` (e.g. `http://backend:8000/api/v1/internal/media/upload`)
- `BACKEND_PUBLIC_ORIGIN` (public URL used for OAuth redirect URIs)

Gmail:
- `GMAIL_CLIENT_ID`, `GMAIL_CLIENT_SECRET`
- `GMAIL_SCOPE`
- `GMAIL_AUTHORIZATION_URL`, `GMAIL_TOKEN_URL`, `GMAIL_BASE_URL`
- `GMAIL_SUBSCRIPTION_TOPIC`

Outlook:
- `MICROSOFT_CLIENT_ID`, `MICROSOFT_CLIENT_SECRET`
- `MICROSOFT_SCOPE`
- `MICROSOFT_AUTHORIZATION_URL`, `MICROSOFT_TOKEN_URL`, `MICROSOFT_BASE_URL`
- `MICROSOFT_CLIENT_STATE`

Email forwarding (SES -> S3 -> SNS):
- `AWS_SES_REGION`
- `AWS_SES_ACCESS_KEY_ID`, `AWS_SES_SECRET_ACCESS_KEY`
- `AWS_SES_S3_BUCKET_NAME` (optional safety check; if set, bucket must match)
- `EMAIL_FORWARD_PREFIX`, `EMAIL_FORWARD_DOMAIN`
