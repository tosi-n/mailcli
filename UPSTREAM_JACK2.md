# Upstream Mapping (jack-2)

This repo vendors selected source-of-truth integration code from:

- `/Users/tosi-n/Documents/Dev/Jenesys/jack-2`

Status at time of initial sync:

- `jack-2` git: **no commits yet** (no `HEAD` SHA available)
- `jack-2` branch (from `git status -sb`): `feature/billing-system-latest`
- Synced at: `2026-02-17`

## Files Vendored

The following files are copied into `vendor/jack2/...` and should be treated as the
reference implementation for integration behavior:

- `backend/app/core/mailing/integrations/base.py`
- `backend/app/core/mailing/integrations/gmail.py`
- `backend/app/core/mailing/integrations/outlook.py`
- `backend/app/core/mailing/integrations/cache_manager.py`
- `backend/app/services/mailing/gmail.py`
- `backend/app/services/mailing/outlook.py`
- `backend/app/services/mailing/forwarding.py`
- `backend/app/services/mailing/email_forwarding_sender.py`

## Sync Policy

Rule of thumb:

1. Change integration behavior in `jack-2` first.
2. Re-sync this repo with `./scripts/sync_from_jack2.sh`.
3. Keep all new code here limited to glue (HTTP surface area, DB, auth broker plumbing).

