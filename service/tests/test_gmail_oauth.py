from __future__ import annotations

import os
import unittest
import urllib.parse


os.environ.setdefault("MAILCLI_TOKEN_ENCRYPTION_KEY", "iu6SKclrmwsvh1jwTF-QYK4ahkFGu9lKe-_RpHhm3E4=")
os.environ.setdefault("BACKEND_PUBLIC_ORIGIN", "https://api.stimulir.test")
os.environ.setdefault("GMAIL_CLIENT_ID", "gmail-client-id")
os.environ.setdefault("GMAIL_CLIENT_SECRET", "gmail-client-secret")

from app.main import _missing_gmail_scopes, _parse_callback_url  # noqa: E402
from app.providers import build_gmail_authorize_url  # noqa: E402
from app.settings import settings  # noqa: E402


class GmailOauthTests(unittest.TestCase):
    def test_build_gmail_authorize_url_requests_exact_gmail_scopes_without_incremental_grant_reuse(self) -> None:
        url = build_gmail_authorize_url("oauth-state")
        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed.query)

        self.assertEqual(query["client_id"], [settings.GMAIL_CLIENT_ID])
        self.assertEqual(query["scope"], [settings.GMAIL_SCOPE])
        self.assertEqual(query["prompt"], ["consent"])
        self.assertEqual(query["access_type"], ["offline"])
        self.assertEqual(query["state"], ["oauth-state"])
        self.assertNotIn("include_granted_scopes", query)

    def test_parse_callback_url_captures_scope(self) -> None:
        parsed = _parse_callback_url(
            "https://api.stimulir.test/api/v1/tool-mail/oauth/callback/gmail"
            "?code=abc&state=xyz&scope=https://www.googleapis.com/auth/gmail.readonly"
        )

        self.assertEqual(parsed["code"], "abc")
        self.assertEqual(parsed["state"], "xyz")
        self.assertEqual(parsed["scope"], "https://www.googleapis.com/auth/gmail.readonly")

    def test_missing_gmail_scopes_prefers_callback_scope(self) -> None:
        missing = _missing_gmail_scopes(
            callback_scope="https://www.googleapis.com/auth/gmail.readonly",
            token={"scope": settings.GMAIL_SCOPE},
        )

        self.assertEqual(missing, ["https://www.googleapis.com/auth/gmail.send"])

    def test_missing_gmail_scopes_falls_back_to_token_scope(self) -> None:
        missing = _missing_gmail_scopes(
            callback_scope=None,
            token={"scope": settings.GMAIL_SCOPE},
        )

        self.assertEqual(missing, [])


if __name__ == "__main__":
    unittest.main()
