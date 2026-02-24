import abc
import urllib.parse
from uuid import UUID

from fastapi import UploadFile

from app.core.enums import MailingIntegrations
from app.core.loggers import logger
from app.core.mailing.constants import ALLOWED_MIMETYPES
from app.core.mailing.integrations.cache_manager import (
    MailingIntegrationsCacheManager,
)
from app.core.services.oauth.base import OAuthBasedIntegrationService
from app.core.services.oauth.exceptions import (
    OAuthIntegrationLoginFailedException,
    OAuthIntegrationLoginRequiredException,
    OAuthIntegrationValidationFailed,
)


class BaseMailingIntegration(OAuthBasedIntegrationService, abc.ABC):
    platform_name: MailingIntegrations
    MIN_ATTACHMENT_SIZE = 5 * 1024  # 5KB

    def __init__(
        self,
        user_id: UUID,
        company_id: UUID | None = None,
    ):
        self.company_id = company_id
        self.user_id = user_id
        self.mailing_integrations_cache_manager = (
            MailingIntegrationsCacheManager()
        )
        self._auth_details = None
        self.referrer_url = None

    @abc.abstractmethod
    async def subscribe(self, *args, **kwargs):
        raise NotImplementedError

    @abc.abstractmethod
    async def _revoke(self, *args, **kwargs):
        raise NotImplementedError

    async def handle_authorization_response(self, url: str) -> dict:
        url_bits = urllib.parse.urlparse(url)
        query_bits = urllib.parse.parse_qs(url_bits.query)

        state = self._validate_authorization_state(query_bits)

        self.company_id, self.user_id, _, self.referrer_url = (
            await self.validate_state(state)
        )

        code = self._validate_authorization_code(query_bits)

        # Exchange the authorization code for an access token
        session = await self._get_oauth_client(False)
        try:
            token = await session.fetch_token(
                self.token_url,
                client_secret=self.client_secret,
                code=code,
                access_type=self.access_type,
            )
            await self._store_auth_details(token)
        except Exception as e:
            raise OAuthIntegrationLoginFailedException(
                f"Token exchange failed {e}"
            ) from e

        return token

    async def fetch_auth_details(self) -> dict:
        """
        Read token info from cache or raise LoginRequired error
        if token is missed
        """
        if self._auth_details:
            return self._auth_details

        if auth_details := await self.mailing_integrations_cache_manager.fetch_auth_details(  # pylint: disable=line-too-long
            platform_name=self.platform_name.value,
            user_id=self.user_id,
            company_id=self.company_id,
        ):
            self._auth_details = auth_details
            return auth_details
        raise OAuthIntegrationLoginRequiredException

    async def _store_auth_details(
        self, auth_details: dict, expiry=None
    ) -> None:
        await self.mailing_integrations_cache_manager.store_auth_details(
            platform_name=self.platform_name.value,
            user_id=self.user_id,
            auth_details=auth_details,
            expiry=expiry,
            company_id=self.company_id,
        )
        self._auth_details = auth_details

    async def validate_state(self, state) -> tuple[str, str, str, str]:
        """
        Return tuple that contains the organization id, user id,
        platform and referrer
        """
        if state := await self.mailing_integrations_cache_manager.validate_and_extract_state(  # pylint: disable=line-too-long
            state
        ):
            return state
        raise OAuthIntegrationValidationFailed

    def _sanitize_attachments(
        self, attachments: list[UploadFile]
    ) -> list[UploadFile]:
        """
        Filter out attachments that are too small and are not of type pdf
        """
        return [
            attachment
            for attachment in attachments
            if (
                (
                    attachment.size
                    and attachment.size > self.MIN_ATTACHMENT_SIZE
                )
                or attachment.content_type == "application/pdf"
            )
        ]

    async def delete_auth_from_cache(self):
        return await self.mailing_integrations_cache_manager.delete_auth(
            platform_name=self.platform_name.value,
            user_id=self.user_id,
            company_id=self.company_id,
        )

    async def _cache_state_string(self, state: str):
        await self.mailing_integrations_cache_manager.generate_and_cache_state_string(  # pylint: disable=line-too-long
            user_id=self.user_id,
            platform_name=self.platform_name.value,
            state=state,
            company_id=self.company_id,
        )

    async def get_connected_email(self):
        return None

    @staticmethod
    def _check_if_attachment_is_valid(
        message_id: str, mime_type: str, filename: str
    ) -> bool:
        # Ensure we only process image and pdf attachments
        if mime_type not in ALLOWED_MIMETYPES:
            logger.warning(
                "Skip body part with not supported %s mime type for extraction. Message ID: %s",
                mime_type,
                message_id,
                extra={
                    "message_id": message_id,
                    "mimeType": mime_type,
                },
            )
            return False

        if mime_type == "application/octet-stream":
            if not filename.lower().endswith(".pdf"):
                logger.warning(
                    "Skip body part with application/octet-stream, but not pdf extension. Message ID: %s",
                    message_id,
                    extra={
                        "attachment_filename": filename,
                        "message_id": message_id,
                        "mimeType": mime_type,
                    },
                )
                return False

            logger.info(
                "Retrieved body part with application/octet-stream and pdf extension. Message ID: %s",
                message_id,
                extra={
                    "attachment_filename": filename,
                    "message_id": message_id,
                    "mimeType": mime_type,
                },
            )

        return True
