import base64
import io
import urllib.parse

from fastapi import UploadFile

from app.core.config import settings
from app.core.enums import MailingIntegrations
from app.core.exceptions.mailing import FailedToGetConnectedEmailException
from app.core.loggers import logger
from app.core.mailing.constants import INVOICE_KEYWORDS
from app.core.services.oauth.exceptions import (
    OAuthIntegrationAPICallFailed,
    OAuthIntegrationBaseException,
    OAuthIntegrationLoginRequiredException,
    OAuthIntegrationRevokeTokenException,
)

from .base import BaseMailingIntegration


class GmailIntegration(BaseMailingIntegration):
    platform_name = MailingIntegrations.GMAIL
    authorization_url = str(settings.GMAIL_AUTHORIZATION_URL)
    scope = settings.GMAIL_SCOPE
    token_url = str(settings.GMAIL_TOKEN_URL)
    refresh_url = str(settings.GMAIL_TOKEN_URL)
    base_url = str(settings.GMAIL_BASE_URL)
    redirect_url = urllib.parse.urljoin(
        str(settings.DOMAIN), "/v2/mailing/callback/gmail"
    )
    client_id = settings.GMAIL_CLIENT_ID
    client_secret = settings.GMAIL_CLIENT_SECRET
    access_type = "offline"
    metadata = {"prompt": "consent"}

    async def subscribe(self, *args, initial_subscription=True, **kwargs):
        try:
            response = await self._make_call(
                method="POST",
                url_path="/gmail/v1/users/me/watch",
                json={
                    "topicName": settings.GMAIL_SUBSCRIPTION_TOPIC,
                    "labelIds": ["INBOX"],
                    "labelFilterBehavior": "INCLUDE",
                },
            )
            if initial_subscription:
                await self.mailing_integrations_cache_manager.store_gmail_history_id(  # pylint: disable=line-too-long
                    user_id=self.user_id,
                    company_id=self.company_id,
                    history_id=response.json().get("historyId"),
                )
        except OAuthIntegrationAPICallFailed as err:
            logger.error(
                "Failed to subscribe for Gmail notifications - %s", str(err)
            )

    async def _revoke(self, *args, **kwargs):
        try:
            await self._make_call(
                method="POST",
                url_path="/gmail/v1/users/me/stop",
            )
            await self.mailing_integrations_cache_manager.delete_auth(
                user_id=self.user_id,
                platform_name=self.platform_name.value,
                company_id=self.company_id,
            )
        except OAuthIntegrationLoginRequiredException:
            logger.warning("Trying to disconnect not connected integration")
            await self.delete_auth_from_cache()

        except OAuthIntegrationAPICallFailed as err:
            logger.error(
                "Failed to remove subscription for Gmail notifications - %s",
                str(err),
            )
            await self.delete_auth_from_cache()
            raise OAuthIntegrationRevokeTokenException

    async def get_invoices_from_messages(
        self, new_history_id
    ) -> list[UploadFile]:
        messages = []
        if previous_history_id := await self.mailing_integrations_cache_manager.get_gmail_history_id(  # pylint: disable=line-too-long
            user_id=self.user_id,
            company_id=self.company_id,
        ):
            messages = await self._fetch_messages_from_history(
                previous_history_id
            )

        logger.info(
            "Retrieved %s messages from user Gmail history changes",
            len(messages),
            extra={
                "count": len(messages),
                "history_id": previous_history_id,
                "user_id": self.user_id,
                "company_id": self.company_id,
            },
        )

        emails_invoices = []
        for message in messages:
            message_invoices = await self._get_message_invoices(
                message_id=message["id"]
            )
            emails_invoices.extend(message_invoices)

            logger.info(
                "Retrieved %s invoices from user Gmail message %s",
                len(message_invoices),
                message["id"],
                extra={
                    "message_id": message["id"],
                    "count": len(message_invoices),
                    "user_id": self.user_id,
                    "company_id": self.company_id,
                },
            )

        await self.mailing_integrations_cache_manager.store_gmail_history_id(
            user_id=self.user_id,
            history_id=new_history_id,
            company_id=self.company_id,
        )
        return emails_invoices

    async def _fetch_messages_from_history(
        self, history_id: str
    ) -> list[dict]:
        messages = []
        history_changes = await self._get_history_changes(history_id)
        messages.extend(
            self._get_messages_from_history_changes(
                history_changes.get("history", [])
            )
        )

        while history_changes and "nextPageToken" in history_changes:
            history_changes = await self._get_history_changes(
                history_changes["historyId"]
            )
            if not (history_changes and history_changes.get("history")):
                break

            messages.extend(
                self._get_messages_from_history_changes(
                    history_changes["history"]
                )
            )

        return messages

    async def _get_history_changes(self, history_id):
        try:
            response = await self._make_call(
                method="get",
                url_path="/gmail/v1/users/me/history",
                params={"startHistoryId": history_id},
            )
            return response.json()
        except OAuthIntegrationAPICallFailed as err:
            logger.error(
                "Failed to get Gmail messages history - %s",
                str(err),
                extra={"history_id": history_id},
            )
            return {"history": []}

    def _get_messages_from_history_changes(self, history_changes):
        return [
            change["message"]
            for changes in history_changes
            for change in changes.get("messagesAdded", [])
            if not self._is_message_deleted(
                change["message"], changes.get("messagesDeleted", [])
            )
        ]

    @staticmethod
    def _is_message_deleted(message, deleted_messages):
        return message["id"] in [
            msg["message"]["id"] for msg in deleted_messages
        ]

    async def _get_message_invoices(self, message_id: str) -> list[UploadFile]:
        try:
            logger.info(
                "Fetching message details for message %s",
                message_id,
                extra={"message_id": message_id},
            )
            message_details_response = await self._make_call(
                method="get",
                url_path=f"/gmail/v1/users/me/messages/{message_id}",
            )
            logger.info(
                "Successfully fetched message details for message %s",
                message_id,
                extra={"message_id": message_id},
            )

            message_details = message_details_response.json()
            snippet = message_details.get("snippet", "")
            payload = message_details.get("payload", {})
            subject = next(
                (
                    header["value"]
                    for header in payload.get("headers", [])
                    if header["name"] == "Subject"
                ),
                "",
            )

            if any(
                keyword in subject.lower() for keyword in INVOICE_KEYWORDS
            ) or any(
                keyword in snippet.lower() for keyword in INVOICE_KEYWORDS
            ):
                return await self._extract_attachments(message_details)

            logger.info(
                "Skip attachments extraction for message without invoice keyword",
                extra={"message_id": message_id},
            )
            return []

        except OAuthIntegrationAPICallFailed as err:
            logger.error(
                "Failed to get message invoices - %s",
                str(err),
                extra={"message_id": message_id},
            )
            return []

    async def _extract_attachments(  # pylint: disable=too-many-locals
        self, message_details: dict
    ) -> list[UploadFile]:
        attachments = []
        logger.info(
            "Extracting attachments from message %s",
            message_details["id"],
            extra={
                "message_id": message_details["id"],
                "user_id": self.user_id,
                "company_id": self.company_id,
            },
        )

        # Recursive helper to yield all parts that contain a filename.
        def _get_attachment_parts(parts):
            for part in parts:
                # If there are nested parts, process them recursively.
                if part.get("parts"):
                    yield from _get_attachment_parts(part["parts"])
                # Only yield parts that actually have a filename (non-empty)
                if part.get("filename"):
                    yield part

        # Start from the top-level parts in the payload.
        top_level_parts = message_details.get("payload", {}).get("parts", [])
        for part in _get_attachment_parts(top_level_parts):
            filename = part.get("filename", "")
            mime_type = part.get("mimeType", "")

            is_valid_attachment = self._check_if_attachment_is_valid(
                message_id=message_details["id"],
                mime_type=mime_type,
                filename=str(filename),
            )
            if not is_valid_attachment:
                continue

            body = part.get("body", {})
            attachment_id = body.get("attachmentId")
            if not attachment_id:
                logger.warning(
                    "Skip body part with no attachmentId. Message ID: %s",
                    message_details["id"],
                    extra={"message_id": message_details["id"]},
                )
                continue

            try:
                logger.info(
                    "Fetching attachment with ID %s for message ID %s",
                    attachment_id,
                    message_details["id"],
                    extra={
                        "message_id": message_details["id"],
                        "attachment_id": attachment_id,
                    },
                )
                attachment_response = await self._make_call(
                    method="get",
                    url_path=f"/gmail/v1/users/me/messages/{message_details['id']}/attachments/{attachment_id}",
                )
                attachment = attachment_response.json()
                data = attachment.get("data", "")

                padding = "=" * (
                    -len(data) % 4
                )  # Compute the required padding.
                data += padding  # Add the padding to the end of the string.

                decoded_data = base64.urlsafe_b64decode(data)

                # Compute the size of the decoded data.
                size = len(decoded_data)

                upload_file = UploadFile(
                    file=io.BytesIO(decoded_data),
                    filename=filename,
                    headers={"content-type": mime_type},
                )
                upload_file.size = size
                attachments.append(upload_file)

                logger.info(
                    "Successfully fetched attachment %s from message ID %s",
                    attachment_id,
                    message_details["id"],
                    extra={
                        "message_id": message_details["id"],
                        "attachment_filename": filename,
                    },
                )
            except OAuthIntegrationAPICallFailed as err:
                logger.error(
                    "Failed to get Gmail message attachment - %s",
                    str(err),
                    extra={"message_id": message_details["id"]},
                )
                continue

        logger.info(
            "Extracted %s attachments from message %s",
            len(attachments),
            message_details["id"],
            extra={
                "message_id": message_details["id"],
                "company_id": self.company_id,
                "user_id": self.user_id,
            },
        )
        return attachments

    async def get_connected_email(self):
        try:
            response = await self._make_call(
                method="GET", url_path="/gmail/v1/users/me/profile"
            )
        except OAuthIntegrationBaseException as err:
            logger.error(
                "Failed to get connected email from Gmail API - %s",
                str(err),
                extra={"user_id": self.user_id, "company_id": self.company_id},
            )
            raise FailedToGetConnectedEmailException

        return response.json()["emailAddress"]
