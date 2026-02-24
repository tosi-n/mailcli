import base64
import io
import urllib.parse
from datetime import datetime, timedelta, timezone
from urllib.parse import urljoin

from fastapi import UploadFile, status

from app.core.config import settings
from app.core.enums import MailingIntegrations
from app.core.exceptions import (
    FailedToCreateSubscriptionException,
    FailedToExtendSubscriptionException,
    FailedToReauthorizeSubscriptionException,
)
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


class OutlookIntegration(BaseMailingIntegration):
    platform_name = MailingIntegrations.OUTLOOK
    authorization_url = str(settings.MICROSOFT_AUTHORIZATION_URL)
    scope = settings.MICROSOFT_SCOPE
    token_url = str(settings.MICROSOFT_TOKEN_URL)
    refresh_url = str(settings.MICROSOFT_TOKEN_URL)
    base_url = str(settings.MICROSOFT_BASE_URL)
    subscription_expires_in_minutes: int = (
        settings.MICROSOFT_SUBSCRIPTION_EXPIRES_IN_MINUTES
    )
    redirect_url = urllib.parse.urljoin(
        str(settings.DOMAIN), "/v2/mailing/callback/outlook"
    )
    client_id = settings.MICROSOFT_CLIENT_ID
    client_secret = settings.MICROSOFT_CLIENT_SECRET

    async def _store_auth_details(
        self, auth_details: dict, expiry=None
    ) -> None:
        if existing_auth_details := await self.mailing_integrations_cache_manager.fetch_auth_details(  # pylint: disable=line-too-long
            platform_name=self.platform_name.value,
            user_id=self.user_id,
            company_id=self.company_id,
        ):
            existing_auth_details.update(auth_details)
            auth_details = existing_auth_details

        await super()._store_auth_details(auth_details, expiry)

    async def subscribe(self, *args, **kwargs):
        logger.info(
            "Creating Outlook subscription for user - %s in company - %s",
            self.user_id,
            self.company_id,
            extra={"user_id": self.user_id, "company_id": self.company_id},
        )

        try:
            response = await self._make_call(
                method="POST",
                url_path="/v1.0/subscriptions",
                json={
                    "changeType": "created",
                    "notificationUrl": urljoin(
                        str(settings.DOMAIN),
                        f"/v2/mailing/webhook/outlook?id={self.user_id}&cmpId={self.company_id}",
                    ),
                    "lifecycleNotificationUrl": urljoin(
                        str(settings.DOMAIN),
                        f"/v2/mailing/lifecycle-webhook/outlook?id={self.user_id}&cmpId={self.company_id}",
                    ),
                    "resource": "me/mailFolders/Inbox/messages",
                    "expirationDateTime": (
                        datetime.now(timezone.utc)
                        + timedelta(
                            minutes=self.subscription_expires_in_minutes
                        )
                    ).isoformat(),
                    "clientState": settings.MICROSOFT_CLIENT_STATE,
                },
            )
        except OAuthIntegrationBaseException as err:
            logger.error(
                "Failed to subscribe for Outlook notifications - %s", str(err)
            )
            raise FailedToCreateSubscriptionException(
                "Failed to subscribe for Outlook notifications"
            )

        if response.status_code != status.HTTP_201_CREATED:
            logger.error(
                "Failed to subscribe for Outlook notifications - %s",
                response.text,
            )
            raise FailedToCreateSubscriptionException(
                "Failed to subscribe for Outlook notifications"
            )

        auth_details = await self.fetch_auth_details()
        auth_details["subscription_id"] = response.json()["id"]
        await self._store_auth_details(auth_details)

        logger.info(
            "Successfully created Outlook subscription for user - %s in company - %s",
            self.user_id,
            self.company_id,
            extra={"user_id": self.user_id, "company_id": self.company_id},
        )

    async def _revoke(self, *args, **kwargs):
        logger.info(
            "Revoking Outlook subscription for user - %s in company - %s",
            self.user_id,
            self.company_id,
            extra={"user_id": self.user_id, "company_id": self.company_id},
        )

        auth_details = await self.fetch_auth_details()
        if "subscription_id" not in auth_details:
            logger.warning(
                "subscription_id is missed in Outlook auth details",
                extra={"user_id": self.user_id, "company_id": self.company_id},
            )
            raise OAuthIntegrationLoginRequiredException

        try:
            response = await self._make_call(
                method="DELETE",
                url_path=f"/v1.0/subscriptions/{auth_details['subscription_id']}",
            )
        except OAuthIntegrationBaseException as err:
            logger.error(
                "Failed to delete Outlook subscription - %s",
                str(err),
                extra={"user_id": self.user_id, "company_id": self.company_id},
            )
            await self.delete_auth_from_cache()
            raise OAuthIntegrationRevokeTokenException(
                "Failed to delete Outlook subscription"
            )

        if response.status_code != status.HTTP_204_NO_CONTENT:
            logger.error(
                "Failed to delete Outlook subscription - %s",
                response.text,
                extra={"user_id": self.user_id, "company_id": self.company_id},
            )
            await self.delete_auth_from_cache()
            raise OAuthIntegrationRevokeTokenException(
                "Failed to delete Outlook subscription"
            )

        await self.delete_auth_from_cache()

        logger.info(
            "Successfully revoked Outlook subscription for user - %s in company - %s",
            self.user_id,
            self.company_id,
            extra={"user_id": self.user_id, "company_id": self.company_id},
        )

    async def reauthorize_subscription(self):
        logger.info(
            "Reauthorizing Outlook subscription for user - %s in company - %s",
            self.user_id,
            self.company_id,
            extra={"user_id": self.user_id, "company_id": self.company_id},
        )

        auth_details = await self.fetch_auth_details()
        try:
            response = await self._make_call(
                method="POST",
                url_path=f"/v1.0/subscriptions/{auth_details['subscription_id']}/reauthorize",
            )
        except OAuthIntegrationBaseException as err:
            logger.error(
                "API call to reauthorize Outlook subscription failed: %s",
                str(err),
            )
            raise FailedToReauthorizeSubscriptionException(str(err))

        if response.status_code != status.HTTP_200_OK:
            raise FailedToReauthorizeSubscriptionException(
                f"Failed to reauthorize Outlook subscription - {response.text}"
            )

        logger.info(
            "Successfully reauthorized Outlook subscription for user - %s in company - %s",
            self.user_id,
            self.company_id,
            extra={"user_id": self.user_id, "company_id": self.company_id},
        )

    async def extend_subscription(self):
        logger.info(
            "Extending Outlook subscription for user - %s in company - %s",
            self.user_id,
            self.company_id,
            extra={"user_id": self.user_id, "company_id": self.company_id},
        )

        auth_details = await self.fetch_auth_details()
        try:
            response = await self._make_call(
                method="PATCH",
                url_path=f"/v1.0/subscriptions/{auth_details['subscription_id']}",
                json={
                    "expirationDateTime": (
                        datetime.now(timezone.utc)
                        + timedelta(
                            minutes=self.subscription_expires_in_minutes
                        )
                    ).isoformat(),
                },
            )
        except OAuthIntegrationBaseException as err:
            logger.error(
                "API call to extend Outlook subscription failed: %s",
                str(err),
            )
            raise FailedToExtendSubscriptionException(str(err))

        if response.status_code != status.HTTP_200_OK:
            logger.error(
                "API call to extend Outlook subscription failed: %s",
                response.text,
            )
            raise FailedToExtendSubscriptionException(
                f"Failed to extend Outlook subscription - {response.text}"
            )

        logger.info(
            "Successfully extended Outlook subscription for user - %s in company - %s",
            self.user_id,
            self.company_id,
            extra={"user_id": self.user_id, "company_id": self.company_id},
        )

    async def get_message_invoices(
        self, message_resource: str
    ) -> list[UploadFile]:
        logger.info(
            "Trying to extract documents from Outlook message %s",
            message_resource,
            extra={"user_id": self.user_id, "company_id": self.company_id},
        )
        try:
            message_response = await self._make_call(
                method="GET",
                url_path=f"/v1.0/{message_resource}",
            )
        except OAuthIntegrationAPICallFailed as err:
            logger.error(
                "Failed to get message from Outlook API - %s",
                str(err),
                extra={"user_id": self.user_id, "company_id": self.company_id},
            )
            return []

        message_data = message_response.json()
        if not message_data.get("hasAttachments"):
            logger.info(
                "Outlook message %s has no attachment",
                message_resource,
                extra={"user_id": self.user_id, "company_id": self.company_id},
            )
            return []

        subject = message_data["subject"]
        body = message_data["body"]
        if not (
            any(keyword in subject.lower() for keyword in INVOICE_KEYWORDS)
            or any(
                keyword in body["content"].lower()
                for keyword in INVOICE_KEYWORDS
            )
        ):
            logger.info(
                "Didn't find any invoice keyword in message %s subject or body",
                message_resource,
                extra={"user_id": self.user_id, "company_id": self.company_id},
            )
            return []

        try:
            attachments_response = await self._make_call(
                method="GET",
                url_path=f"/v1.0/{message_resource}/attachments",
            )
        except OAuthIntegrationAPICallFailed as err:
            logger.error(
                "Failed to get attachments from Outlook API for message %s - %s",
                message_resource,
                str(err),
                extra={"user_id": self.user_id, "company_id": self.company_id},
            )
            return []

        attachments = []
        for attachment in attachments_response.json()["value"]:
            is_valid_attachment = self._check_if_attachment_is_valid(
                message_id=message_resource,
                mime_type=attachment["contentType"],
                filename=attachment["name"],
            )
            if not is_valid_attachment:
                continue

            decoded_data = base64.urlsafe_b64decode(attachment["contentBytes"])
            attachments.append(
                UploadFile(
                    file=io.BytesIO(decoded_data),
                    filename=attachment["name"],
                    headers={"content-type": attachment["contentType"]},
                )
            )

        logger.info(
            "Found %s documents in Outlook message",
            len(attachments),
            extra={
                "message_identifier": message_resource,
                "user_id": self.user_id,
                "company_id": self.company_id,
            },
        )
        return attachments

    async def get_connected_email(self):
        try:
            response = await self._make_call(method="GET", url_path="/v1.0/Me")
        except OAuthIntegrationBaseException as err:
            logger.error(
                "Failed to get connected email from Outlook API - %s",
                str(err),
                extra={"user_id": self.user_id, "company_id": self.company_id},
            )
            raise FailedToGetConnectedEmailException

        return response.json()["mail"]
