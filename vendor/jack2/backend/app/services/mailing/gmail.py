import base64
import datetime
import json

from app.core.enums import (
    CommunicationPlatform,
    ConnectionStatus,
    DocumentSource,
    MailingIntegrations,
)
from app.core.exceptions import (
    FailedToValidateEmailWebhookData,
    ObjectNotFoundException,
)
from app.messaging.messages import MailingWebhookDataMessage
from app.messaging.producers.mailing_webhooks import MailingWebhooksProducer
from app.models.communication_platform_connection import (
    CommunicationPlatformConnection,
)
from app.schemas.communication import (
    UpdateCommunicationPlatformConnectionSchema,
)
from app.schemas.mailing import GmailWebhookDataSchema
from app.schemas.mailing.gmail import GmailWebhookMessageSchema

from .base import BaseMailingService

__all__ = ["GmailService"]


class GmailService(BaseMailingService):
    INTEGRATION_TYPE = MailingIntegrations.GMAIL

    async def handle_webhook_event(self, webhook_data: GmailWebhookDataSchema):
        try:
            decoded_data = json.loads(
                base64.urlsafe_b64decode(webhook_data.message.data).decode(
                    "utf-8"
                )
            )
        except ValueError as err:
            raise FailedToValidateEmailWebhookData from err

        user = await self._user_repository.get_by_email(
            email=decoded_data["emailAddress"]
        )
        if not user:
            raise ObjectNotFoundException

        connection = await self._communication_platform_service.fetch_connection_for_user(  # pylint: disable=line-too-long
            user_id=user.id,
            platform=CommunicationPlatform.GMAIL,
        )
        await self.update_connection_timestamp(
            connection,
            last_notified_timestamp=True,
        )

        decoded_data["internal_user_id"] = user.id

        await MailingWebhooksProducer().send(
            MailingWebhookDataMessage(
                user_id=user.id,
                company_id=connection.company_id,
                platform_name=self.INTEGRATION_TYPE,
                data=decoded_data,
            )
        )

    async def process_webhook_message(self, webhook_message: dict):
        try:
            webhook_message = GmailWebhookMessageSchema(**webhook_message)
        except ValueError as err:
            raise FailedToValidateEmailWebhookData from err

        user = await self._user_repository.get(
            webhook_message.internal_user_id
        )

        if not user:
            raise ObjectNotFoundException

        messages_invoices = await self.integration.get_invoices_from_messages(
            webhook_message.history_id
        )

        await self._document_service.upload_files(
            company_id=self.integration.company_id,
            user=user,
            uploaded_files=messages_invoices,
            source=DocumentSource.GMAIL_FETCH,
        )

    async def renew_watch_subscription(
        self, connection: CommunicationPlatformConnection
    ):
        new_history_id = await self.integration.subscribe(
            initial_subscription=False
        )

        await MailingWebhooksProducer().send(
            MailingWebhookDataMessage(
                user_id=connection.user_id,
                platform_name=connection.platform,
                data={
                    "history_id": new_history_id,
                    "internal_user_id": connection.user_id,
                },
            )
        )

    async def update_connection_timestamp(
        self,
        connection: CommunicationPlatformConnection,
        last_watched_timestamp: bool = False,
        last_notified_timestamp: bool = False,
    ):
        current_time = datetime.datetime.now(datetime.UTC)
        update_data = UpdateCommunicationPlatformConnectionSchema(
            company_id=connection.company_id,
            user_id=connection.user_id,
            platform=connection.platform,
            status=ConnectionStatus.CONNECTED,
        )
        if last_watched_timestamp:
            update_data.last_watched_timestamp = current_time
        if last_notified_timestamp:
            update_data.last_notified_timestamp = current_time
        await self._communication_platform_service.update_connection(
            data=update_data
        )
