from datetime import UTC, datetime
from uuid import UUID

from app.core.config import settings
from app.core.enums import (
    CommunicationPlatform,
    ConnectionStatus,
    DocumentSource,
    MailingIntegrations,
)
from app.core.exceptions import (
    FailedToReauthorizeSubscriptionException,
    FailedToValidateEmailWebhookData,
    JackBaseException,
    ObjectNotFoundException,
)
from app.core.loggers import logger
from app.core.services.oauth.exceptions import (
    OAuthIntegrationLoginRequiredException,
)
from app.messaging.messages import MailingWebhookDataMessage
from app.messaging.producers.mailing_webhooks import MailingWebhooksProducer
from app.schemas.communication import (
    UpdateCommunicationPlatformConnectionSchema,
)
from app.schemas.mailing import (
    OutlookLifecycleWebhookPayloadSchema,
    OutlookWebhookDataSchema,
)
from app.services.company.company import CompanyService

from .base import BaseMailingService

__all__ = ["OutlookService"]


class OutlookService(BaseMailingService):
    INTEGRATION_TYPE = MailingIntegrations.OUTLOOK

    async def handle_webhook_event(
        self, webhook_data: OutlookWebhookDataSchema
    ):
        user = await self._user_repository.get(item_id=webhook_data.user_id)
        if not user:
            raise ObjectNotFoundException(
                "Received webhook event for not existing user"
            )
        await MailingWebhooksProducer().send(
            MailingWebhookDataMessage(
                user_id=user.id,
                company_id=webhook_data.company_id,
                platform_name=self.INTEGRATION_TYPE,
                data=webhook_data.model_dump(),
            )
        )

    async def process_webhook_message(self, webhook_message: dict):
        logger.info("Processing Outlook webhook message - %s", webhook_message)

        try:
            webhook_data = OutlookWebhookDataSchema(**webhook_message)
        except ValueError as err:
            raise FailedToValidateEmailWebhookData from err

        user = await self._user_repository.get(webhook_data.user_id)

        if not user:
            raise ObjectNotFoundException

        if not await CompanyService(self.db).check_if_user_can_access(
            company_id=webhook_data.company_id,
            user_id=user.id,
        ):
            logger.warning(
                "Handle Outlook webhook from user who has no access to company",
                extra={
                    "user_id": user.id,
                    "company_id": webhook_data.company_id,
                },
            )
            await self.delete_mailing_connection(
                user_id=user.id,
                company_id=webhook_data.company_id,
                platform=CommunicationPlatform.OUTLOOK,
            )
            return

        messages_invoices = []
        for message_resource in webhook_data.new_messages_urls:
            try:
                messages_invoices.extend(
                    await self.integration.get_message_invoices(
                        message_resource=message_resource,
                    )
                )
            except OAuthIntegrationLoginRequiredException:
                logger.warning(
                    "Outlook integration login required",
                    extra={"user_id": user.id},
                )
                await self.delete_mailing_connection(
                    user_id=user.id,
                    company_id=self.integration.company_id,
                    platform=CommunicationPlatform.OUTLOOK,
                )

        try:
            logger.info(
                "Extracted %s documents from Outlook message - %s",
                len(messages_invoices),
                webhook_message,
                extra={
                    "user_id": user.id,
                    "company_id": self.integration.company_id,
                },
            )
            if messages_invoices:
                await self._document_service.upload_files(
                    company_id=self.integration.company_id,
                    user=user,
                    uploaded_files=messages_invoices,
                    source=DocumentSource.OUTLOOK_FETCH,
                )
        except JackBaseException as err:
            logger.error(
                "Failed to upload files from outlook to Jack",
                extra={
                    "user_id": user.id,
                    "company_id": self.integration.company_id,
                },
            )
            raise err

        logger.info(
            "Successfully processed Outlook webhook message - %s",
            webhook_message,
            extra={
                "user_id": user.id,
                "company_id": self.integration.company_id,
            },
        )

    async def renew_subscription(self, connection):
        await self.integration.extend_subscription()

        current_time = datetime.now(UTC)
        update_data = UpdateCommunicationPlatformConnectionSchema(
            company_id=connection.company_id,
            user_id=connection.user_id,
            platform=connection.platform,
            status=ConnectionStatus.CONNECTED,
            last_watched_timestamp=current_time,
        )
        await self._communication_platform_service.update_connection(
            data=update_data
        )

    async def handle_lifecycle_webhook_event(
        self,
        user_id: UUID,
        company_id: UUID,
        lifecycle_webhook_event: OutlookLifecycleWebhookPayloadSchema,
    ):
        for event in lifecycle_webhook_event.value:
            if event.client_state != settings.MICROSOFT_CLIENT_STATE:
                logger.warning(
                    "Received lifecycle webhook event with invalid client state",
                    extra={"user_id": user_id, "company_id": company_id},
                )
                return

            user = await self._user_repository.get(item_id=user_id)
            if not user:
                logger.warning(
                    "Received lifecycle webhook event for not existing user",
                    extra={"user_id": user_id, "company_id": company_id},
                )
                return

            match event.lifecycle_event:
                case "subscriptionRemoved":
                    await self.handle_subscription_removed_event(
                        user_id, company_id
                    )
                case "reauthorizationRequired":
                    await self.handle_reauthorization_required_event(
                        user_id, company_id
                    )
                case _:
                    logger.warning(
                        "Received unsupported lifecycle webhook event"
                    )

    async def handle_subscription_removed_event(
        self, user_id: UUID, company_id: UUID
    ):
        logger.info(
            "Handling subscription removed event",
            extra={"user_id": user_id, "company_id": company_id},
        )
        await self.integration.delete_auth_from_cache()
        await self.delete_mailing_connection(
            user_id=user_id,
            company_id=company_id,
            platform=CommunicationPlatform.OUTLOOK,
        )
        logger.info(
            "Successfully handled subscription removed event",
            extra={"user_id": user_id, "company_id": company_id},
        )

    async def handle_reauthorization_required_event(
        self, user_id: UUID, company_id: UUID
    ):
        logger.info(
            "Handling subscription reauthorization required event",
            extra={"user_id": user_id, "company_id": company_id},
        )

        try:
            await self.integration.reauthorize_subscription()
        except FailedToReauthorizeSubscriptionException as err:
            logger.error(
                "Failed to handle reauthorization request - %s",
                err,
                extra={"user_id": user_id, "company_id": company_id},
            )
            await self.integration.delete_auth_from_cache()
            await self.delete_mailing_connection(
                user_id=user_id,
                company_id=company_id,
                platform=CommunicationPlatform.OUTLOOK,
            )
            raise FailedToReauthorizeSubscriptionException

        logger.info(
            "Successfully handled subscription reauthorization required event",
            extra={"user_id": user_id, "company_id": company_id},
        )
