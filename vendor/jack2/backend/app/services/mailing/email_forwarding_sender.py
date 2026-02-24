import asyncio
import csv
import io
import os
from datetime import datetime
from uuid import UUID

import aiofiles
from asyncpg.exceptions import UniqueViolationError
from fastapi import UploadFile
from jinja2 import Template
from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from app.core.config import settings
from app.core.enums import UserRoles
from app.core.enums.mailing import (
    EmailForwardingSenderStatus,
    MailingIntegrations,
)
from app.core.exceptions import (
    DuplicateObjectException,
    FileTooLargeException,
    InvalidCSVFormatException,
    ObjectNotFoundException,
)
from app.core.loggers import logger
from app.core.mailing.sender import EmailSenderService
from app.repositories.mailing.email_forwarding_sender import (
    EmailForwardingSenderRepository,
)
from app.schemas.mailing import (
    AddEmailForwardingSenderSchema,
    CreateEmailForwardingSenderSchema,
    ReadEmailForwardingSenderSchema,
    SenderCSVRowSchema,
    UpdateEmailForwardingSenderSchema,
)
from app.services.base import BaseService
from app.services.company.company import CompanyService
from app.services.company.company_member import CompanyMemberService

__all__ = ["EmailForwardingSenderService"]


class EmailForwardingSenderService(BaseService):
    INTEGRATION_TYPE = MailingIntegrations.EMAIL_FORWARDING
    MAX_CSV_FILE_SIZE = 15 * 1024 * 1024  # 15MB

    def __init__(self, db: AsyncSession):
        super().__init__(db)
        self._repository = EmailForwardingSenderRepository(db)
        self._company_member_service = CompanyMemberService(db)
        self._company_service = CompanyService(db)
        self._email_sender_service = EmailSenderService()

    async def fetch_or_notify_sender(
        self,
        company_id: UUID,
        email: str,
    ) -> ReadEmailForwardingSenderSchema | None:
        if sender := await self._repository.get_by_company_and_email(
            company_id=company_id, email=email
        ):
            logger.info(
                "Sender %s found",
                sender.email,
                extra={"company_id": company_id},
            )
            match sender.status:
                case EmailForwardingSenderStatus.ALLOWED:
                    return sender
                case EmailForwardingSenderStatus.REJECTED:
                    await self.send_rejection_notification(sender)
                case EmailForwardingSenderStatus.PENDING:
                    await self.send_pending_notification(sender)
                case EmailForwardingSenderStatus.BLOCKED:
                    logger.info("Sender %s is blocked", sender.email)
        else:
            sender = await self.create_sender(
                company_id=company_id,
                data=AddEmailForwardingSenderSchema(
                    email=email,
                    status=EmailForwardingSenderStatus.PENDING,
                ),
            )
            await self.send_pending_notification(sender)

    async def create_sender(
        self,
        company_id: UUID,
        data: AddEmailForwardingSenderSchema,
        user_id: UUID | None = None,
    ) -> ReadEmailForwardingSenderSchema:
        logger.info(
            "Creating new sender for %s in company %s", data.email, company_id
        )
        company = await self._company_service.get_by_id(company_id)
        try:
            sender = await self._repository.create(
                obj_in=CreateEmailForwardingSenderSchema(
                    company_id=company.id,
                    user_id=user_id,
                    email=data.email,
                    full_name=data.full_name,
                    position=data.position,
                    status=data.status,
                    reason=data.reason,
                )
            )
            return sender
        except IntegrityError as err:
            if err.orig.pgcode == UniqueViolationError.sqlstate:
                raise DuplicateObjectException(
                    "Email forwarding sender already exists"
                ) from err

    async def get_by_company_and_email(
        self, company_id: UUID, email: str
    ) -> ReadEmailForwardingSenderSchema:
        sender = await self._repository.get_by_company_and_email(
            company_id=company_id, email=email
        )
        if not sender:
            raise ObjectNotFoundException("Email forwarding sender not found")
        return sender

    async def get_all_by_company(
        self,
        company_id: UUID,
        status: EmailForwardingSenderStatus | None = None,
        search: str | None = None,
    ) -> list[ReadEmailForwardingSenderSchema]:
        company = await self._company_service.get_by_id(company_id)
        senders = await self._repository.get_all_by_company(
            company_id=company.id, status=status, search=search
        )
        return senders

    async def update_status(
        self,
        company_id: UUID,
        sender_id: UUID,
        user_id: UUID,
        data: UpdateEmailForwardingSenderSchema,
    ) -> ReadEmailForwardingSenderSchema:
        sender = await self._repository.get_by_filters(
            filters=(
                self._repository.model.id == sender_id,
                self._repository.model.company_id == company_id,
            ),
            many=False,
            options=(joinedload(self._repository.model.user),),
        )
        if not sender:
            raise ObjectNotFoundException("Email forwarding sender not found")
        updated_sender = await self._repository.update(
            sender,
            UpdateEmailForwardingSenderSchema(
                user_id=user_id, status=data.status, reason=data.reason
            ),
        )
        match data.status:
            case EmailForwardingSenderStatus.ALLOWED:
                await self.send_approval_notification(updated_sender)
            case EmailForwardingSenderStatus.REJECTED:
                await self.send_rejection_notification(updated_sender)
            case EmailForwardingSenderStatus.PENDING:
                await self.send_pending_notification(updated_sender)
        return updated_sender

    async def delete_sender(self, company_id: UUID, email: str) -> None:
        sender = await self._repository.get_by_company_and_email(
            company_id=company_id, email=email
        )
        if not sender:
            raise ObjectNotFoundException("Email forwarding sender not found")
        await self._repository.delete(sender)

    async def process_csv_upload(
        self,
        company_id: UUID,
        user_id: UUID,
        csv_file: UploadFile,
    ) -> tuple[list[str], list[str]]:
        successful_senders = []
        failed_rows = []

        # Read CSV content
        content = await csv_file.read()
        if len(content) > self.MAX_CSV_FILE_SIZE:
            raise FileTooLargeException()

        csv_text = content.decode("utf-8")
        csv_reader = csv.DictReader(io.StringIO(csv_text))

        for _, row in enumerate(csv_reader, start=2):
            try:
                # Validate row data
                validated_data = SenderCSVRowSchema(**row)

                sender = await self.create_sender(
                    company_id=company_id,
                    user_id=user_id,
                    data=AddEmailForwardingSenderSchema(
                        email=validated_data.email,
                        full_name=validated_data.full_name,
                        position=validated_data.position,
                        status=EmailForwardingSenderStatus.ALLOWED,
                    ),
                )
                successful_senders.append(sender.email)
                await self.send_pending_notification(sender)

            except DuplicateObjectException:
                failed_rows.append(validated_data.email)
            except ObjectNotFoundException:
                failed_rows.append(validated_data.email)
            except ValidationError as e:
                raise InvalidCSVFormatException(
                    f"Row {row} is invalid format: {e}"
                )

        return successful_senders, failed_rows

    async def send_pending_notification(
        self, sender: ReadEmailForwardingSenderSchema
    ) -> None:
        logger.info("Sending pending notification to %s", sender.email)
        await self.send_email(
            recipient_email=sender.email,
            subject="Invoice Upload Issue - Action Required",
            template_name="status-pending.html",
            context={
                "username": "Sir/Madame",
            },
        )
        company = await self._company_service.get_by_id(sender.company_id)
        admins = await self._company_member_service.get_by_roles(
            company_id=sender.company_id,
            roles=[UserRoles.PRACTICE_ADMIN, UserRoles.COMPANY_ADMIN],
        )
        if admins:
            settings_url = f"{settings.FRONTEND_URL}/clients/{company.id}/team"
            await asyncio.gather(
                *[
                    self.send_email(
                        recipient_email=admin.user.email,
                        subject="Unauthorised Invoice Forwarding Attempt",
                        template_name="status-pending-notify-admins.html",
                        context={
                            "sender_email": sender.email,
                            "timestamp": datetime.now().strftime(
                                "%Y-%m-%d %H:%M:%S"
                            ),
                            "company_name": company.name,
                            "settings_url": settings_url,
                        },
                    )
                    for admin in admins
                ]
            )

    async def send_allowed_notification(
        self, sender: ReadEmailForwardingSenderSchema
    ) -> None:
        logger.info("Sending allowed notification to %s", sender.email)
        company = await self._company_service.get_by_id(sender.company_id)
        await self.send_email(
            recipient_email=sender.email,
            subject="Invoice Upload - Approved",
            template_name="status-approved.html",
            context={
                "sender_name": sender.full_name or sender.email,
                "sender_email": sender.email,
                "company_name": company.name,
            },
        )

    async def send_rejection_notification(
        self, sender: ReadEmailForwardingSenderSchema
    ) -> None:
        logger.info("Sending rejection notification to %s", sender.email)
        company = await self._company_service.get_by_id(sender.company_id)
        await self.send_email(
            recipient_email=sender.email,
            subject="Invoice Upload - Denied",
            template_name="status-denied.html",
            context={
                "sender_name": sender.full_name or sender.email,
                "sender_email": sender.email,
                "company_name": company.name,
            },
        )

    async def send_approval_notification(
        self, sender: ReadEmailForwardingSenderSchema
    ) -> None:
        logger.info("Sending approval notification to %s", sender.email)
        company = await self._company_service.get_by_id(sender.company_id)
        await self.send_email(
            recipient_email=sender.email,
            subject="Invoice Upload - Approved",
            template_name="status-approved.html",
            context={
                "sender_name": sender.full_name or sender.email,
                "sender_email": sender.email,
                "company_name": company.name,
            },
        )

    async def send_email(
        self,
        recipient_email: str,
        subject: str,
        template_name: str,
        context: dict,
    ):
        template_path = os.path.join(
            settings.BASE_DIR, f"templates/{template_name}"
        )

        async with aiofiles.open(
            template_path, mode="r", encoding="utf-8"
        ) as file:
            content = await file.read()
            template = Template(content)

        email_body = template.render(**context)

        await self._email_sender_service.send_email(
            to=recipient_email,
            subject=subject,
            body=email_body,
        )
        logger.info("Status notification sent to %s", recipient_email)
