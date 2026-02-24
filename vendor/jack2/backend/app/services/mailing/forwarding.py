import io
import json
import re
from email import message_from_string
from uuid import UUID

import httpx
from botocore.exceptions import ClientError
from fastapi import UploadFile
from PIL import Image
from PIL.ExifTags import TAGS
from pypdf import PdfWriter

from app.core.config import settings
from app.core.enums import DocumentSource, MailingIntegrations
from app.core.exceptions import (
    FailedToConvertEmailToPDFException,
    FailedToFetchEmailFromS3Exception,
    ForbiddenException,
    ForwardingUnkownSNSMessageException,
    ObjectNotFoundException,
)
from app.core.loggers import logger
from app.core.utils.html_to_pdf import HTMLToPDFConverter
from app.messaging.messages import (
    EmailToPdfConversionMessage,
    MailingWebhookDataMessage,
)
from app.messaging.producers.email_pdf_conversion import (
    EmailToPdfConversionProducer,
)
from app.messaging.producers.mailing_webhooks import MailingWebhooksProducer
from app.models import User
from app.schemas.mailing import SNSMessageSchema
from app.schemas.mailing.sns import SNSMailingWebhookMessageSchema
from app.services.mailing.base import BaseMailingService
from app.services.mailing.email_forwarding_sender import (
    EmailForwardingSenderService,
)

__all__ = ["EmailForwardingService"]


class EmailForwardingService(BaseMailingService):
    INTEGRATION_TYPE = MailingIntegrations.EMAIL_FORWARDING
    MIN_ATTACHMENT_SIZE = 5000  # 5KB
    EXTENSION_TO_CONTENT_TYPE = {
        "pdf": "application/pdf",
        "jpg": "image/jpeg",
        "png": "image/png",
        "jpeg": "image/jpeg",
        "zip": "application/zip",
    }
    UNSUPPORTED_CONTENT_TYPES = [
        "application/octet-stream",
    ]
    MIN_ATTAHMENT_DIMENSIONS = 300
    LOGO_KEYWORDS = ["logo", "sign", "icon"]
    LOGO_ASPECT_RATIO = (0.5, 2.0)
    SCANNER_SOFTWARE_KEYWORDS = [
        "scan",
        "adobe",
        "acrobat",
        "docuscan",
        "office lens",
        "camscanner",
        "xerox",
        "hp",
        "canon",
        "epson",
        "brother",
        "scansnap",
    ]

    async def handle_webhook_event(self, webhook_data: SNSMessageSchema):
        match webhook_data.type:
            case "SubscriptionConfirmation":
                await self.handle_subscription_confirmation(webhook_data)
            case "Notification":
                await self.handle_subscription_notification(webhook_data)
            case _:
                logger.error(
                    "Unknown SNS message type: %s",
                    webhook_data.type,
                    extra={"webhook_data": webhook_data},
                )
                raise ForwardingUnkownSNSMessageException

    async def handle_subscription_confirmation(
        self, webhook_data: SNSMessageSchema
    ):
        try:
            subscribe_url = webhook_data.subscribe_url
            async with httpx.AsyncClient() as client:
                await client.get(subscribe_url)
        except httpx.HTTPError as e:
            logger.error(
                "Failed to confirm SNS subscription: %s",
                str(e),
                extra={"subscribe_url": subscribe_url},
            )
            raise e
        logger.info(
            "Confirmed SNS subscription: %s",
            subscribe_url,
        )

    async def handle_subscription_notification(
        self, webhook_data: SNSMessageSchema
    ):
        message_json = json.loads(webhook_data.message)

        bucket_name = message_json["receipt"]["action"]["bucketName"]
        object_key = message_json["receipt"]["action"]["objectKey"]

        logger.info(
            "Received SNS S3 notification for email forwarding: %s",
            message_json,
            extra={
                "bucket_name": bucket_name,
                "object_key": object_key,
            },
        )

        await MailingWebhooksProducer().send(
            MailingWebhookDataMessage(
                platform_name=self.INTEGRATION_TYPE,
                data={
                    "bucket_name": bucket_name,
                    "object_key": object_key,
                },
            )
        )

    async def process_webhook_message(self, webhook_message: dict):
        webhook_message = SNSMailingWebhookMessageSchema(**webhook_message)
        raw_email = await self.fetch_email_from_s3(
            object_key=webhook_message.object_key,
            bucket_name=webhook_message.bucket_name,
        )
        email_message = self.parse_raw_email(raw_email)

        company = await self.get_company_info(email_message["to_email"])
        if not company:
            logger.error(
                "Company not found for forwarding email - %s",
                email_message["to_email"],
                extra={"from_email": email_message["from_email"]},
            )
            await self.send_email(
                recipient_email=email_message["from_email"],
                subject="Jack Hasn't Received Your Document",
                template_name="status-failure.html",
                context={
                    "user_name": "Sir/Madame",
                    "reason": "Company not found",
                },
            )
            return None

        sender = None
        user = await self._user_service.get_user_by_email_if_exists(
            email=email_message["from_email"]
        )
        can_access = (
            await self._check_if_user_can_access(
                company_id=company.id,
                user=user,
            )
            if user
            else False
        )
        if not can_access:
            sender = await EmailForwardingSenderService(
                self.db
            ).fetch_or_notify_sender(
                company_id=company.id,
                email=email_message["from_email"],
            )
            if not sender:
                return None

            user = await self._user_service.get_by_id(sender.user_id)

        if email_message["attachments"]:
            if (
                company.is_memo_processing_client
                and email_message["text_body"]
            ):
                await EmailToPdfConversionProducer().send(
                    EmailToPdfConversionMessage(
                        company_id=company.id,
                        user_id=user.id,
                        sender_id=sender.id if sender else None,
                        object_key=webhook_message.object_key,
                        bucket_name=webhook_message.bucket_name,
                        source=MailingIntegrations.EMAIL_FORWARDING,
                        is_memo_processing=True,
                    )
                )
                return
            logger.info(
                "Saving %s attachments from message %s from %s to %s",
                len(email_message["attachments"]),
                email_message["message_id"],
                email_message["from_email"],
                email_message["to_email"],
                extra={
                    "message_id": email_message["message_id"],
                    "from_email": email_message["from_email"],
                    "to_email": email_message["to_email"],
                    "count": len(email_message["attachments"]),
                },
            )
            await self._document_service.upload_files(
                company_id=company.id,
                user=user,
                uploaded_files=email_message["attachments"],
                source=DocumentSource.EMAIL_FORWARDING,
                email_forwarding_sender_id=sender.id if sender else None,
            )
            logger.info(
                "Email attachments uploaded successfully",
                extra={
                    "user_id": user.id,
                    "company_id": company.id,
                    "source": MailingIntegrations.EMAIL_FORWARDING,
                    "no_of_attachments": len(email_message["attachments"]),
                },
            )
        else:
            logger.info(
                "No attachments found in message %s from %s to %s",
                email_message["message_id"],
                email_message["from_email"],
                email_message["to_email"],
                extra={
                    "message_id": email_message["message_id"],
                    "from_email": email_message["from_email"],
                    "to_email": email_message["to_email"],
                },
            )
            await EmailToPdfConversionProducer().send(
                EmailToPdfConversionMessage(
                    user_id=user.id,
                    company_id=company.id,
                    object_key=webhook_message.object_key,
                    bucket_name=webhook_message.bucket_name,
                    source=MailingIntegrations.EMAIL_FORWARDING,
                    sender_id=sender.id if sender else None,
                )
            )

    async def fetch_email_from_s3(self, object_key: str, bucket_name: str):
        async with self._boto_session.client(
            "s3",
            endpoint_url=settings.AWS_ENDPOINT_URL_CUSTOM,
        ) as s3_client:
            logger.info(
                "Fetching email from S3: %s",
                object_key,
                extra={
                    "bucket_name": bucket_name,
                },
            )
            try:
                response = await s3_client.get_object(
                    Bucket=bucket_name,
                    Key=object_key,
                )
                body_bytes = await response["Body"].read()
                decoded_mail = body_bytes.decode("utf-8")
                logger.info(
                    "Email fetched from S3: %s",
                    extra={
                        "object_key": object_key,
                        "bucket_name": bucket_name,
                    },
                )
                return decoded_mail
            except ClientError as e:
                logger.error(
                    "Failed to fetch email from S3: %s",
                    str(e),
                    extra={
                        "object_key": object_key,
                        "bucket_name": bucket_name,
                    },
                )
                raise FailedToFetchEmailFromS3Exception from e

    def parse_raw_email(self, raw_email: str) -> dict:
        msg = message_from_string(raw_email)

        from_email, to_email, subject, message_id = (
            self._extract_basic_headers(msg)
        )
        text_body, html_body, attachments = self._extract_email_parts(msg)

        logger.info(
            "Number of attachments: %s",
            len(attachments),
            extra={
                "message_id": message_id,
                "from_email": from_email,
                "to_email": to_email,
            },
        )
        sanitized_attachments = self._sanitize_attachments(attachments)
        logger.info(
            "Number of sanitized attachments: %s",
            len(sanitized_attachments) if sanitized_attachments else 0,
            extra={
                "message_id": message_id,
                "from_email": from_email,
                "to_email": to_email,
            },
        )

        parsed_message = {
            "from_email": from_email,
            "to_email": to_email,
            "subject": subject,
            "message_id": message_id,
            "text_body": text_body,
            "html_body": html_body,
            "attachments": sanitized_attachments,
        }
        logger.info(
            "Email parsed successfully",
            extra={
                "message_id": message_id,
                "from_email": from_email,
                "to_email": to_email,
            },
        )
        return parsed_message

    def _extract_basic_headers(self, msg) -> tuple:
        # X-Forwarded-For header is used for autoforwarded emails.
        # The format is:
        # X-Forwarded-For: <original-email> <forwarded-email>
        # We extract the original email and the forwarded email from the header
        x_forwarded_for = msg.get("X-Forwarded-For", "").lower()
        if x_forwarded_for:
            emails = x_forwarded_for.split()
            if len(emails) >= 2:
                from_email = emails[0]
                to_email = emails[1]
                subject = msg.get("Subject", "")
                message_id = msg.get("Message-ID", "")
                return (
                    from_email.strip(),
                    to_email.strip(),
                    subject.strip(),
                    message_id.strip(),
                )

        from_email = msg.get("From", "").lower()
        to_email = msg.get("To", "").lower()
        subject = msg.get("Subject", "")
        message_id = msg.get("Message-ID", "")
        email_forwarding_regex = (
            r"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"
        )
        from_email_match = re.search(email_forwarding_regex, from_email)
        if from_email_match:
            from_email = from_email_match.group(0)

        to_email_match = re.search(email_forwarding_regex, to_email)
        if to_email_match:
            to_email = to_email_match.group(0)

        return (
            from_email.strip(),
            to_email.strip(),
            subject.strip(),
            message_id.strip(),
        )

    def _extract_email_parts(self, msg) -> tuple:
        text_body = None
        html_body = None
        attachments = []

        for part in msg.walk():
            if part.get_content_maintype() == "multipart":
                continue

            content_type = part.get_content_type()
            content_disposition = (
                part.get("Content-Disposition") or ""
            ).lower()

            filename = part.get_filename()
            if "attachment" in content_disposition or filename:
                payload = part.get_payload(decode=True)
                if payload:
                    # If content type is application/octet-stream, try to determine
                    # from extension
                    if (
                        content_type in self.UNSUPPORTED_CONTENT_TYPES
                        and filename
                    ):
                        content_type = self._get_content_type_from_filename(
                            filename
                        )
                        if not content_type:
                            logger.error(
                                "Content type not found for attachment %s",
                                filename,
                                extra={
                                    "message_id": msg.get("Message-ID", "")
                                },
                            )
                            continue

                    attachments.append(
                        UploadFile(
                            filename=filename,
                            file=io.BytesIO(payload),
                            headers={"content-type": content_type},
                            size=len(payload),
                        )
                    )
                else:
                    logger.error(
                        "Attachment %s is empty",
                        filename,
                        extra={
                            "message_id": msg.get("Message-ID", ""),
                        },
                    )

            elif content_type == "text/plain" and text_body is None:
                charset = part.get_content_charset() or "utf-8"
                text_body = part.get_payload(decode=True).decode(
                    charset, errors="replace"
                )

            elif content_type == "text/html" and html_body is None:
                charset = part.get_content_charset() or "utf-8"
                html_body = part.get_payload(decode=True).decode(
                    charset, errors="replace"
                )

        return text_body, html_body, attachments

    def _get_content_type_from_filename(self, filename: str) -> str | None:
        """Determine content type from filename."""
        return self.EXTENSION_TO_CONTENT_TYPE.get(
            filename.split(".")[-1].lower()
        )

    def _sanitize_attachments(self, attachments: list[dict]) -> list[dict]:
        """
        Filter out attachments that are too small and are not of type pdf.
        Also filters out logos based on image metadata and filename.
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
            and not self._is_likely_logo(attachment)
        ]

    def _is_likely_logo(self, attachment) -> bool:
        if self._is_logo_by_filename(attachment):
            return True

        if attachment.content_type.startswith("image/"):
            try:
                img = Image.open(io.BytesIO(attachment.file.getvalue()))

                if self._is_logo_by_dimensions(img):
                    return True

                # if not self._has_valid_exif_data(img):
                #     return True

                # Reset file pointer for future reads
                attachment.file.seek(0)
            except Exception as e:
                logger.warning(
                    "Failed to process image metadata: %s",
                    str(e),
                    extra={
                        "attachment_filename": attachment.filename,
                        "content_type": attachment.content_type,
                    },
                )

        return False

    def _is_logo_by_filename(self, attachment) -> bool:
        if any(
            keyword in attachment.filename.lower()
            for keyword in self.LOGO_KEYWORDS
        ):
            logger.info(
                "Attachment is likely a logo based on filename",
                extra={
                    "attachment_filename": attachment.filename,
                },
            )
            return True
        return False

    def _is_logo_by_dimensions(self, img) -> bool:
        width, height = img.size
        aspect_ratio = width / height if height != 0 else 0

        if (
            width < self.MIN_ATTAHMENT_DIMENSIONS
            or height < self.MIN_ATTAHMENT_DIMENSIONS
        ) and (
            self.LOGO_ASPECT_RATIO[0]
            <= aspect_ratio
            <= self.LOGO_ASPECT_RATIO[1]
        ):
            logger.info(
                "Attachment is likely a logo based on image metadata",
                extra={
                    "width": width,
                    "height": height,
                    "aspect_ratio": aspect_ratio,
                },
            )
            return True
        return False

    def _has_valid_exif_data(self, img) -> bool:
        exif_data = self._extract_exif_data(img)
        if not exif_data:
            return False

        return (
            self._has_camera_info(exif_data)
            or self._has_gps_data(exif_data)
            or self._has_capture_time(exif_data)
            or self._is_from_scanner(exif_data)
        )

    def _extract_exif_data(self, img) -> dict:
        if not hasattr(img, "_getexif"):
            return {}

        raw_exif = img._getexif()  # pylint: disable=protected-access
        if not raw_exif:
            return {}

        return {
            TAGS.get(tag_id, tag_id): value
            for tag_id, value in raw_exif.items()
        }

    def _has_camera_info(self, exif_data: dict) -> bool:
        return "Make" in exif_data or "Model" in exif_data

    def _has_gps_data(self, exif_data: dict) -> bool:
        return any(tag.startswith("GPS") for tag in exif_data)

    def _has_capture_time(self, exif_data: dict) -> bool:
        return "DateTimeOriginal" in exif_data

    def _is_from_scanner(self, exif_data: dict) -> bool:
        software = exif_data.get("Software", "")
        if not isinstance(software, str):
            return False
        software_lower = software.lower()
        return any(
            keyword in software_lower
            for keyword in self.SCANNER_SOFTWARE_KEYWORDS
        )

    async def process_html_to_pdf_conversion_message(
        self, message: EmailToPdfConversionMessage
    ):
        raw_email = await self.fetch_email_from_s3(
            object_key=message.object_key, bucket_name=message.bucket_name
        )
        email_message = self.parse_raw_email(raw_email)
        pdf_file = await self._get_email_html_body_as_pdf(
            email_message["html_body"]
        ) or await self._get_email_text_body_as_pdf(email_message["text_body"])
        user = await self._user_service.get_by_id(message.user_id)
        if pdf_file:
            await self._document_service.upload_files(
                company_id=message.company_id,
                user=user,
                uploaded_files=[pdf_file],
                source=DocumentSource.EMAIL_FORWARDING,
                email_forwarding_sender_id=message.sender_id,
            )
            logger.info(
                "Email converted to PDF and uploaded successfully",
                extra={
                    "user_id": message.user_id,
                    "company_id": message.company_id,
                    "source": message.source,
                    "bucket_name": message.bucket_name,
                    "object_key": message.object_key,
                },
            )
        else:
            logger.error(
                "Failed to convert email to PDF ",
                extra={
                    "user_id": message.user_id,
                    "company_id": message.company_id,
                    "source": message.source,
                    "bucket_name": message.bucket_name,
                    "object_key": message.object_key,
                },
            )
            raise FailedToConvertEmailToPDFException

    async def get_company_info(self, to_email: str) -> tuple[str]:
        try:
            email_prefix, document_email = to_email.split("+")
            if email_prefix != settings.EMAIL_FORWARD_PREFIX:
                logger.error(
                    "Email prefix is not valid - %s",
                    email_prefix,
                    extra={"to_email": to_email},
                )
                return None
            company_email_suffix, email_domain = document_email.split("@")
            logger.info(
                "Company email suffix: %s and email domain: %s",
                company_email_suffix,
                email_domain,
                extra={"to_email": to_email},
            )
            company_info = (
                await self._company_service.get_company_by_email_suffix(
                    email_suffix=company_email_suffix
                )
            )
            return company_info
        except ObjectNotFoundException:
            logger.error(
                "Company not found in db for email suffix - %s",
                company_email_suffix,
                extra={"to_email": to_email},
            )
            return None
        except ValueError:
            logger.error(
                "Invalid email format - %s",
                to_email,
            )
            return None

    async def _check_if_user_can_access(
        self, company_id: UUID, user: User
    ) -> bool:
        try:
            return await self._company_service.check_if_user_can_access(
                company_id=company_id, user_id=user.id
            )
        except ForbiddenException:
            logger.error(
                "User does not have access to company - %s",
                company_id,
                extra={"user_id": user.id},
            )
            return False

    async def _get_email_html_body_as_pdf(
        self, html_body: str
    ) -> UploadFile | None:
        try:
            print("HTML body: %s", html_body)
            pdf_data = await HTMLToPDFConverter.convert_html_to_pdf(
                html_body
            )  # pylint: disable=line-too-long
            return (
                UploadFile(
                    filename="email_fwd_html_output.pdf",
                    file=io.BytesIO(pdf_data),
                    headers={"content-type": "application/pdf"},
                )
                if pdf_data
                else None
            )
        except Exception as e:
            print("Failed to convert HTML to PDF - %s", str(e))
            logger.exception("Failed to convert HTML to PDF - %s", str(e))
        return None

    async def _get_email_text_body_as_pdf(
        self, text_body
    ) -> UploadFile | None:
        try:
            pdf_data = await HTMLToPDFConverter.convert_text_to_pdf(text_body)

            return (
                UploadFile(
                    filename="email_fwd_text_output.pdf",
                    file=io.BytesIO(pdf_data),
                    headers={"content-type": "application/pdf"},
                )
                if pdf_data
                else None
            )
        except Exception as e:
            logger.exception("Failed to convert text to PDF - %s", str(e))

        return None

    async def process_memo_message(self, message: EmailToPdfConversionMessage):
        email = await self.fetch_email_from_s3(
            object_key=message.object_key, bucket_name=message.bucket_name
        )
        email_message = self.parse_raw_email(email)
        email_body_pdf = await self._get_email_text_body_as_pdf(
            email_message["text_body"]
        )
        attachments = email_message["attachments"]

        for attachment in attachments:
            if not email_body_pdf:
                logger.error(
                    "Failed to convert email body to PDF",
                    extra={"company_id": message.company_id},
                )
                merged_pdf = None
            elif attachment.content_type == "application/pdf":
                merged_pdf = await self._merge_pdfs(attachment, email_body_pdf)
            else:
                converted_pdf = await self._convert_attachment_to_pdf(
                    attachment
                )
                merged_pdf = (
                    await self._merge_pdfs(converted_pdf, email_body_pdf)
                    if converted_pdf
                    else None
                )
            if not merged_pdf:
                logger.error(
                    "Failed to merge email body with attachment. "
                    "Using attachment as is.",
                    extra={
                        "company_id": message.company_id,
                        "user_id": message.user_id,
                        "attachment_id": attachment.filename,
                    },
                )
                merged_pdf = attachment
            user = await self._user_service.get_by_id(message.user_id)
            await self._document_service.upload_files(
                company_id=message.company_id,
                user=user,
                uploaded_files=[merged_pdf],
                source=DocumentSource.EMAIL_FORWARDING,
                memo=email_message["text_body"],
                email_forwarding_sender_id=message.sender_id,
            )

            logger.info(
                "Successfully merged email body with attachment",
                extra={
                    "company_id": message.company_id,
                    "user_id": message.user_id,
                    "attachment_id": attachment.filename,
                },
            )

    async def _convert_attachment_to_pdf(
        self, attachment
    ) -> UploadFile | None:
        try:
            if not attachment.content_type.startswith("image/"):
                return None

            img = Image.open(attachment.file)
            if img.mode in ("RGBA", "P"):
                img = img.convert("RGB")

            pdf_buf = io.BytesIO()
            img.save(pdf_buf, format="PDF")
            pdf_buf.seek(0)

            pdf_bytes = pdf_buf.getvalue()
            filename = attachment.filename.split(".")[0]
            return UploadFile(
                filename=f"{filename}.pdf",
                file=io.BytesIO(pdf_bytes),
                headers={"content-type": "application/pdf"},
            )

        except Exception as exc:
            logger.exception("Failed to convert attachment to PDF: %s", exc)
            return None

    async def _merge_pdfs(
        self, pdf1: UploadFile, pdf2: UploadFile
    ) -> UploadFile | None:
        """
        Merge two PDF files into one.
        Returns the merged PDF as bytes or None if merging failed.
        """
        try:
            merger = PdfWriter()

            merger.append(pdf1.file)

            merger.append(pdf2.file)

            output_buffer = io.BytesIO()
            merger.write(output_buffer)
            merger.close()

            bytes_pdf = output_buffer.getvalue()
            return UploadFile(
                filename=pdf1.filename,
                file=io.BytesIO(bytes_pdf),
                headers={"content-type": "application/pdf"},
            )

        except Exception as e:
            logger.error(
                "Failed to merge PDFs",
                extra={"error": str(e)},
            )
            return None
