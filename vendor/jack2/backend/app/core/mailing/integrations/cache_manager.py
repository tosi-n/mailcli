import json
import random
import string
from uuid import UUID

from app.core.context_vars import Referrer
from app.core.services.cache import CacheService


class MailingIntegrationsCacheManager:
    def __init__(self):
        self.__cache_service = CacheService()

    async def generate_and_cache_state_string(
        self,
        company_id: UUID,
        user_id: UUID,
        platform_name: str,
        state: str = None,
    ) -> str:
        # Generate a state for the platform
        value = f"{company_id}@{user_id}@{platform_name}@{Referrer.get('')}"

        if state is None:
            # the folowing is not used in security encryption context
            state = "".join(
                random.choices(
                    string.ascii_uppercase + string.digits, k=32
                )  # nosec
            )

        await self.__cache_service.set_value(state, value, 300)
        return state

    async def generate_and_cache_forwarding_state_string(
        self,
        platform_name: str,
        state: str = None,
    ) -> str:
        if state is None:
            # the folowing is not used in security encryption context
            state = "".join(
                random.choices(
                    string.ascii_uppercase + string.digits, k=32
                )  # nosec
            )

        await self.__cache_service.set_value(state, platform_name, 300)

    async def store_forwarding_watch(
        self,
        timestamp: str,
    ):
        platform_name = "FORWARDING_WATCH"
        await self.__cache_service.set_value(platform_name, timestamp)

    async def store_forwarding_notification(
        self,
        notification: str,
    ):
        platform_name = "FORWARDING_NOTIFICATION"
        await self.__cache_service.set_value(platform_name, notification)

    async def get_forwarding_watch(
        self,
    ):
        platform_name = "FORWARDING_WATCH"
        return await self.__cache_service.get_value(platform_name)

    async def get_forwarding_notification(
        self,
    ):
        platform_name = "FORWARDING_NOTIFICATION"
        return await self.__cache_service.get_value(platform_name)

    async def validate_and_extract_state(
        self,
        state: str,
    ) -> tuple[str, str, str, str] | None:
        cached_value = await self.__cache_service.get_value(state)
        if cached_value:
            company_id, user_id, platform_name, referrer = str(
                cached_value
            ).split("@")
            return company_id, user_id, platform_name, referrer
        return None

    async def validate_and_extract_forwarding_state(
        self,
        state: str,
    ) -> str | None:
        return await self.__cache_service.get_value(state)

    async def store_auth_details(
        self,
        platform_name: str,
        auth_details: dict,
        user_id: UUID | None = None,
        company_id: UUID | None = None,
        expiry=3600,
    ):
        auth_key = self.get_auth_key(
            platform_name=platform_name,
            user_id=user_id,
            company_id=company_id,
        )
        auth_details = json.dumps(auth_details)
        await self.__cache_service.set_value(auth_key, auth_details, expiry)
        return

    async def fetch_auth_details(
        self,
        platform_name: str,
        user_id: UUID | None,
        company_id: UUID | None,
    ) -> dict | None:
        auth_key = self.get_auth_key(
            platform_name=platform_name,
            user_id=user_id,
            company_id=company_id,
        )
        auth_details = await self.__cache_service.get_value(auth_key)

        if auth_details is None:
            return None

        return json.loads(auth_details)

    async def delete_auth(
        self,
        platform_name: str,
        user_id: UUID | None,
        company_id: UUID | None,
    ):
        token_key = self.get_auth_key(
            platform_name=platform_name,
            user_id=user_id,
            company_id=company_id,
        )
        await self.__cache_service.delete_value(token_key)

    async def store_gmail_history_id(
        self, user_id: UUID | None, company_id: UUID | None, history_id: str
    ):
        await self.__cache_service.set_value(
            key=self.get_gmail_history_key(user_id, company_id),
            value=history_id,
        )

    async def get_gmail_history_id(self, user_id: UUID, company_id: UUID):
        return await self.__cache_service.get_value(
            self.get_gmail_history_key(user_id=user_id, company_id=company_id)
        )

    @staticmethod
    def get_auth_key(
        platform_name: str, user_id: UUID | None, company_id: UUID | None
    ) -> str:
        if user_id is None:
            return f"{platform_name}"
        return f"{platform_name}_{company_id}_{user_id}"

    @staticmethod
    def get_gmail_history_key(
        user_id: UUID | None, company_id: UUID | None
    ) -> str:
        if user_id is None:
            return "FORWARDINGHISTORY"
        return f"GMAILHISTORYID_{company_id}_{user_id}"


mailing_integrations_cache_manager = MailingIntegrationsCacheManager()
