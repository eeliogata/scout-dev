from typing import Protocol
from uuid import UUID

from threat_monitor.contracts import (
    AlertDetail,
    AlertEvent,
    AlertStatusChange,
    Company,
    Page,
    PostQuery,
    PostSummary,
    PostVersion,
)


class InvestigationTools(Protocol):
    """Bind one instance to a company and run; never take that scope from the model."""

    async def search_posts(self, query: PostQuery) -> Page[PostSummary]: ...

    async def list_posts(self, query: PostQuery) -> Page[PostSummary]: ...

    async def get_post(self, version_id: UUID) -> PostVersion: ...

    async def get_thread(
        self,
        source_id: UUID,
        thread_id: str,
        *,
        cursor: str | None = None,
        limit: int = 20,
        include_history: bool = False,
    ) -> Page[PostSummary]: ...

    async def get_company_profile(self) -> Company: ...

    async def get_alert_history(
        self, *, cursor: str | None = None, limit: int = 20
    ) -> Page[AlertDetail]: ...

    async def change_alert_status(
        self, alert_id: UUID, change: AlertStatusChange
    ) -> AlertEvent: ...
