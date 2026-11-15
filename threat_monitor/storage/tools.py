from threat_monitor.contracts import Actor, Page, PostQuery
from threat_monitor.ingestion.pipeline import embed_query


class DatabaseInvestigationTools:
    def __init__(self, store, context):
        self.store = store
        self.company = context.company
        self.run_id = context.run_id

    async def search_posts(self, query):
        embedding = None
        if query.query:
            embedding = await embed_query(query.query, settings=self.store.settings)
        return await self.store.query_posts(query, embedding=embedding)

    async def list_posts(self, query):
        return await self.store.query_posts(query)

    async def get_post(self, version_id):
        return await self.store.get_post(version_id)

    async def get_thread(self, source_id, thread_id, *, cursor=None, limit=20, include_history=False):
        query = PostQuery(source_ids=[source_id], cursor=cursor, limit=limit, include_history=include_history)
        return await self.store.query_posts(query, thread_id=thread_id)

    async def get_company_profile(self):
        return self.company.model_copy(deep=True)

    async def get_alert_history(self, *, cursor=None, limit=20):
        if not 1 <= limit <= 100:
            raise ValueError("limit must be between 1 and 100")
        alerts = await self.store.list_alerts(self.company.id, cursor=cursor, limit=limit)
        details = [await self.store.get_alert(alert.id, company_id=self.company.id)
                   for alert in alerts.items]
        return Page(items=details, next_cursor=alerts.next_cursor)

    async def change_alert_status(self, alert_id, change):
        return await self.store.change_alert_status(
            alert_id, change, actor=Actor.MODEL, company_id=self.company.id, run_id=self.run_id,
        )
