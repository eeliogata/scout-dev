import json
from uuid import UUID

from pydantic import Field, ValidationError, field_validator

from threat_monitor.contracts import (
    AlertDetail, AlertStatusChange, Contract, Page, PostQuery, PostSummary, PostVersion,
)
from threat_monitor.storage.db import Conflict, NotFound, offset_from_cursor
from threat_monitor.storage.search import post_cursor


class InvestigationQuery(PostQuery):
    limit: int = Field(default=2, ge=1, le=100)


class QueryArguments(Contract):
    query: InvestigationQuery

    @field_validator("query")
    @classmethod
    def valid_query(cls, query):
        post_cursor(query.cursor, ranked=bool(query.query))
        if query.query is not None and not query.query.strip():
            raise ValueError("Search text must not be blank")
        return query


class PostArguments(Contract):
    version_id: UUID


class HistoryArguments(Contract):
    cursor: str | None = None
    limit: int = Field(default=2, ge=1, le=100)

    @field_validator("cursor")
    @classmethod
    def valid_cursor(cls, cursor):
        offset_from_cursor(cursor)
        return cursor


class ThreadArguments(HistoryArguments):
    include_history: bool = False

    @field_validator("cursor")
    @classmethod
    def valid_cursor(cls, cursor):
        post_cursor(cursor)
        return cursor

    source_id: UUID
    thread_id: str = Field(min_length=1)


class StatusArguments(Contract):
    alert_id: UUID
    change: AlertStatusChange


TOOL_ARGUMENTS = {
    "search_posts": (QueryArguments, "Search current versions using text and same-target filters. Results are bounded candidates; candidate_limit_reached signals a full branch. Use include_history for older versions."),
    "list_posts": (QueryArguments, "Browse current versions with filters and opaque keyset cursors. Use include_history for older versions."),
    "get_post": (PostArguments, "Read the full original text of one exact immutable post version."),
    "get_thread": (ThreadArguments, "Read current posts in a thread. Follow next_cursor; use include_history for older versions."),
    "get_company_profile": (Contract, "Read the trusted company profile bound to this analysis run."),
    "get_alert_history": (HistoryArguments, "Read this company's alerts, user decisions, evidence and status history."),
    "change_alert_status": (StatusArguments, "Change an observed company alert's status with a reason and previously unreviewed source evidence."),
}


def compact_schema(value):
    if isinstance(value, dict):
        return {key: compact_schema(item) for key, item in value.items() if key != "title"}
    if isinstance(value, list):
        return [compact_schema(item) for item in value]
    return value


def tool_definitions():
    return [
        {"type": "function", "function": {
            "name": name, "description": description, "parameters": compact_schema(arguments.model_json_schema()),
        }}
        for name, (arguments, description) in TOOL_ARGUMENTS.items()
    ]


def history_data(history):
    return {
        "items": [{
            "alert": {
                "id": str(item.alert.id),
                "title": item.alert.title,
                "category": item.alert.category,
                "status": item.alert.status,
                "primary_post_version_id": str(item.alert.primary_post_version_id or item.alert.evidence[0].post_version_id),
                "evidence_version_ids": list(dict.fromkeys(str(e.post_version_id) for e in item.alert.evidence)),
            },
            "events": [{
                "actor": event.actor,
                "previous_status": event.previous_status,
                "status": event.status,
                "reason": event.reason,
                "note": event.note,
                "created_at": event.created_at.isoformat(),
                "evidence_version_ids": list(dict.fromkeys(str(e.post_version_id) for e in event.evidence)),
            } for event in item.events],
        } for item in history.items],
        "next_cursor": history.next_cursor,
    }


def validation_message(exc):
    if isinstance(exc, ValidationError):
        return json.dumps(exc.errors(include_input=False, include_url=False, include_context=False))
    return str(exc)


class ToolDispatcher:
    def __init__(self, tools, version):
        self.tools = tools
        self.versions = {version.id: version}
        self.observed_versions = {version.id}
        self.observed_alerts = set()
        self.has_closed_alerts = False
        self.required_thread = (version.post.source_id, version.post.thread_id)
        self.thread_read = version.post.thread_id is None

    def observe(self, result):
        if isinstance(result, PostVersion):
            self.versions[result.id] = result
            self.observed_versions.add(result.id)
        if isinstance(result, Page):
            for item in result.items:
                if isinstance(item, PostSummary):
                    self.observed_versions.add(item.version_id)
                if isinstance(item, AlertDetail):
                    self.observed_alerts.add(item.alert.id)
                    self.has_closed_alerts |= item.alert.status != "open"
                    self.observed_versions.update(e.post_version_id for e in item.alert.evidence)
                    for event in item.events:
                        self.observed_versions.update(e.post_version_id for e in event.evidence)

    async def validate_evidence(self, evidence):
        for item in evidence:
            if item.post_version_id not in self.observed_versions:
                raise ValueError("Evidence must reference a post version observed during this investigation")
            if item.post_version_id not in self.versions:
                version = await self.tools.get_post(item.post_version_id)
                if version.id != item.post_version_id:
                    raise ValueError("Evidence lookup returned a different post version")
                self.observe(version)
            post = self.versions[item.post_version_id].post
            if not item.quote.strip() or item.quote not in post.title + "\n" + post.text:
                raise ValueError("Evidence quote must occur verbatim in its referenced post")

    async def execute(self, name, raw_arguments):
        if name not in TOOL_ARGUMENTS:
            return {"error": "Unknown investigation tool"}
        try:
            arguments = TOOL_ARGUMENTS[name][0].model_validate_json(raw_arguments)
        except (ValidationError, ValueError, TypeError) as exc:
            return {"error": validation_message(exc)}
        try:
            result = await self.dispatch(name, arguments)
        except (Conflict, NotFound) as exc:
            return {"error": str(exc)}
        if (name == "get_thread" and arguments.cursor is None
                and (arguments.source_id, arguments.thread_id) == self.required_thread):
            self.thread_read = True
        self.observe(result)
        if name == "get_alert_history":
            return history_data(result)
        return result.model_dump(mode="json", exclude_none=True, exclude_defaults=True)

    async def dispatch(self, name, arguments):
        match name:
            case "search_posts":
                return await self.tools.search_posts(arguments.query)
            case "list_posts":
                return await self.tools.list_posts(arguments.query)
            case "get_post":
                return await self.tools.get_post(arguments.version_id)
            case "get_thread":
                return await self.tools.get_thread(
                    arguments.source_id, arguments.thread_id, cursor=arguments.cursor, limit=arguments.limit,
                    **({"include_history": True} if arguments.include_history else {}),
                )
            case "get_company_profile":
                return await self.tools.get_company_profile()
            case "get_alert_history":
                return await self.tools.get_alert_history(cursor=arguments.cursor, limit=arguments.limit)
            case "change_alert_status":
                if arguments.alert_id not in self.observed_alerts:
                    raise Conflict("Read this alert in get_alert_history before changing its status")
                if not arguments.change.reason.strip() or not arguments.change.evidence:
                    raise Conflict("Model status changes require a reason and source evidence")
                try:
                    await self.validate_evidence(arguments.change.evidence)
                    return await self.tools.change_alert_status(arguments.alert_id, arguments.change)
                except ValueError as exc:
                    raise Conflict(str(exc)) from exc
        raise ValueError("Unknown investigation tool")
