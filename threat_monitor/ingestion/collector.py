import asyncio
import time
import hashlib
import json
from collections.abc import AsyncIterator
from datetime import datetime, timezone

from bs4 import BeautifulSoup
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from soupsieve import SelectorSyntaxError, compile as compile_selector

from threat_monitor.config import Settings
from threat_monitor.contracts import NormalizedPost, Source
from threat_monitor.ingestion.sessions import session_headers
from threat_monitor.ingestion.providers import extract_context_html, fetch_page
from threat_monitor.ingestion.urls import origin as _origin, resolve_url as _url, thread_key


class ForumSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, str_strip_whitespace=True)

    thread_link_selector: str | None = None
    thread_urls: list[str] = Field(default_factory=list, max_length=100)
    session_ref: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_-]{1,64}$")
    authenticated_selector: str | None = None
    login_selector: str | None = None
    challenge_selector: str | None = None
    ready_selector: str | None = None
    request_delay_seconds: float = Field(default=5.0, ge=0, le=300)
    thread_title_selector: str
    post_selector: str
    body_selector: str
    permalink_selector: str
    listing_next_selector: str | None = None
    thread_next_selector: str | None = None
    empty_listing_selector: str | None = None
    author_selector: str | None = None
    published_at_selector: str | None = None
    post_id_attribute: str = Field(default="id", min_length=1)
    max_listing_pages: int = Field(default=1, gt=0)
    max_threads: int = Field(default=5, gt=0)
    max_thread_pages: int = Field(default=2, gt=0)


def _settings(source: Source) -> ForumSettings:
    if source.parser != "css_forum":
        raise ValueError("Unsupported forum parser. Expected css_forum")
    try:
        config = ForumSettings.model_validate(source.collection_settings)
    except ValidationError as error:
        fields = ", ".join(str(issue["loc"][0]) for issue in error.errors())
        raise ValueError(f"Invalid forum collection settings: {fields}") from None
    if not config.thread_urls and not config.thread_link_selector:
        raise ValueError("Supply thread_urls or a thread_link_selector")
    if config.session_ref and not config.authenticated_selector:
        raise ValueError("Authenticated collection requires an authenticated_selector")
    for name, selector in config.model_dump().items():
        if name.endswith("_selector") and selector is not None:
            try:
                compile_selector(selector)
            except SelectorSyntaxError:
                raise ValueError(f"Invalid CSS in forum setting {name}") from None
    return config


def _link(node, page_url, origin, *, permalink=False):
    return _url(page_url, node.get("href", ""), origin, permalink=permalink)


class CollectionIncomplete(RuntimeError):
    pass


async def _pages(start, limit, next_selector, origin, stage, *, settings, config, request_clock,
                 progress=None, save_progress=None):
    if progress is not None and progress.get("done"):
        return
    visited = set(progress.get("visited", [])) if progress is not None else set()
    url = progress.get("next_url", start) if progress is not None else start
    for _ in range(limit):
        try:
            if request_clock:
                await asyncio.sleep(max(0, config.request_delay_seconds - (time.monotonic() - request_clock[0])))
            headers = session_headers(config.session_ref, url) if config.session_ref else None
            final_url, html = await fetch_page(url, settings=settings, headers=headers, wait_for=config.ready_selector)
            request_clock[:] = [time.monotonic()]
            final_url = _url(url, final_url, origin)
            if final_url in visited:
                raise ValueError("Repeated pagination URL")
            visited.update((url, final_url))
            page = BeautifulSoup(html, "html.parser")
            if config.challenge_selector and page.select_one(config.challenge_selector):
                raise RuntimeError("Forum challenge requires manual browser interaction")
            if (config.login_selector and page.select_one(config.login_selector)) or (
                config.authenticated_selector and not page.select_one(config.authenticated_selector)
            ):
                raise RuntimeError("Forum session is not authenticated; log in and import again")
            next_link = page.select_one(next_selector) if next_selector else None
            next_url = _link(next_link, final_url, origin) if next_link else None
            if next_url and stage == "thread" and config.thread_urls and thread_key(next_url) != thread_key(start):
                raise ValueError("Pagination leaves the selected thread")
            if next_url in visited:
                raise ValueError("Repeated pagination URL")
        except (ValueError, RuntimeError) as error:
            raise RuntimeError(f"Forum {stage} page: {error}") from None
        yield page, final_url, datetime.now(timezone.utc)
        if progress is not None:
            progress.update(next_url=next_url, visited=sorted(visited), done=next_url is None)
            await save_progress()
        if next_url is None:
            return
        url = next_url
    if progress is not None:
        raise CollectionIncomplete(f"{stage.capitalize()} page budget reached; remaining pages saved for retry")


def _text(node, selector):
    match = node.select_one(selector) if selector else None
    return match.get_text(" ", strip=True) if match else ""


def _published_at(node, selector):
    match = node.select_one(selector) if selector else None
    if match is None or match.name != "time":
        return None
    try:
        stamp = datetime.fromisoformat(match.get("datetime", ""))
        return stamp.astimezone(timezone.utc) if stamp.tzinfo is not None else None
    except (ValueError, OverflowError):
        return None


def _post_text(body):
    for element in body.select("script, style, template"):
        element.decompose()
    for element in body.select("br"):
        element.replace_with("\n")
    for element in body.select("p, div, li, pre, blockquote"):
        element.insert_after("\n")
    return body.get_text().strip()


async def _thread_posts(url, source_id, config, origin, *, settings, request_clock,
                        progress=None, save_progress=None):
    title = progress.get("title") if progress is not None else None
    thread_id = progress.get("thread_id") if progress is not None else None
    async for page, page_url, fetched_at in _pages(
        url, config.max_thread_pages, config.thread_next_selector, origin, "thread", settings=settings, config=config, request_clock=request_clock,
        progress=progress, save_progress=save_progress,
    ):
        if title is None:
            thread_id = page_url
            title = _text(page, config.thread_title_selector)
            if not title:
                raise RuntimeError("Forum thread parse failed: thread title is missing")
            if progress is not None:
                progress.update(title=title, thread_id=thread_id)
        posts = page.select(config.post_selector)
        if not posts:
            raise RuntimeError("Forum thread parse failed: no posts found")
        for post in posts:
            body = post.select_one(config.body_selector)
            permalink = post.select_one(config.permalink_selector)
            body_html = str(body) if body is not None else ""
            text = _post_text(body) if body else ""
            if not text or permalink is None:
                raise RuntimeError("Forum post parse failed: body or permalink is missing")
            try:
                post_url = _link(permalink, page_url, origin, permalink=True)
                extraction = None
                if origin[1].rstrip(".").endswith(".onion"):
                    extraction = await extract_context_html(body_html, settings=settings)
                yield NormalizedPost(
                    source_id=source_id,
                    external_id=post.get(config.post_id_attribute, "").strip() or None,
                    thread_id=thread_id,
                    url=post_url,
                    author=_text(post, config.author_selector) or None,
                    published_at=_published_at(post, config.published_at_selector),
                    fetched_at=fetched_at,
                    title=title,
                    text=text,
                    content_hash=hashlib.sha256(json.dumps(
                        [title, text], ensure_ascii=False, separators=(",", ":"),
                    ).encode("utf-8")).hexdigest(),
                    context_extraction=extraction,
                )
            except ValidationError:
                raise RuntimeError("Forum post parse failed: invalid normalized post") from None
            except ValueError as error:
                raise RuntimeError(f"Forum post parse failed: {error}") from None


async def collect_source(source: Source, *, settings: Settings, checkpoint=None,
                         save_checkpoint=None, remember_thread=None, recent_threads=()) -> AsyncIterator[NormalizedPost]:
    config = _settings(source)
    url = str(source.url)
    origin = _origin(url)
    start = _url(url, url, origin)
    request_clock = []
    state = checkpoint if checkpoint is not None else {}
    threads = state.setdefault("threads", {})
    queue = state.setdefault("pending_threads", [])
    scanned = 0

    async def save():
        if save_checkpoint is not None:
            await save_checkpoint(state)

    async def discover(target, *, observed=True):
        target = _url(start, target, origin)
        if target not in queue:
            queue.append(target)
        if observed and remember_thread is not None:
            await remember_thread(target)
        return target

    async def pending():
        nonlocal scanned
        for target in queue:
            progress = threads.setdefault(target, {})
            if progress.get("done"):
                continue
            if scanned >= config.max_threads:
                if checkpoint is not None:
                    raise CollectionIncomplete("Thread budget reached; discovered URLs saved for retry")
                return
            scanned += 1
            async for post in _thread_posts(target, source.id, config, origin, settings=settings,
                    request_clock=request_clock, progress=progress if checkpoint is not None else None,
                    save_progress=save):
                yield post
                if remember_thread is not None and post.published_at:
                    await remember_thread(target, post.published_at)
            progress["done"] = True
            await save()

    if config.thread_urls:
        targets = list(dict.fromkeys(_url(start, target, origin) for target in config.thread_urls))
        if len(targets) > config.max_threads:
            raise ValueError("Explicit thread URLs exceed max_threads")
        for target in targets:
            await discover(target)
        await save()
        async for post in pending():
            yield post
        return

    today = datetime.now(timezone.utc).date().isoformat()
    if checkpoint is not None and state.get("discovery_date") != today:
        if "listing" in state:
            # A resumed archive scan must not delay discovery of today's threads.
            fresh = []
            async for page, page_url, _ in _pages(
                start, 1, config.listing_next_selector, origin, "listing",
                settings=settings, config=config, request_clock=request_clock,
            ):
                links = page.select(config.thread_link_selector)
                if not links and not (config.empty_listing_selector and page.select_one(config.empty_listing_selector)):
                    raise RuntimeError("Forum listing parse failed: no thread links or empty listing marker found")
                for link in links:
                    target = await discover(_link(link, page_url, origin))
                    fresh.append(target)
            fresh = list(dict.fromkeys([*fresh, *recent_threads]))
            for target in fresh:
                if threads.get(target, {}).get("done"):
                    threads[target] = {}
            queue[:] = fresh + [target for target in queue if target not in fresh]
        state["discovery_date"] = today
        await save()

    # Resume saved discoveries before fetching another listing page.
    async for post in pending():
        yield post
    async for page, page_url, _ in _pages(
        start, config.max_listing_pages, config.listing_next_selector, origin, "listing",
        settings=settings, config=config, request_clock=request_clock,
        progress=state.setdefault("listing", {}) if checkpoint is not None else None, save_progress=save,
    ):
        links = page.select(config.thread_link_selector)
        if not links and not (config.empty_listing_selector and page.select_one(config.empty_listing_selector)):
            raise RuntimeError("Forum listing parse failed: no thread links or empty listing marker found")
        for link in links:
            try:
                await discover(_link(link, page_url, origin))
            except ValueError as error:
                raise RuntimeError(f"Forum listing parse failed: {error}") from None
        await save()
        async for post in pending():
            yield post
        if checkpoint is None and scanned >= config.max_threads:
            return
    for target in recent_threads:
        await discover(target, observed=False)
    await save()
    async for post in pending():
        yield post
