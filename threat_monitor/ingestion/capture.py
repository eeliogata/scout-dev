import hashlib
import json
from collections import Counter
from pathlib import Path

from bs4 import BeautifulSoup

from threat_monitor.contracts import NormalizedPost
from threat_monitor.ingestion.collector import _post_text, _settings
from threat_monitor.ingestion.providers import extract_context_html
from threat_monitor.ingestion.urls import origin, resolve_url, thread_key


def captured_posts(source, files):
    config = _settings(source)
    allowed = origin(str(source.url))
    targets = {thread_key(resolve_url(str(source.url), url, allowed)): url for url in config.thread_urls}
    if not targets or len(targets) > config.max_threads:
        raise ValueError('Browser capture requires bounded explicit thread_urls')
    captures = [json.loads(Path(file).read_text(encoding='utf-8')) for file in files]
    pages = Counter()
    seen = set()
    posts = []
    captured_urls = {resolve_url(str(source.url), capture['url'], allowed) for capture in captures}
    for capture in captures:
        url = resolve_url(str(source.url), capture['url'], allowed)
        thread = thread_key(url)
        if thread not in targets or capture.get('authenticated') is not True:
            raise ValueError('Capture is outside selected threads or is not authenticated')
        pages[thread] += 1
        if pages[thread] > config.max_thread_pages:
            raise ValueError('Captured pages exceed the configured thread limit')
        if not capture.get('posts'):
            raise ValueError('Capture contains no posts')
        for item in capture['posts']:
            soup = BeautifulSoup(item['html'], 'html.parser')
            for node in soup.select('script, style, template, form, input, button, iframe'):
                node.decompose()
            html = str(soup)
            text = _post_text(soup)
            post = NormalizedPost(
                source_id=source.id, external_id=item['id'], thread_id=targets[thread],
                url=resolve_url(url, item['permalink'], allowed, permalink=True),
                author=item.get('author'), fetched_at=capture['captured_at'],
                title=capture['title'], text=text,
                content_hash=hashlib.sha256(json.dumps([capture['title'], text], ensure_ascii=False, separators=(',', ':')).encode()).hexdigest(),
            )
            key = (post.external_id, post.content_hash)
            if key not in seen:
                posts.append((post, html))
                seen.add(key)
    if set(pages) != set(targets):
        raise ValueError('Capture each selected thread before previewing')
    for capture in captures:
        thread = thread_key(resolve_url(str(source.url), capture['url'], allowed))
        for next_url in capture.get('next', []):
            next_url = resolve_url(capture['url'], next_url, allowed)
            if thread_key(next_url) != thread:
                raise ValueError('Captured pagination leaves its selected thread')
            if next_url not in captured_urls and pages[thread] < config.max_thread_pages:
                raise ValueError('Capture the next thread page before previewing')
    return posts


async def preview_captures(source, files, settings):
    result = []
    for post, html in captured_posts(source, files):
        post.context_extraction = await extract_context_html(html, settings=settings)
        result.append(post.model_dump(mode='json'))
        print(f'Context.dev parsed {post.external_id}: request {post.context_extraction.request_id}', flush=True)
    return result
