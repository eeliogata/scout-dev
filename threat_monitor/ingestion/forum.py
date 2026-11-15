"""Operator commands for session import, read-only preview, and bounded collection."""
import argparse
import asyncio
import json
from pathlib import Path

from pydantic import ValidationError
from psycopg.types.json import Jsonb

from threat_monitor.config import get_settings
from threat_monitor.contracts import Source, NormalizedPost, Classification
from threat_monitor.ingestion.collector import collect_source, _settings
from threat_monitor.ingestion.sessions import import_session, private_json, session_path


async def run(args):
    if args.command == 'session-import':
        count = import_session(args.reference, args.origin, args.file)
        print(f'Imported {count} forum cookies. Secret values are not displayed.')
        return
    if args.command == 'session-remove':
        session_path(args.reference).unlink(missing_ok=True)
        print('Local session removed. Log out in the browser to revoke it at the forum.')
        return
    source = Source.model_validate_json(args.source.read_text(encoding='utf-8'))
    _settings(source)
    if source.enabled:
        raise ValueError('Operator collection requires enabled=false to prevent scheduling')
    settings = get_settings()
    if args.command == 'preview':
        if args.captures:
            from threat_monitor.ingestion.capture import preview_captures
            posts = await preview_captures(source, args.captures, settings)
        else:
            posts = [p.model_dump(mode='json') async for p in collect_source(source, settings=settings)]
        if not posts:
            raise ValueError('Preview returned no posts')
        private_json(args.output, {'source': source.model_dump(mode='json'), 'posts': posts,
                                   'collection_method': 'browser_html' if args.captures else 'context_fetch'})
        print(f'Preview saved: {len(posts)} posts. No Gemini calls or database writes.')
        return
    if not args.backup_verified:
        raise ValueError('Back up the database and verify an isolated restore before using --backup-verified')
    preview = json.loads(args.preview.read_text(encoding='utf-8'))
    if preview.get('source') != source.model_dump(mode='json') or not preview.get('posts'):
        raise ValueError('A successful preview for this exact source configuration is required')
    captured = None
    if args.captured:
        if preview.get('collection_method') != 'browser_html':
            raise ValueError('--captured requires a browser HTML preview')
        captured = [NormalizedPost.model_validate(p) for p in preview['posts']]
        allowed_threads = set(source.collection_settings.get('thread_urls', []))
        if any(p.source_id != source.id or p.thread_id not in allowed_threads or not p.context_extraction for p in captured):
            raise ValueError('Captured posts do not match the selected source')
    elif preview.get('collection_method') == 'browser_html':
        raise ValueError('Use --captured to ingest the browser HTML preview explicitly')
    classifications = {}
    if args.classifications:
        if captured is None:
            raise ValueError('--classifications requires --captured')
        from threat_monitor.ingestion.pipeline import _validate_classification
        review = json.loads(args.classifications.read_text(encoding='utf-8'))
        if review.get('model') != 'agent-authored/manual-classification-v1' or not review.get('provenance'):
            raise ValueError('Manual classification provenance is required')
        entries = {entry['external_id']: entry for entry in review['posts']}
        if len(entries) != len(review['posts']) or set(entries) != {p.external_id for p in captured}:
            raise ValueError('Manual review must cover every captured post exactly once')
        for post in captured:
            entry = entries[post.external_id]
            if entry['content_hash'] != post.content_hash:
                raise ValueError('Reviewed post content has changed')
            classification = Classification.model_validate(entry['classification'])
            _validate_classification(classification, post)
            classifications[post.external_id] = classification
        settings = settings.model_copy(update={'gemini_filter_model': review['model']})
    from threat_monitor.storage.repository import Store
    from threat_monitor.storage.db import one
    from threat_monitor.worker import Worker
    store = Store(settings)
    await store.ready()
    config = source.model_dump(mode='json', exclude={'id', 'next_due_at', 'last_attempt_at', 'last_success_at'})
    async with store.connection(autocommit=True) as lock:
        acquired = await one(lock, "SELECT pg_try_advisory_lock(26002) AS acquired")
        if not acquired["acquired"]:
            raise ValueError("Stop the existing worker before operator collection")
        async with store.connection() as conn:
            existing = await one(conn, 'SELECT config, enabled FROM sources WHERE id = %s', (source.id,))
            from threat_monitor.contracts import SourceCreate
            if existing and (SourceCreate.model_validate(existing['config']).model_dump(mode='json') != config or existing['enabled']):
                raise ValueError('Source ID already exists with different configuration')
            if not existing:
                await conn.execute('INSERT INTO sources(id, config, enabled, scan_interval_seconds, revisit_days, next_due_at) '
                                   'VALUES (%s, %s, false, %s, %s, now())',
                                   (source.id, Jsonb(config), source.scan_interval_seconds, source.revisit_days))
            job_id = await store._new_collection(conn, [source.id])
            job = await one(conn, "UPDATE jobs SET state='running', started_at=now() WHERE id=%s RETURNING *", (job_id,))
            await conn.execute('UPDATE sources SET last_attempt_at=now(),last_collection_at=now() WHERE id=%s', (source.id,))
        worker = Worker(store)
        if captured is None:
            if not await worker.process(job):
                raise RuntimeError(f'Collection failed; inspect job {job_id}')
        else:
            from threat_monitor.worker import failure_message
            try:
                for version in await store.pending_embeddings(source.id):
                    await worker.embed(version)
                for post in captured:
                    await worker.ingest_post(post, classifications.get(post.external_id))
                await store.complete_source(job_id, source.id)
                await store.finish_job(job_id, 'succeeded')
            except Exception as error:
                await store.finish_job(job_id, 'failed', failure_message(error, settings))
                raise RuntimeError(f'Collection failed; inspect job {job_id}') from None
    print(f'Collection succeeded: {job_id}. Source remains disabled for scheduling.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    imp = commands.add_parser('session-import')
    imp.add_argument('reference')
    imp.add_argument('--origin', required=True)
    imp.add_argument('--file', type=Path, required=True, help='Playwright storage state or JSON cookie array')
    remove = commands.add_parser('session-remove')
    remove.add_argument('reference')
    for name in ('preview', 'ingest'):
        cmd = commands.add_parser(name)
        cmd.add_argument('source', type=Path)
        if name == 'preview':
            cmd.add_argument('--output', type=Path, required=True)
            cmd.add_argument('--captures', type=Path, nargs='+', help='Explicit authenticated browser HTML captures')
        else:
            cmd.add_argument('--preview', type=Path, required=True)
            cmd.add_argument('--backup-verified', action='store_true')
            cmd.add_argument('--captured', action='store_true', help='Ingest the Context.dev-parsed browser preview without refetching')
            cmd.add_argument('--classifications', type=Path, help='Explicit manually reviewed classifications with hashes and provenance')
    try:
        asyncio.run(run(parser.parse_args()))
    except ValidationError:
        parser.exit(1, 'Forum command failed: invalid source configuration\n')
    except (OSError, ValueError, RuntimeError) as error:
        parser.exit(1, f'Forum command failed: {error}\n')


if __name__ == '__main__':
    main()
