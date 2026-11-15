import argparse
import asyncio
import logging

import psycopg

from threat_monitor.analysis.service import analyze_company
from threat_monitor.config import get_settings
from threat_monitor.contracts import AnalysisResult, Classification
from threat_monitor.ingestion.pipeline import classify_post, collect_source, embed_post
from threat_monitor.ingestion.collector import CollectionIncomplete
from threat_monitor.storage.db import ConfigurationError, Conflict, one, run_database_command
from threat_monitor.storage.repository import Store
from threat_monitor.storage.tools import DatabaseInvestigationTools


logger = logging.getLogger(__name__)


def failure_message(exc, settings):
    message = f"{type(exc).__name__}: {exc}"
    for value in settings.__dict__.values():
        if hasattr(value, "get_secret_value") and value.get_secret_value():
            message = message.replace(value.get_secret_value(), "[redacted]")
    return message[:1500]


class Worker:
    def __init__(self, store):
        self.store = store
        self.settings = store.settings
        self.session_locks = {}

    async def embed(self, version):
        try:
            chunks = await embed_post(version.post, settings=self.settings)
            await self.store.save_chunks(version, chunks)
        except Exception as exc:
            await self.store.record_ingestion_error(version.post, failure_message(exc, self.settings))
            raise

    async def ingest_post(self, post, classification=None):
        try:
            record = await self.store.ingestion_record(post)
            if record and record["decision"] is not None:
                return
            if classification is None:
                classification = Classification.model_validate(
                    await classify_post(post, settings=self.settings))
            version = await self.store.save_classification(post, classification)
            if version is not None:
                await self.embed(version)
        except Exception as exc:
            await self.store.record_ingestion_error(post, failure_message(exc, self.settings))
            raise

    async def collect(self, job):
        for source_id in job["source_ids"]:
            if source_id in job["completed_source_ids"]:
                continue
            source = await self.store.get_source(source_id)
            session = source.collection_settings.get("session_ref")
            key = session or str(source_id)
            async with self.session_locks.setdefault(key, asyncio.Lock()):
                for version in await self.store.pending_embeddings(source_id):
                    await self.embed(version)
                options = {}
                if "collection_checkpoint" in job:
                    async def save(state):
                        await self.store.save_collection_checkpoint(job["id"], state)
                    async def remember(url, activity_at=None):
                        await self.store.remember_thread(source_id, url, activity_at)
                    options = {"checkpoint": job["collection_checkpoint"], "save_checkpoint": save,
                               "remember_thread": remember, "recent_threads": await self.store.recent_threads(source)}
                async for post in collect_source(source, settings=self.settings, **options):
                    if post.source_id != source_id:
                        raise ValueError("Collector returned a post belonging to a different source")
                    await self.ingest_post(post)
                await self.store.complete_source(job["id"], source_id)

    async def analyze(self, job):
        while True:
            context = await self.store.analysis_batch(job["analysis_run_id"], self.settings.analysis_batch_size)
            if not context.post_versions:
                return None
            tools = DatabaseInvestigationTools(self.store, context)
            result = AnalysisResult.model_validate(
                await analyze_company(context, tools, settings=self.settings))
            await self.store.checkpoint_analysis(context, result)
            if result.incomplete_reason:
                return result.incomplete_reason
            if set(result.processed_version_ids) != {version.id for version in context.post_versions}:
                return "Analysis did not process every assigned version; retry to resume"

    async def process(self, job):
        try:
            reason = None
            if job["kind"] == "collection":
                await self.collect(job)
            else:
                reason = await self.analyze(job)
            await self.store.finish_job(job["id"], "incomplete" if reason else "succeeded", reason)
            logger.info("Job %s: %s", job["id"], "incomplete" if reason else "succeeded")
            return reason is None
        except CollectionIncomplete as exc:
            await self.store.finish_job(job["id"], "incomplete", str(exc))
            logger.info("Job %s: partial coverage: %s", job["id"], exc)
            return False
        except Exception as exc:
            message = failure_message(exc, self.settings)
            await self.store.finish_job(job["id"], "failed", message)
            logger.error("Job %s failed: %s", job["id"], message)
            return False

    async def prepare_analysis(self):
        while True:
            await self.store.schedule_analysis()
            await asyncio.sleep(self.settings.worker_poll_seconds)

    async def run(self, *, once=False):
        await self.store.ready()
        # The session lock makes recovery safe: only one worker can own this queue.
        async with self.store.connection(autocommit=True) as lock:
            acquired = await one(lock, "SELECT pg_try_advisory_lock(26002) AS acquired")
            if not acquired["acquired"]:
                raise Conflict("Another worker already owns this database queue")
            await self.store.recover_jobs()
            if once:
                job = await self.store.claim_job()
                return await self.process(job) if job else True
            tasks = {}
            preparation = asyncio.create_task(self.prepare_analysis())
            try:
                while True:
                    await lock.execute("SELECT 1")
                    if preparation.done():
                        preparation.result()
                    for task in list(tasks):
                        if task.done():
                            task.result()
                            del tasks[task]
                    await self.store.schedule_collection()
                    for kind, capacity in (("collection", 2), ("analysis", 1)):
                        while sum(value == kind for value in tasks.values()) < capacity:
                            job = await self.store.claim_job(kind)
                            if not job:
                                break
                            tasks[asyncio.create_task(self.process(job))] = kind
                    await asyncio.sleep(self.settings.worker_poll_seconds)
            finally:
                preparation.cancel()
                for task in tasks:
                    task.cancel()
                await asyncio.gather(preparation, *tasks, return_exceptions=True)


def main():
    parser = argparse.ArgumentParser(description="Run the PostgreSQL-backed threat monitor worker.")
    parser.add_argument("--once", action="store_true", help="Process at most one queued job, without scheduling collection")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    settings = get_settings()
    try:
        succeeded = run_database_command(Worker(Store(settings)).run(once=args.once))
    except KeyboardInterrupt:
        return
    except (ConfigurationError, Conflict, psycopg.Error) as exc:
        raise SystemExit(failure_message(exc, settings)) from exc
    if not succeeded:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
