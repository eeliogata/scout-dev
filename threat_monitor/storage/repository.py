import hashlib
import json
import math
from uuid import uuid4

from psycopg.types.json import Jsonb

from threat_monitor.contracts import (
    Actor, Alert, AlertDetail, AlertEvent, AlertEvidence, AlertStatus, AnalysisContext,
    Classification, Company, CompanyCreate, ExtractedFacts, Job, PostListItem, PostListPage,
    PostSummary, PostSearchPage, PostVersion, Source,
)
from threat_monitor.storage.db import (
    Conflict, Database, NotFound, offset_from_cursor, one, page, rows,
)
from threat_monitor.storage.search import encode_cursor, post_cursor, retrieve
from threat_monitor.storage.analysis_queue import AnalysisQueue


def company_from_row(row):
    return Company(**row["profile"], **{key: row[key] for key in (
        "id", "profile_version", "created_at", "updated_at", "next_analysis_at", "analysis_scheduling_error",
    )})


def source_from_row(row):
    return Source(id=row["id"], **(row["config"] | {key: row[key] for key in (
        "enabled", "scan_interval_seconds", "revisit_days", "next_due_at", "last_attempt_at", "last_success_at",
    )}))


def job_from_row(row):
    return Job(**{key: row[key] for key in Job.model_fields})


def classification_from_row(row):
    data = dict(row["classification"])
    data["target_extraction_status"] = row["target_extraction_status"]
    if row["target_extraction_status"] == "review_required":
        data["facts"] = ExtractedFacts().model_dump(mode="json")
        data["targets"] = []
    elif "targets" in row:
        data["targets"] = [{"label": target["label"], "facts": target["facts"]}
                           for target in row["targets"]]
    return Classification.model_validate(data)


def version_from_row(row):
    return PostVersion(id=row["id"], post_id=row["post_id"], post=row["post"],
                       classification=classification_from_row(row), targets=row.get("targets", []))


def alert_from_row(row):
    return Alert(**row["finding"], **{key: row[key] for key in (
        "id", "company_id", "status", "created_at", "updated_at",
    )})


def event_from_row(row):
    return AlertEvent(**{key: row[key] for key in AlertEvent.model_fields})


def post_key(post):
    if post.external_id:
        return "id:" + post.external_id
    return f"url:{post.url}"


def vector_text(vector):
    if len(vector) != 768 or not all(math.isfinite(value) for value in vector):
        raise ValueError("Embedding must contain 768 finite values")
    norm = math.sqrt(sum(value * value for value in vector))
    if norm == 0:
        raise ValueError("Embedding must not be a zero vector")
    return json.dumps([value / norm for value in vector])


async def lock_analysis_publication(conn):
    # Company snapshots and embedding publication must see each other's committed work.
    await conn.execute("SELECT pg_advisory_xact_lock(26003)")


class Store(AnalysisQueue, Database):
    async def _attach_targets(self, conn, versions):
        grouped = {row["id"]: [] for row in versions}
        if grouped:
            for target in await rows(conn,
                    "SELECT * FROM post_targets WHERE post_version_id = ANY(%s) ORDER BY ordinal",
                    (list(grouped),)):
                grouped[target["post_version_id"]].append({key: target[key] for key in (
                    "id", "ordinal", "label", "facts",
                )})
        for version in versions:
            version["targets"] = grouped[version["id"]]

    async def list_posts(self, cursor=None, limit=100):
        before = post_cursor(cursor)
        async with self.connection() as conn:
            total = await one(conn, "SELECT count(*) AS count FROM posts WHERE current_version_id IS NOT NULL")
            found = await rows(conn,
                "SELECT v.*, s.config->>'name' AS source_name FROM posts p "
                "JOIN post_versions v ON v.id = p.current_version_id "
                "JOIN sources s ON s.id = v.source_id "
                "WHERE (%s::bigint IS NULL OR v.sequence < %s) "
                "ORDER BY v.sequence DESC LIMIT %s", (before, before, limit + 1))
        items = [PostListItem(
            version_id=row["id"], post_id=row["post_id"], source_name=row["source_name"],
            embedding_ready=row["embedding_model"] == self.settings.embedding_model,
            title=row["post"]["title"], excerpt=row["post"]["text"][:300], category=row["category"],
            published_at=row["post"].get("published_at"), fetched_at=row["fetched_at"],
        ) for row in found]
        cursor = encode_cursor("before_sequence", found[limit - 1]["sequence"]) if len(found) > limit else None
        return PostListPage(items=items[:limit], next_cursor=cursor, total_count=total["count"])

    async def create_company(self, profile):
        async with self.connection() as conn:
            await lock_analysis_publication(conn)
            row = await one(conn,
                "INSERT INTO companies(id, profile) VALUES (%s, %s) RETURNING *",
                (uuid4(), Jsonb(profile.model_dump(mode="json"))),
            )
            company = company_from_row(row)
            await self._enqueue_analysis(conn, company)
            return company

    async def get_company(self, company_id):
        async with self.connection() as conn:
            row = await one(conn, "SELECT * FROM companies WHERE id = %s", (company_id,))
            if not row:
                raise NotFound("Company not found")
            return company_from_row(row)

    async def list_companies(self, cursor=None, limit=20):
        offset = offset_from_cursor(cursor)
        async with self.connection() as conn:
            found = await rows(conn,
                "SELECT * FROM companies ORDER BY lower(profile->>'name'), id LIMIT %s OFFSET %s",
                (limit + 1, offset),
            )
            return page([company_from_row(row) for row in found], limit, offset)

    async def update_company(self, company_id, change):
        async with self.connection() as conn:
            await lock_analysis_publication(conn)
            current = await one(conn,
                "SELECT * FROM companies WHERE id = %s FOR UPDATE", (company_id,))
            if not current:
                raise NotFound("Company not found")
            profile = CompanyCreate.model_validate(
                current["profile"] | change.model_dump(mode="json", exclude_unset=True)
            )
            if profile.model_dump(mode="json") == current["profile"]:
                return company_from_row(current)
            row = await one(conn,
                "UPDATE companies SET profile = %s, profile_version = profile_version + 1, "
                "updated_at = now() WHERE id = %s RETURNING *",
                (Jsonb(profile.model_dump(mode="json")), company_id),
            )
            company = company_from_row(row)
            await self._enqueue_analysis(conn, company)
            return company

    async def create_source(self, config):
        async with self.connection() as conn:
            row = await one(conn,
                "INSERT INTO sources(id, config, enabled, scan_interval_seconds, revisit_days, next_due_at) "
                "VALUES (%s, %s, %s, %s, %s, now() + (abs(hashtext(%s)::bigint) %% %s) * interval '1 second') RETURNING *",
                (source_id := uuid4(), Jsonb(config.model_dump(mode="json")), config.enabled,
                 config.scan_interval_seconds, config.revisit_days, str(source_id), config.scan_interval_seconds),
            )
            return source_from_row(row)

    async def get_source(self, source_id):
        async with self.connection() as conn:
            row = await one(conn, "SELECT * FROM sources WHERE id = %s", (source_id,))
            if not row:
                raise NotFound("Source not found")
            return source_from_row(row)

    async def list_sources(self, cursor=None, limit=20):
        offset = offset_from_cursor(cursor)
        async with self.connection() as conn:
            found = await rows(conn, "SELECT * FROM sources ORDER BY id LIMIT %s OFFSET %s",
                               (limit + 1, offset))
            return page([source_from_row(row) for row in found], limit, offset)

    async def _new_collection(self, conn, source_ids):
        if len(source_ids) != 1:
            raise ValueError("Each collection job must have exactly one source")
        source_id = source_ids[0]
        await conn.execute("SELECT id FROM sources WHERE id = %s FOR UPDATE", (source_id,))
        existing = await one(conn,
            "SELECT id FROM jobs WHERE collection_source_id=%s AND state IN ('queued','running')",
            (source_id,))
        if existing:
            return existing["id"]
        job_id = uuid4()
        await conn.execute(
            "INSERT INTO jobs(id, kind, source_ids, collection_source_id, total_count) "
            "VALUES (%s, 'collection', %s, %s, 1)", (job_id, source_ids, source_id))
        await conn.execute(
            "UPDATE sources SET next_due_at = now() + scan_interval_seconds * interval '1 second' WHERE id=%s",
            (source_id,))
        return job_id

    async def enqueue_collection(self, source_ids=None):
        async with self.connection() as conn:
            found = await rows(conn,
                "SELECT id FROM sources WHERE enabled AND (%s::uuid[] IS NULL OR id = ANY(%s)) "
                "ORDER BY id FOR UPDATE", (source_ids, source_ids))
            ids = [row["id"] for row in found]
            if source_ids is not None and set(ids) != set(source_ids):
                raise NotFound("One or more sources are missing or disabled")
            if not ids:
                raise ValueError("No enabled sources to collect")
            return [await self._new_collection(conn, [source_id]) for source_id in ids]

    async def schedule_collection(self):
        async with self.connection() as conn:
            found = await rows(conn,
                "SELECT id FROM sources s WHERE enabled AND next_due_at <= now() AND NOT EXISTS "
                "(SELECT 1 FROM jobs j WHERE j.collection_source_id=s.id AND j.state IN ('queued','running')) "
                "ORDER BY id FOR UPDATE SKIP LOCKED")
            for source in found:
                previous = await one(conn,
                    "SELECT id,state FROM jobs WHERE collection_source_id=%s "
                    "ORDER BY created_at DESC LIMIT 1", (source["id"],))
                if previous and previous["state"] in ("failed", "incomplete"):
                    await conn.execute("UPDATE jobs SET state='queued', error=NULL, finished_at=NULL WHERE id=%s",
                                       (previous["id"],))
                    await conn.execute("UPDATE sources SET next_due_at=now()+scan_interval_seconds*interval '1 second' WHERE id=%s",
                                       (source["id"],))
                else:
                    await self._new_collection(conn, [source["id"]])

    async def save_collection_checkpoint(self, job_id, checkpoint):
        async with self.connection() as conn:
            await conn.execute("UPDATE jobs SET collection_checkpoint=%s WHERE id=%s AND state='running'",
                               (Jsonb(checkpoint), job_id))

    async def remember_thread(self, source_id, url, activity_at=None):
        async with self.connection() as conn:
            await conn.execute(
                "INSERT INTO collection_threads(source_id,url,last_activity_at) VALUES (%s,%s,%s) "
                "ON CONFLICT(source_id,url) DO UPDATE SET last_seen_at=now(), "
                "last_activity_at=GREATEST(collection_threads.last_activity_at, EXCLUDED.last_activity_at)",
                (source_id, url, activity_at))

    async def recent_threads(self, source):
        async with self.connection() as conn:
            found = await rows(conn,
                "SELECT url FROM collection_threads WHERE source_id=%s AND "
                "COALESCE(last_activity_at,last_seen_at) >= now() - %s * interval '1 day' "
                "ORDER BY COALESCE(last_activity_at,last_seen_at) DESC, url",
                (source.id, source.revisit_days))
            return [row["url"] for row in found]

    async def enqueue_analysis(self, company_id):
        async with self.connection() as conn:
            await lock_analysis_publication(conn)
            row = await one(conn, "SELECT * FROM companies WHERE id = %s FOR UPDATE", (company_id,))
            if not row:
                raise NotFound("Company not found")
            return await self._enqueue_analysis(conn, company_from_row(row))

    async def get_job(self, job_id):
        async with self.connection() as conn:
            row = await one(conn, "SELECT * FROM jobs WHERE id = %s", (job_id,))
            if not row:
                raise NotFound("Job not found")
            return job_from_row(row)

    async def list_analysis_jobs(self, company_id, cursor=None, limit=20):
        offset = offset_from_cursor(cursor)
        async with self.connection() as conn:
            if not await one(conn, "SELECT id FROM companies WHERE id = %s", (company_id,)):
                raise NotFound("Company not found")
            found = await rows(conn,
                "SELECT * FROM jobs WHERE company_id = %s AND kind = 'analysis' "
                "ORDER BY created_at DESC, id DESC LIMIT %s OFFSET %s",
                (company_id, limit + 1, offset),
            )
            return page([job_from_row(row) for row in found], limit, offset)

    async def retry_job(self, job_id):
        async with self.connection() as conn:
            job = await one(conn, "SELECT kind, state, finished_at, collection_source_id FROM jobs WHERE id = %s", (job_id,))
            if not job:
                raise NotFound("Job not found")
            if job["state"] not in ("failed", "incomplete"):
                raise Conflict("Only failed or incomplete jobs can be retried")
            if job["kind"] == "collection":
                if not job["collection_source_id"]:
                    raise Conflict("Create separate per-source jobs instead of retrying a legacy multi-source job")
                await conn.execute("SELECT id FROM sources WHERE id=%s FOR UPDATE", (job["collection_source_id"],))
                if await one(conn, "SELECT id FROM jobs WHERE collection_source_id=%s AND state IN ('queued','running')",
                             (job["collection_source_id"],)):
                    raise Conflict("This source already has an active collection job")
            if job["kind"] == "analysis":
                run = await one(conn,
                    "SELECT r.*, c.profile_version AS current_version FROM analysis_runs r "
                    "JOIN companies c ON c.id = r.company_id WHERE r.job_id = %s FOR SHARE OF c",
                    (job_id,),
                )
                if not run:
                    raise NotFound("Analysis run not found")
                self._check_analysis_snapshot(run)
            row = await one(conn,
                "UPDATE jobs SET state = 'queued', error = NULL, finished_at = NULL "
                "WHERE id = %s AND state = %s AND finished_at IS NOT DISTINCT FROM %s RETURNING id",
                (job_id, job["state"], job["finished_at"]),
            )
            if not row:
                raise Conflict("Job state changed while retrying. Refresh and try again.")
            return row["id"]

    async def claim_job(self, kind=None):
        async with self.connection() as conn:
            job = await one(conn,
                "UPDATE jobs SET state = 'running', error = NULL, started_at = now(), finished_at = NULL "
                "WHERE id = (SELECT id FROM jobs j WHERE state = 'queued' AND (%s::text IS NULL OR kind=%s) "
                "AND (kind <> 'analysis' OR NOT EXISTS (SELECT 1 FROM jobs running "
                "WHERE running.kind='analysis' AND running.company_id=j.company_id AND running.state='running')) "
                "ORDER BY created_at, id FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING *", (kind, kind))

            if job and job["collection_source_id"]:
                await conn.execute("UPDATE sources SET last_attempt_at=now(),last_collection_at=now() WHERE id=%s",
                                   (job["collection_source_id"],))
            return job

    async def recover_jobs(self):
        async with self.connection() as conn:
            await conn.execute("UPDATE jobs SET state = 'queued', error = 'Worker interrupted; resuming' "
                               "WHERE state = 'running'")

    async def finish_job(self, job_id, state, error=None):
        async with self.connection() as conn:
            job = await one(conn, "UPDATE jobs SET state=%s,error=%s,finished_at=now() WHERE id=%s RETURNING collection_source_id",
                            (state, error, job_id))
            if job and job["collection_source_id"]:
                await conn.execute(
                    "UPDATE sources SET next_due_at=now()+scan_interval_seconds*interval '1 second', "
                    "last_success_at=CASE WHEN %s='succeeded' THEN now() ELSE last_success_at END WHERE id=%s",
                    (state, job["collection_source_id"]))

    async def complete_source(self, job_id, source_id):
        async with self.connection() as conn:
            await conn.execute(
                "UPDATE jobs SET completed_source_ids = array_append(completed_source_ids, %s), "
                "processed_count = processed_count + 1 WHERE id = %s "
                "AND NOT (%s = ANY(completed_source_ids))", (source_id, job_id, source_id))

    async def _run_company(self, conn, run_id):
        run = await one(conn,
            "SELECT r.*, j.state, c.profile_version AS current_version FROM analysis_runs r "
            "JOIN jobs j ON j.id = r.job_id JOIN companies c ON c.id = r.company_id "
            "WHERE r.id = %s FOR UPDATE OF c", (run_id,))
        if not run:
            raise NotFound("Analysis run not found")
        if run["state"] != "running":
            raise Conflict("Analysis run is not running")
        return self._check_analysis_snapshot(run)

    def _check_analysis_snapshot(self, run):
        company = Company.model_validate(run["company"])
        if company.profile_version != run["current_version"]:
            raise Conflict("Company profile changed. Use the newly queued analysis or start a new run.")
        if (run["model"], run["model_revision"]) != (
            self.settings.analysis_model, self.settings.analysis_model_revision,
        ):
            raise Conflict("Analysis model configuration changed; create a new analysis run")
        return company

    async def analysis_batch(self, run_id, limit):
        async with self.connection() as conn:
            company = await self._run_company(conn, run_id)
            await conn.execute(
                "UPDATE analysis_run_posts a SET processed=true,disposition='superseded' "
                "FROM post_versions v,posts p WHERE a.run_id=%s AND NOT a.processed "
                "AND v.id=a.post_version_id AND p.id=v.post_id "
                "AND (a.head_revision IS NULL OR a.head_revision<>p.head_revision OR p.current_version_id<>v.id)", (run_id,))
            await self._update_analysis_progress(conn, run_id)
            found = await rows(conn,
                "SELECT v.* FROM analysis_run_posts p JOIN post_versions v ON v.id = p.post_version_id "
                "WHERE p.run_id = %s AND NOT p.processed ORDER BY v.sequence LIMIT %s", (run_id, limit))
            await self._attach_targets(conn, found)
            return AnalysisContext(run_id=run_id, company=company,
                                   post_versions=[version_from_row(row) for row in found])

    async def get_post(self, version_id):
        async with self.connection() as conn:
            row = await one(conn, "SELECT * FROM post_versions WHERE id = %s", (version_id,))
            if not row:
                raise NotFound("Post version not found")
            await self._attach_targets(conn, [row])
            return version_from_row(row)

    async def ingestion_record(self, post):
        expected = hashlib.sha256(json.dumps(
            [post.title, post.text], ensure_ascii=False, separators=(",", ":")
        ).encode()).hexdigest()
        if post.content_hash != expected:
            raise ValueError("Post content_hash does not match normalized title and text")
        async with self.connection() as conn:
            await lock_analysis_publication(conn)
            record = await one(conn, "SELECT * FROM ingestion_records WHERE source_id = %s "
                             "AND source_key = %s AND content_hash = %s",
                             (post.source_id, post_key(post), post.content_hash))
            if record and record["decision"] and record["post_version_id"]:
                version = await one(conn, "SELECT * FROM post_versions WHERE id = %s",
                                    (record["post_version_id"],))
                await self._observe_version(conn, post, version)
            return record

    async def _observe_version(self, conn, post, version):
        parent = await one(conn, "SELECT * FROM posts WHERE id = %s FOR UPDATE",
                           (version["post_id"],))
        if parent["last_observed_at"] and post.fetched_at < parent["last_observed_at"]:
            return
        changed = parent["current_version_id"] != version["id"]
        await conn.execute(
            "UPDATE posts SET current_version_id = %s, head_revision = head_revision + %s, "
            "last_observed_at = %s WHERE id = %s",
            (version["id"], int(changed), post.fetched_at, version["post_id"]),
        )
        if changed:
            await self._sync_current_chunks(conn, version["post_id"])
        if changed:
            for company in await rows(conn, "SELECT * FROM companies ORDER BY id FOR SHARE"):
                await self._enqueue_analysis(conn, company_from_row(company), [version["id"]])

    async def _sync_current_chunks(self, conn, post_id):
        await conn.execute("DELETE FROM current_search_chunks WHERE post_id = %s", (post_id,))
        await conn.execute(
            "INSERT INTO current_search_chunks "
            "SELECT p.id, p.source_id, v.id, c.chunk_index, c.embedding_model, c.embedding "
            "FROM posts p JOIN post_versions v ON v.id = p.current_version_id "
            "JOIN post_chunks c ON c.post_version_id = v.id AND c.embedding_model = v.embedding_model "
            "WHERE p.id = %s", (post_id,))

    async def _record(self, conn, post, decision=None, reason=None, version_id=None, error=None):
        await conn.execute(
            "INSERT INTO ingestion_records(source_id, source_key, content_hash, url, decision, "
            "reason, classifier_model, post_version_id, error) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) "
            "ON CONFLICT (source_id, source_key, content_hash) DO UPDATE SET "
            "decision = COALESCE(EXCLUDED.decision, ingestion_records.decision), "
            "reason = COALESCE(EXCLUDED.reason, ingestion_records.reason), "
            "classifier_model = COALESCE(EXCLUDED.classifier_model, ingestion_records.classifier_model), "
            "post_version_id = COALESCE(EXCLUDED.post_version_id, ingestion_records.post_version_id), "
            "error = EXCLUDED.error, updated_at = now()",
            (post.source_id, post_key(post), post.content_hash, str(post.url), decision,
             reason, self.settings.gemini_filter_model if decision is not None else None, version_id, error),
        )

    async def record_ingestion_error(self, post, error):
        async with self.connection() as conn:
            await self._record(conn, post, error=error)

    async def save_classification(self, post, classification):
        async with self.connection() as conn:
            await lock_analysis_publication(conn)
            if not classification.keep:
                await self._record(conn, post, False, classification.reason)
                return None
            from threat_monitor.ingestion.pipeline import _validate_classification
            _validate_classification(classification, post)
            parent = await one(conn,
                "INSERT INTO posts(id, source_id, source_key) VALUES (%s,%s,%s) "
                "ON CONFLICT (source_id, source_key) DO UPDATE SET source_key = EXCLUDED.source_key "
                "RETURNING id", (uuid4(), post.source_id, post_key(post)))
            facts = classification.facts
            version = await one(conn,
                "INSERT INTO post_versions(id, post_id, source_id, content_hash, post, classification, "
                "category, industry, countries, technologies, employee_min, employee_max, fetched_at) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
                "ON CONFLICT (post_id, content_hash) DO UPDATE SET content_hash = EXCLUDED.content_hash "
                "RETURNING *",
                (uuid4(), parent["id"], post.source_id, post.content_hash,
                 Jsonb(post.model_dump(mode="json")), Jsonb(classification.model_dump(mode="json")),
                 classification.category, facts.industry, facts.countries, facts.technologies,
                 facts.employees.minimum if facts.employees else None,
                 facts.employees.maximum if facts.employees else None, post.fetched_at),
            )
            if (classification.target_extraction_status == "complete"
                    and version["classification"] == classification.model_dump(mode="json")
                    and version["target_extraction_status"] != "complete"):
                await self._save_targets(conn, version, classification.targets)
            await self._record(conn, post, True, classification.reason, version["id"])
            await self._attach_targets(conn, [version])
            await self._observe_version(conn, post, version)
            return version_from_row(version)

    async def _save_targets(self, conn, version, targets):
        for ordinal, target in enumerate(targets):
            facts = target.facts
            await conn.execute(
                "INSERT INTO post_targets(id, post_version_id, ordinal, label, facts, "
                "industry, countries, technologies, employee_min, employee_max) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (uuid4(), version["id"], ordinal, target.label,
                 Jsonb(facts.model_dump(mode="json")), facts.industry, facts.countries,
                 facts.technologies, facts.employees.minimum if facts.employees else None,
                 facts.employees.maximum if facts.employees else None))
        await conn.execute("UPDATE post_versions SET target_extraction_status = 'complete' WHERE id = %s",
                           (version["id"],))
        version["target_extraction_status"] = "complete"

    async def review_targets(self, version_id, targets):
        from threat_monitor.ingestion.pipeline import _validate_classification
        async with self.connection() as conn:
            version = await one(conn, "SELECT * FROM post_versions WHERE id = %s FOR UPDATE", (version_id,))
            if not version:
                raise NotFound("Post version not found")
            if version["target_extraction_status"] == "complete":
                raise Conflict("Target extraction is already complete")
            classification = Classification(keep=True, reason="Target review",
                                            category=version["category"], targets=targets)
            _validate_classification(classification, version_from_row(version).post)
            await self._save_targets(conn, version, classification.targets)
            await self._attach_targets(conn, [version])
            return version_from_row(version)

    async def pending_embeddings(self, source_id):
        async with self.connection() as conn:
            found = await rows(conn,
                "SELECT v.* FROM posts p JOIN post_versions v ON v.id = p.current_version_id "
                "WHERE v.source_id = %s AND v.embedding_model IS DISTINCT FROM %s "
                "ORDER BY v.sequence", (source_id, self.settings.embedding_model))
            await self._attach_targets(conn, found)
            return [version_from_row(row) for row in found]

    async def save_chunks(self, version, chunks):
        if not chunks:
            raise ValueError("Accepted posts require at least one embedding chunk")
        if sorted(chunk.index for chunk in chunks) != list(range(len(chunks))):
            raise ValueError("Chunk indices must be contiguous and unique")
        for chunk in chunks:
            if chunk.text != version.post.text[chunk.start_char:chunk.end_char]:
                raise ValueError("Chunk text does not match the stored post offsets")
            if chunk.embedding_model != self.settings.embedding_model:
                raise ValueError("Chunk embedding model differs from the configured model")
        async with self.connection() as conn:
            await lock_analysis_publication(conn)
            row = await one(conn,
                "SELECT embedding_model FROM post_versions WHERE id = %s FOR UPDATE", (version.id,))
            if not row:
                raise NotFound("Post version not found")
            if row["embedding_model"] == self.settings.embedding_model:
                return
            await conn.execute("DELETE FROM current_search_chunks WHERE post_version_id = %s", (version.id,))
            await conn.execute("DELETE FROM post_chunks WHERE post_version_id = %s", (version.id,))
            for chunk in chunks:
                await conn.execute(
                    "INSERT INTO post_chunks VALUES (%s,%s,%s,%s,%s,%s::vector,%s)",
                    (version.id, chunk.index, chunk.text, chunk.start_char, chunk.end_char,
                     vector_text(chunk.embedding), chunk.embedding_model))
            await conn.execute("UPDATE post_versions SET embedding_model = %s WHERE id = %s",
                               (self.settings.embedding_model, version.id))
            await conn.execute("UPDATE ingestion_records SET error = NULL WHERE post_version_id = %s",
                               (version.id,))
            current = await one(conn, "SELECT current_version_id FROM posts WHERE id = %s",
                                (version.post_id,))
            if current["current_version_id"] == version.id:
                await self._sync_current_chunks(conn, version.post_id)
                for company in await rows(conn, "SELECT * FROM companies ORDER BY id FOR SHARE"):
                    await self._enqueue_analysis(conn, company_from_row(company), [version.id])

    async def query_posts(self, query, *, embedding=None, thread_id=None):
        conditions, params = [], []
        if not query.include_history:
            conditions.append("EXISTS (SELECT 1 FROM posts p WHERE p.current_version_id = v.id)")
        for field, values in (("source_id", query.source_ids), ("category", query.categories)):
            if values:
                conditions.append(f"v.{field} = ANY(%s)")
                params.append(values)
        target_conditions, target_params = [], []
        if query.industries:
            target_conditions.append("t.industry = ANY(%s)")
            target_params.append(query.industries)
        for field, values in (("countries", query.countries), ("technologies", query.technologies)):
            if values:
                target_conditions.append(f"t.{field} && %s::text[]")
                target_params.append(values)
        if query.employees:
            if query.employees.minimum is not None:
                target_conditions.append("(t.employee_max IS NULL OR t.employee_max >= %s)")
                target_params.append(query.employees.minimum)
            if query.employees.maximum is not None:
                target_conditions.append("(t.employee_min IS NULL OR t.employee_min <= %s)")
                target_params.append(query.employees.maximum)
        if target_conditions:
            conditions.append("EXISTS (SELECT 1 FROM post_targets t WHERE t.post_version_id = v.id AND "
                              + " AND ".join(target_conditions) + ")")
            params.extend(target_params)
        if query.fetched_since:
            conditions.append("v.fetched_at >= %s")
            params.append(query.fetched_since)
        if thread_id is not None:
            conditions.append("v.post->>'thread_id' = %s")
            params.append(thread_id)
        where = " AND ".join(conditions) or "true"
        async with self.connection() as conn:
            await conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            found, cursor, bounded = await retrieve(conn, query, where, params,
                self.settings.embedding_model, vector_text(embedding) if embedding is not None else None)
            await self._attach_targets(conn, found)
            summaries = [PostSummary(
                version_id=row["id"], post_id=row["post_id"], source_id=row["source_id"],
                url=row["post"]["url"], title=row["post"]["title"],
                excerpt=row["post"]["text"][:500], facts=classification_from_row(row).facts,
                targets=row["targets"], target_extraction_status=row["target_extraction_status"],
                fetched_at=row["fetched_at"],
            ) for row in found]
            return PostSearchPage(items=summaries, next_cursor=cursor, candidate_limit_reached=bounded)

    async def _validate_evidence(self, conn, evidence):
        versions = {}
        for item in evidence:
            row = await one(conn, "SELECT post_id, post, sequence FROM post_versions WHERE id = %s",
                            (item.post_version_id,))
            if not row:
                raise ValueError("Evidence references an unknown post version")
            if item.quote not in row["post"]["title"] + "\n" + row["post"]["text"]:
                raise ValueError("Evidence quote is absent from the referenced post")
            versions[row["post_id"]] = max(versions.get(row["post_id"], 0), row["sequence"])
        return versions

    async def _save_finding(self, conn, company_id, finding, *, run_id=None):
        versions = await self._validate_evidence(conn, finding.evidence)
        if finding.matched_target_ids:
            matched = await rows(conn,
                "SELECT id FROM post_targets WHERE id = ANY(%s) AND post_version_id = ANY(%s)",
                (finding.matched_target_ids, list({e.post_version_id for e in finding.evidence})))
            if {row["id"] for row in matched} != set(finding.matched_target_ids):
                raise ValueError("Matched targets must belong to cited post versions")
        primary_version = finding.primary_post_version_id or finding.evidence[0].post_version_id
        if primary_version not in {item.post_version_id for item in finding.evidence}:
            raise ValueError("The primary listing must be cited in the finding")
        primary = await one(conn, "SELECT post_id FROM post_versions WHERE id = %s", (primary_version,))
        key = hashlib.sha256(json.dumps([
            finding.category, str(primary["post_id"])
        ]).encode()).hexdigest()
        # Serialize the legacy-key transition and concurrent findings for this company.
        await conn.execute("SELECT id FROM companies WHERE id = %s FOR UPDATE", (company_id,))
        candidates = await rows(conn,
            "SELECT a.id, a.finding, a.finding_run_id FROM alerts a JOIN post_versions v ON v.id = "
            "COALESCE(a.finding->>'primary_post_version_id', "
            "a.finding->'evidence'->0->>'post_version_id')::uuid "
            "WHERE a.company_id = %s AND a.finding->>'category' = %s AND v.post_id = %s "
            "FOR UPDATE OF a", (company_id, finding.category, primary["post_id"]))
        if len(candidates) > 1:
            raise Conflict("Multiple legacy alerts identify this primary listing; resolve their review histories before updating")
        finding = finding.model_copy(update={"primary_post_version_id": primary_version})
        if candidates:
            row = candidates[0]
            previous_run = row["finding_run_id"]
            if previous_run is not None and run_id != previous_run:
                if run_id is None:
                    return
                order = await one(conn,
                    "SELECT (incoming.created_at, incoming.id) < (previous.created_at, previous.id) AS stale "
                    "FROM jobs incoming JOIN analysis_runs new_run ON new_run.job_id = incoming.id "
                    "CROSS JOIN jobs previous JOIN analysis_runs old_run ON old_run.job_id = previous.id "
                    "WHERE new_run.id = %s AND old_run.id = %s", (run_id, previous_run))
                if order["stale"]:
                    return
            current_versions = await self._validate_evidence(conn, [
                AlertEvidence.model_validate(item) for item in row["finding"]["evidence"]
            ])
            if run_id is None and any(sequence < current_versions.get(post_id, 0) for post_id, sequence in versions.items()):
                return
            await conn.execute(
                "UPDATE alerts SET finding_key = %s, finding = %s, updated_at = now(), finding_run_id = %s WHERE id = %s",
                (key, Jsonb(finding.model_dump(mode="json")), run_id, row["id"]))
        else:
            row = await one(conn,
                "INSERT INTO alerts(id, company_id, finding_key, finding, initial_evidence, finding_run_id) "
                "VALUES (%s,%s,%s,%s,%s,%s) RETURNING id",
                (uuid4(), company_id, key, Jsonb(finding.model_dump(mode="json")),
                 list({item.post_version_id for item in finding.evidence}), run_id))
        for item in finding.evidence:
            await conn.execute("INSERT INTO alert_evidence VALUES (%s,%s,%s) ON CONFLICT DO NOTHING",
                               (row["id"], item.post_version_id, item.quote))

    async def _update_analysis_progress(self, conn, run_id):
        await conn.execute(
            "UPDATE jobs SET processed_count=(SELECT count(*) FROM analysis_run_posts "
            "WHERE run_id=%s AND processed), coverage=coverage || jsonb_build_object("
            "'superseded_assignments',(SELECT count(*) FROM analysis_run_posts WHERE run_id=%s AND disposition='superseded')) "
            "WHERE analysis_run_id=%s", (run_id, run_id, run_id))

    async def checkpoint_analysis(self, context, result):
        assigned = {version.id for version in context.post_versions}
        processed = set(result.processed_version_ids)
        if not processed.issubset(assigned) or len(processed) != len(result.processed_version_ids):
            raise ValueError("Analysis processed IDs must be unique members of its assigned batch")
        async with self.connection() as conn:
            await lock_analysis_publication(conn)
            company = await self._run_company(conn, context.run_id)
            snapshots = await rows(conn,
                "SELECT a.post_version_id,a.head_revision,p.head_revision AS current_revision,p.current_version_id "
                "FROM analysis_run_posts a JOIN post_versions v ON v.id=a.post_version_id "
                "JOIN posts p ON p.id=v.post_id WHERE a.run_id=%s AND a.post_version_id=ANY(%s::uuid[])",
                (context.run_id, list(assigned)))
            if {row["post_version_id"] for row in snapshots} != assigned:
                raise ValueError("Batch contains versions outside the run snapshot")
            stale = {row["post_version_id"] for row in snapshots if row["head_revision"] is None
                     or row["head_revision"] != row["current_revision"]
                     or row["current_version_id"] != row["post_version_id"]}
            for finding in result.findings:
                if not {e.post_version_id for e in finding.evidence} & assigned:
                    raise ValueError("Finding must cite an assigned version")
                if not {e.post_version_id for e in finding.evidence} & stale:
                    await self._save_finding(conn, company.id, finding, run_id=context.run_id)
            for version_id in processed:
                await conn.execute(
                    "UPDATE analysis_run_posts SET processed=true,disposition=%s WHERE run_id=%s AND post_version_id=%s",
                    ('superseded' if version_id in stale else 'processed', context.run_id, version_id))
            await conn.execute(
                "DELETE FROM pending_analysis_changes q USING analysis_run_posts a,analysis_runs r "
                "WHERE a.run_id=%s AND a.processed AND a.disposition='processed' AND r.id=a.run_id "
                "AND q.company_id=r.company_id AND q.post_version_id=a.post_version_id "
                "AND q.head_revision=a.head_revision AND q.profile_version=(r.company->>'profile_version')::int",
                (context.run_id,))
            await self._update_analysis_progress(conn, context.run_id)

    async def list_alerts(self, company_id, *, status=None, severity=None, cursor=None, limit=20):
        offset = offset_from_cursor(cursor)
        async with self.connection() as conn:
            if not await one(conn, "SELECT id FROM companies WHERE id = %s", (company_id,)):
                raise NotFound("Company not found")
            found = await rows(conn,
                "SELECT * FROM alerts WHERE company_id = %s "
                "AND (%s::text IS NULL OR status = %s) "
                "AND (%s::text IS NULL OR finding->>'severity' = %s) "
                "ORDER BY created_at DESC, id LIMIT %s OFFSET %s",
                (company_id, status, status, severity, severity, limit + 1, offset))
            return page([alert_from_row(row) for row in found], limit, offset)

    async def get_alert(self, alert_id, *, company_id=None):
        async with self.connection() as conn:
            row = await one(conn, "SELECT * FROM alerts WHERE id = %s "
                            "AND (%s::uuid IS NULL OR company_id = %s)",
                            (alert_id, company_id, company_id))
            if not row:
                raise NotFound("Alert not found")
            events = await rows(conn, "SELECT * FROM alert_events WHERE alert_id = %s ORDER BY sequence",
                                (alert_id,))
            return AlertDetail(alert=alert_from_row(row), events=[event_from_row(e) for e in events])

    async def change_alert_status(self, alert_id, change, *, actor=Actor.USER,
                                  company_id=None, run_id=None):
        async with self.connection() as conn:
            if actor == Actor.MODEL:
                await lock_analysis_publication(conn)
                if run_id is None or company_id is None:
                    raise ValueError("Model changes require a bound company and analysis run")
                company = await self._run_company(conn, run_id)
                stale = await one(conn,
                    "SELECT a.post_version_id FROM analysis_run_posts a JOIN post_versions v ON v.id=a.post_version_id "
                    "JOIN posts p ON p.id=v.post_id WHERE a.run_id=%s AND NOT a.processed "
                    "AND (a.head_revision IS NULL OR a.head_revision<>p.head_revision OR p.current_version_id<>v.id) LIMIT 1",
                    (run_id,))
                if stale:
                    raise Conflict("Post evidence changed; resume with the current head before changing status")
                if company.id != company_id:
                    raise Conflict("Analysis run belongs to another company")
                if not change.evidence:
                    raise ValueError("Model status changes require source evidence")
            row = await one(conn, "SELECT * FROM alerts WHERE id = %s "
                            "AND (%s::uuid IS NULL OR company_id = %s) FOR UPDATE",
                            (alert_id, company_id, company_id))
            if not row:
                raise NotFound("Alert not found")
            if row["status"] == change.status:
                raise Conflict("Alert already has that status")
            await self._validate_evidence(conn, change.evidence)
            latest = await one(conn,
                "SELECT * FROM alert_events WHERE alert_id = %s ORDER BY sequence DESC LIMIT 1",
                (alert_id,))
            seen = set(latest["seen_version_ids"] if latest else row["initial_evidence"])
            supplied = {item.post_version_id for item in change.evidence}
            if actor == Actor.MODEL and not supplied - seen:
                raise Conflict("A model status change requires previously unreviewed evidence")
            attached = await rows(conn,
                "SELECT DISTINCT post_version_id FROM alert_evidence WHERE alert_id = %s", (alert_id,))
            seen.update(item["post_version_id"] for item in attached)
            seen.update(supplied)
            verb = {AlertStatus.OPEN: "Reopened", AlertStatus.RESOLVED: "Resolved",
                    AlertStatus.DISMISSED_NOT_TARGETED: "Dismissed"}[change.status]
            note = f"{verb} by {actor.value}"
            if actor == Actor.MODEL and change.status == AlertStatus.OPEN and latest:
                if latest["actor"] == "user" and latest["status"] == "dismissed_not_targeted":
                    note += " after user dismissal"
            for item in change.evidence:
                await conn.execute("INSERT INTO alert_evidence VALUES (%s,%s,%s) ON CONFLICT DO NOTHING",
                                   (alert_id, item.post_version_id, item.quote))
            event = await one(conn,
                "INSERT INTO alert_events(id, alert_id, previous_status, status, actor, reason, note, "
                "evidence, seen_version_ids, analysis_run_id) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *",
                (uuid4(), alert_id, row["status"], change.status, actor, change.reason, note,
                 Jsonb([item.model_dump(mode="json") for item in change.evidence]), list(seen), run_id))
            await conn.execute("UPDATE alerts SET status = %s, updated_at = now() WHERE id = %s",
                               (change.status, alert_id))
            return event_from_row(event)
