import re
import logging
from datetime import datetime, timezone
from uuid import uuid4

from psycopg.types.json import Jsonb

from threat_monitor.contracts import PostQuery
from threat_monitor.ingestion.pipeline import embed_query
from threat_monitor.storage.db import one, rows
from threat_monitor.storage.search import retrieve


def company_query(company):
    return " ".join(filter(None, [company.name, *company.aliases, *company.domains,
        company.industry, *company.countries, *company.technologies,
        f"employees {company.employees.minimum} to {company.employees.maximum}" if company.employees else None]))


class AnalysisQueue:
    async def _mark_pending(self, conn, company, version_ids=None):
        await conn.execute(
            "INSERT INTO pending_analysis_changes(company_id,post_id,post_version_id,head_revision,profile_version) "
            "SELECT %s,p.id,p.current_version_id,p.head_revision,%s FROM posts p "
            "WHERE p.current_version_id IS NOT NULL AND (%s::uuid[] IS NULL OR p.current_version_id=ANY(%s)) "
            "ON CONFLICT(company_id,post_id) DO UPDATE SET "
            "superseded_count=pending_analysis_changes.superseded_count + CASE WHEN "
            "(pending_analysis_changes.head_revision,pending_analysis_changes.profile_version) "
            "IS DISTINCT FROM (EXCLUDED.head_revision,EXCLUDED.profile_version) THEN 1 ELSE 0 END, "
            "post_version_id=EXCLUDED.post_version_id,head_revision=EXCLUDED.head_revision,profile_version=EXCLUDED.profile_version",
            (company.id, company.profile_version, version_ids, version_ids))

    async def _enqueue_analysis(self, conn, company, version_ids=None, *, scope="full_corpus", selected=None, coverage=None):
        if scope == "full_corpus":
            await self._mark_pending(conn, company, version_ids)
        if version_ids is not None and selected is None:
            return None
        existing = await one(conn,
            "SELECT j.id FROM jobs j JOIN analysis_runs r ON r.id=j.analysis_run_id "
            "WHERE j.company_id=%s AND j.state IN ('queued','running') AND j.analysis_scope=%s "
            "AND (r.company->>'profile_version')::int=%s AND r.model=%s "
            "AND r.model_revision IS NOT DISTINCT FROM %s ORDER BY j.created_at LIMIT 1",
            (company.id, scope, company.profile_version, self.settings.analysis_model, self.settings.analysis_model_revision))
        if existing:
            return existing["id"]
        job_id, run_id = uuid4(), uuid4()
        await conn.execute(
            "INSERT INTO jobs(id,kind,company_id,analysis_run_id,analysis_scope,coverage) "
            "VALUES (%s,'analysis',%s,%s,%s,%s)", (job_id, company.id, run_id, scope, Jsonb(coverage or {})))
        await conn.execute(
            "INSERT INTO analysis_runs(id,job_id,company_id,company,model,model_revision) VALUES (%s,%s,%s,%s,%s,%s)",
            (run_id, job_id, company.id, Jsonb(company.model_dump(mode="json")),
             self.settings.analysis_model, self.settings.analysis_model_revision))
        await conn.execute(
            "INSERT INTO analysis_run_posts(run_id,post_version_id,head_revision) "
            "SELECT %s,v.id,p.head_revision FROM posts p JOIN post_versions v ON v.id=p.current_version_id "
            "WHERE v.embedding_model=%s AND (%s::uuid[] IS NULL OR v.id=ANY(%s))",
            (run_id, self.settings.embedding_model, selected, selected))
        await conn.execute("UPDATE jobs SET total_count=(SELECT count(*) FROM analysis_run_posts WHERE run_id=%s) WHERE id=%s",
                           (run_id, job_id))
        if scope == "full_corpus":
            await conn.execute(
                "UPDATE jobs SET coverage=jsonb_build_object('selected',total_count,'deferred',0, "
                "'pending_embeddings',(SELECT count(*) FROM posts WHERE current_version_id IS NOT NULL)-total_count) "
                "WHERE id=%s", (job_id,))
        return job_id

    async def schedule_analysis(self):
        from threat_monitor.storage.repository import company_from_row
        async with self.connection() as conn:
            due = await rows(conn,
                "SELECT c.* FROM companies c WHERE next_analysis_at<=now() "
                "AND EXISTS(SELECT 1 FROM pending_analysis_changes p WHERE p.company_id=c.id) "
                "AND NOT EXISTS(SELECT 1 FROM jobs j WHERE j.company_id=c.id AND j.state IN ('queued','running')) "
                "ORDER BY next_analysis_at,c.id LIMIT 10")
        for row in due:
            company = company_from_row(row)
            try:
                await self._prepare_daily(company)
            except Exception as exc:
                from threat_monitor.worker import failure_message
                message = failure_message(exc, self.settings)
                async with self.connection() as conn:
                    await conn.execute("UPDATE companies SET analysis_scheduling_error=%s,next_analysis_at=now()+interval '5 minutes' WHERE id=%s",
                                       (message, company.id))
                logging.getLogger(__name__).error("Candidate scheduling for %s failed: %s", company.id, message)

    async def _prepare_daily(self, company):
        from threat_monitor.storage.repository import vector_text, lock_analysis_publication
        async with self.connection() as conn:
            cached = await one(conn,
                "SELECT embedding::text FROM company_query_embeddings WHERE company_id=%s "
                "AND profile_version=%s AND embedding_model=%s",
                (company.id, company.profile_version, self.settings.embedding_model))
        if cached:
            vector = cached["embedding"]
        else:
            vector = vector_text(await embed_query(company_query(company), settings=self.settings))
            async with self.connection() as conn:
                await conn.execute(
                    "INSERT INTO company_query_embeddings VALUES (%s,%s,%s,%s::vector) ON CONFLICT DO NOTHING",
                    (company.id, company.profile_version, self.settings.embedding_model, vector))
        async with self.connection() as conn:
            await lock_analysis_publication(conn)
            current = await one(conn, "SELECT * FROM companies WHERE id=%s FOR UPDATE", (company.id,))
            active = await one(conn, "SELECT id FROM jobs WHERE company_id=%s AND state IN ('queued','running')", (company.id,))
            if (current["profile_version"] != company.profile_version or active
                    or current["next_analysis_at"] > datetime.now(timezone.utc)):
                return
            await self._select_daily(conn, company, vector)

    async def _select_daily(self, conn, company, vector):
        patterns = [r"(^|[^[:alnum:]_])" + re.escape(value) + r"($|[^[:alnum:]_])"
                    for value in [company.name, *company.aliases] if value.strip()]
        patterns += [r"(^|[^[:alnum:]_.-])" + re.escape(value) + r"($|[^[:alnum:]_.-]|[.](?![[:alnum:]_-]))"
                     for value in company.domains if value.strip()]
        minimum = company.employees.minimum if company.employees else None
        maximum = company.employees.maximum if company.employees else None
        pending = await rows(conn,
            "SELECT q.*, ((v.post->>'title') || ' ' || (v.post->>'text')) ~* ANY(%s::text[]) AS exact, "
            "(v.target_extraction_status='review_required' OR NOT EXISTS "
            "(SELECT 1 FROM post_targets t WHERE t.post_version_id=v.id) OR EXISTS "
            "(SELECT 1 FROM post_targets t WHERE t.post_version_id=v.id AND t.industry IS NULL "
            "AND t.countries='{}' AND t.employee_min IS NULL AND t.employee_max IS NULL)) AS uncertain, "
            "EXISTS(SELECT 1 FROM post_targets t WHERE t.post_version_id=v.id "
            "AND (%s::text IS NULL OR t.industry IS NULL OR lower(t.industry)=lower(%s)) "
            "AND (%s::text[]='{}' OR t.countries='{}' OR t.countries && %s::text[]) "
            "AND (%s::int IS NULL OR t.employee_max IS NULL OR t.employee_max>=%s) "
            "AND (%s::int IS NULL OR t.employee_min IS NULL OR t.employee_min<=%s)) AS compatible "
            "FROM pending_analysis_changes q JOIN posts p ON p.id=q.post_id "
            "JOIN post_versions v ON v.id=p.current_version_id WHERE q.company_id=%s "
            "AND q.post_version_id=v.id AND q.head_revision=p.head_revision AND v.embedding_model=%s "
            "ORDER BY q.first_pending_at,q.post_id",
            (patterns, company.industry, company.industry, company.countries, company.countries,
             minimum, minimum, maximum, maximum, company.id, self.settings.embedding_model))
        keywords = " OR ".join('"' + value.replace('"', '') + '"' for value in
                               [company.name, *company.aliases, *company.domains, company.industry,
                                *company.countries, *company.technologies] if value)
        ranked, _, limited = await retrieve(conn, PostQuery(query=keywords, limit=100),
            "EXISTS(SELECT 1 FROM pending_analysis_changes q WHERE q.company_id=%s AND q.post_version_id=v.id) "
            "AND EXISTS(SELECT 1 FROM posts p WHERE p.current_version_id=v.id)",
            [company.id], self.settings.embedding_model, vector)
        ranks = {row["id"]: len(ranked) - i for i, row in enumerate(ranked)}
        await conn.execute("INSERT INTO company_analysis_budgets(company_id,budget_date) VALUES (%s,(now() AT TIME ZONE 'UTC')::date) ON CONFLICT DO NOTHING", (company.id,))
        budget = await one(conn, "SELECT * FROM company_analysis_budgets WHERE company_id=%s AND budget_date=(now() AT TIME ZONE 'UTC')::date FOR UPDATE", (company.id,))
        room = max(0, 100 - budget["nonexact_selected"])
        exact = [row for row in pending if row["exact"]]
        uncertain = [row for row in pending if not row["exact"] and row["uncertain"]][:min(room, max(0, 20-budget["uncertain_selected"]))]
        known = [row for row in pending if not row["exact"] and not row["uncertain"]
                 and (row["compatible"] or row["post_version_id"] in ranks)]
        known.sort(key=lambda row: ranks.get(row["post_version_id"], 0), reverse=True)
        selected = exact + uncertain + known[:max(0, room-len(uncertain))]
        stats = {"selected": len(selected), "exact": len(exact), "uncertain": len(uncertain),
                 "deferred": len(pending)-len(selected), "excluded": 0,
                 "superseded": sum(row["superseded_count"] for row in pending),
                 "candidate_limit_reached": limited, "pending_embeddings": 0}
        waiting = await one(conn, "SELECT count(*) AS n FROM pending_analysis_changes WHERE company_id=%s", (company.id,))
        stats["pending_embeddings"] = waiting["n"] - len(pending)
        await self._enqueue_analysis(conn, company, scope="daily_candidates",
                                     selected=[row["post_version_id"] for row in selected], coverage=stats)
        await conn.execute("UPDATE company_analysis_budgets SET nonexact_selected=nonexact_selected+%s,uncertain_selected=uncertain_selected+%s WHERE company_id=%s AND budget_date=(now() AT TIME ZONE 'UTC')::date",
                           (len(selected)-len(exact), len(uncertain), company.id))
        await conn.execute("UPDATE companies SET next_analysis_at=now()+interval '24 hours',analysis_scheduling_error=NULL WHERE id=%s", (company.id,))
