ALTER TABLE sources
    ADD COLUMN scan_interval_seconds integer NOT NULL DEFAULT 86400 CHECK (scan_interval_seconds >= 60),
    ADD COLUMN revisit_days integer NOT NULL DEFAULT 7 CHECK (revisit_days >= 0),
    ADD COLUMN next_due_at timestamptz,
    ADD COLUMN last_attempt_at timestamptz,
    ADD COLUMN last_success_at timestamptz;
UPDATE sources SET next_due_at = now() +
    (abs(hashtext(id::text)::bigint) % scan_interval_seconds) * interval '1 second';
ALTER TABLE sources ALTER COLUMN next_due_at SET NOT NULL;
CREATE INDEX sources_due ON sources(next_due_at) WHERE enabled;

ALTER TABLE jobs
    ADD COLUMN collection_source_id uuid REFERENCES sources(id),
    ADD COLUMN collection_checkpoint jsonb NOT NULL DEFAULT '{}';
UPDATE jobs SET collection_source_id = source_ids[1]
WHERE kind = 'collection' AND cardinality(source_ids) = 1;
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM jobs WHERE kind = 'collection' AND state IN ('queued','running')
               AND cardinality(source_ids) <> 1) THEN
        RAISE EXCEPTION 'Finish legacy multi-source collection jobs before migrating';
    END IF;
END $$;
ALTER TABLE jobs ADD CONSTRAINT collection_single_source CHECK (
    kind <> 'collection' OR
    (collection_source_id IS NOT NULL AND cardinality(source_ids) = 1
     AND collection_source_id = source_ids[1])
) NOT VALID;
CREATE UNIQUE INDEX jobs_active_collection_source ON jobs(collection_source_id)
    WHERE kind = 'collection' AND state IN ('queued','running');

CREATE TABLE collection_threads (
    source_id uuid NOT NULL REFERENCES sources(id),
    url text NOT NULL,
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    last_activity_at timestamptz,
    PRIMARY KEY (source_id, url)
);
