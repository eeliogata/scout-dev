CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE companies (
    id uuid PRIMARY KEY,
    profile jsonb NOT NULL,
    profile_version integer NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE sources (
    id uuid PRIMARY KEY,
    config jsonb NOT NULL,
    enabled boolean NOT NULL,
    last_collection_at timestamptz
);

CREATE TABLE posts (
    id uuid PRIMARY KEY,
    source_id uuid NOT NULL REFERENCES sources(id),
    source_key text NOT NULL,
    UNIQUE (source_id, source_key)
);

CREATE TABLE post_versions (
    id uuid PRIMARY KEY,
    sequence bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
    post_id uuid NOT NULL REFERENCES posts(id),
    source_id uuid NOT NULL REFERENCES sources(id),
    content_hash text NOT NULL,
    post jsonb NOT NULL,
    classification jsonb NOT NULL,
    category text,
    industry text,
    countries text[] NOT NULL,
    technologies text[] NOT NULL,
    employee_min integer,
    employee_max integer,
    fetched_at timestamptz NOT NULL,
    embedding_model text,
    UNIQUE (post_id, content_hash)
);
CREATE INDEX post_versions_search ON post_versions USING gin (
    to_tsvector('simple', (post->>'title') || ' ' || (post->>'text'))
);

CREATE TABLE ingestion_records (
    source_id uuid NOT NULL REFERENCES sources(id),
    source_key text NOT NULL,
    content_hash text NOT NULL,
    url text NOT NULL,
    decision boolean,
    reason text,
    classifier_model text,
    post_version_id uuid REFERENCES post_versions(id),
    error text,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (source_id, source_key, content_hash)
);

CREATE TABLE post_chunks (
    post_version_id uuid NOT NULL REFERENCES post_versions(id),
    chunk_index integer NOT NULL,
    text text NOT NULL,
    start_char integer NOT NULL,
    end_char integer NOT NULL,
    embedding vector(768) NOT NULL,
    embedding_model text NOT NULL,
    PRIMARY KEY (post_version_id, chunk_index)
);

CREATE TABLE jobs (
    id uuid PRIMARY KEY,
    kind text NOT NULL CHECK (kind IN ('collection', 'analysis')),
    state text NOT NULL DEFAULT 'queued'
        CHECK (state IN ('queued', 'running', 'succeeded', 'failed', 'incomplete')),
    company_id uuid REFERENCES companies(id),
    source_ids uuid[] NOT NULL DEFAULT '{}',
    completed_source_ids uuid[] NOT NULL DEFAULT '{}',
    analysis_run_id uuid,
    processed_count integer NOT NULL DEFAULT 0,
    total_count integer,
    error text,
    created_at timestamptz NOT NULL DEFAULT now(),
    started_at timestamptz,
    finished_at timestamptz
);
CREATE INDEX jobs_queue ON jobs (created_at) WHERE state = 'queued';

CREATE TABLE analysis_runs (
    id uuid PRIMARY KEY,
    job_id uuid NOT NULL UNIQUE REFERENCES jobs(id),
    company_id uuid NOT NULL REFERENCES companies(id),
    company jsonb NOT NULL,
    model text NOT NULL,
    model_revision text
);

CREATE TABLE analysis_run_posts (
    run_id uuid NOT NULL REFERENCES analysis_runs(id),
    post_version_id uuid NOT NULL REFERENCES post_versions(id),
    processed boolean NOT NULL DEFAULT false,
    PRIMARY KEY (run_id, post_version_id)
);

CREATE TABLE alerts (
    id uuid PRIMARY KEY,
    company_id uuid NOT NULL REFERENCES companies(id),
    finding_key text NOT NULL,
    finding jsonb NOT NULL,
    status text NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'resolved', 'dismissed_not_targeted')),
    initial_evidence uuid[] NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (company_id, finding_key)
);

CREATE TABLE alert_evidence (
    alert_id uuid NOT NULL REFERENCES alerts(id),
    post_version_id uuid NOT NULL REFERENCES post_versions(id),
    quote text NOT NULL,
    PRIMARY KEY (alert_id, post_version_id, quote)
);

CREATE TABLE alert_events (
    id uuid PRIMARY KEY,
    sequence bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
    alert_id uuid NOT NULL REFERENCES alerts(id),
    previous_status text NOT NULL,
    status text NOT NULL,
    actor text NOT NULL CHECK (actor IN ('user', 'model')),
    reason text NOT NULL,
    note text NOT NULL,
    evidence jsonb NOT NULL,
    seen_version_ids uuid[] NOT NULL,
    analysis_run_id uuid REFERENCES analysis_runs(id),
    created_at timestamptz NOT NULL DEFAULT now()
);
