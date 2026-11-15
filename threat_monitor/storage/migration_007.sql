ALTER TABLE companies ADD COLUMN next_analysis_at timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN analysis_scheduling_error text;
ALTER TABLE jobs ADD COLUMN analysis_scope text NOT NULL DEFAULT 'full_corpus'
    CHECK (analysis_scope IN ('full_corpus','daily_candidates')),
    ADD COLUMN coverage jsonb NOT NULL DEFAULT '{}';
ALTER TABLE analysis_run_posts ADD COLUMN head_revision bigint,
    ADD COLUMN disposition text NOT NULL DEFAULT 'selected'
        CHECK (disposition IN ('selected','processed','superseded'));
CREATE UNIQUE INDEX jobs_running_company ON jobs(company_id)
    WHERE kind='analysis' AND state='running';

CREATE TABLE pending_analysis_changes (
    company_id uuid NOT NULL REFERENCES companies(id),
    post_id uuid NOT NULL REFERENCES posts(id),
    post_version_id uuid NOT NULL,
    head_revision bigint NOT NULL CHECK (head_revision > 0),
    profile_version integer NOT NULL CHECK (profile_version > 0),
    first_pending_at timestamptz NOT NULL DEFAULT now(),
    superseded_count integer NOT NULL DEFAULT 0,
    PRIMARY KEY(company_id,post_id),
    FOREIGN KEY(post_id,post_version_id) REFERENCES post_versions(post_id,id)
);
CREATE INDEX pending_analysis_age ON pending_analysis_changes(company_id,first_pending_at);
INSERT INTO pending_analysis_changes(company_id,post_id,post_version_id,head_revision,profile_version)
SELECT c.id,p.id,p.current_version_id,p.head_revision,c.profile_version
FROM companies c CROSS JOIN posts p WHERE p.current_version_id IS NOT NULL;

CREATE TABLE company_query_embeddings (
    company_id uuid NOT NULL REFERENCES companies(id),
    profile_version integer NOT NULL,
    embedding_model text NOT NULL,
    embedding vector(768) NOT NULL,
    PRIMARY KEY(company_id,profile_version,embedding_model)
);
CREATE TABLE company_analysis_budgets (
    company_id uuid NOT NULL REFERENCES companies(id),
    budget_date date NOT NULL,
    nonexact_selected integer NOT NULL DEFAULT 0 CHECK (nonexact_selected BETWEEN 0 AND 100),
    uncertain_selected integer NOT NULL DEFAULT 0 CHECK (uncertain_selected BETWEEN 0 AND 20),
    PRIMARY KEY(company_id,budget_date)
);
