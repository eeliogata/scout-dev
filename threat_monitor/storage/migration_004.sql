ALTER TABLE post_versions ADD COLUMN target_extraction_status text NOT NULL
    DEFAULT 'review_required' CHECK (target_extraction_status IN ('complete', 'review_required'));

-- Flattened historic claims cannot establish that a post describes just one victim.
CREATE TABLE post_targets (
    id uuid PRIMARY KEY,
    post_version_id uuid NOT NULL REFERENCES post_versions(id),
    ordinal integer NOT NULL CHECK (ordinal >= 0),
    label text NOT NULL CHECK (length(trim(label)) > 0),
    facts jsonb NOT NULL,
    industry text,
    countries text[] NOT NULL,
    technologies text[] NOT NULL,
    employee_min integer,
    employee_max integer,
    UNIQUE (post_version_id, ordinal)
);
CREATE INDEX post_targets_industry ON post_targets (industry, post_version_id);
CREATE INDEX post_targets_countries ON post_targets USING gin (countries);
