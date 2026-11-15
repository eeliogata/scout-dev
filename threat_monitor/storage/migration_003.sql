ALTER TABLE post_versions ADD CONSTRAINT post_versions_parent_version UNIQUE (post_id, id);

ALTER TABLE posts
    ADD COLUMN current_version_id uuid,
    ADD COLUMN head_revision bigint NOT NULL DEFAULT 0,
    ADD COLUMN last_observed_at timestamptz,
    ADD CONSTRAINT posts_current_version FOREIGN KEY (id, current_version_id)
        REFERENCES post_versions (post_id, id),
    ADD CONSTRAINT posts_head_state CHECK (
        (current_version_id IS NULL AND head_revision = 0) OR
        (current_version_id IS NOT NULL AND head_revision > 0)
    );

UPDATE posts p SET current_version_id = latest.id, head_revision = 1,
    last_observed_at = latest.fetched_at
FROM (
    SELECT DISTINCT ON (post_id) post_id, id, fetched_at
    FROM post_versions ORDER BY post_id, sequence DESC
) latest WHERE latest.post_id = p.id;

CREATE INDEX posts_current_version_lookup ON posts (current_version_id);
