ALTER TABLE alerts ADD COLUMN finding_run_id uuid REFERENCES analysis_runs(id);

-- Keep one parent per permalink and retain every immutable version and citation.
CREATE TEMP TABLE permalink_post_map ON COMMIT DROP AS
SELECT p.id,
       left(p.source_key, -65) AS permalink_key,
       first_value(p.id) OVER (
           PARTITION BY p.source_id, left(p.source_key, -65)
           ORDER BY first_version.sequence, p.id
       ) AS canonical_id
FROM posts p
JOIN LATERAL (
    SELECT min(v.sequence) AS sequence FROM post_versions v WHERE v.post_id = p.id
) first_version ON true
WHERE p.source_key ~ '^url:.*#[0-9a-f]{64}$';

UPDATE post_versions v
SET post_id = m.canonical_id
FROM permalink_post_map m
WHERE v.post_id = m.id AND m.id <> m.canonical_id;

DELETE FROM posts p USING permalink_post_map m
WHERE p.id = m.id AND m.id <> m.canonical_id;

UPDATE posts p SET source_key = m.permalink_key
FROM permalink_post_map m
WHERE p.id = m.id AND m.id = m.canonical_id;

UPDATE ingestion_records SET source_key = left(source_key, -65)
WHERE source_key ~ '^url:.*#[0-9a-f]{64}$';
