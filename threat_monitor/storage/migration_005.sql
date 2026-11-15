CREATE TABLE current_search_chunks (
    post_id uuid NOT NULL REFERENCES posts(id),
    source_id uuid NOT NULL REFERENCES sources(id),
    post_version_id uuid NOT NULL,
    chunk_index integer NOT NULL,
    embedding_model text NOT NULL,
    embedding vector(768) NOT NULL,
    PRIMARY KEY (post_version_id, chunk_index),
    FOREIGN KEY (post_id, post_version_id) REFERENCES post_versions(post_id, id),
    FOREIGN KEY (post_version_id, chunk_index) REFERENCES post_chunks(post_version_id, chunk_index)
);
CREATE INDEX current_search_chunks_post ON current_search_chunks(post_id);
CREATE INDEX current_search_chunks_model ON current_search_chunks(embedding_model);
CREATE INDEX post_versions_thread ON post_versions(source_id, (post->>'thread_id'));

INSERT INTO current_search_chunks
SELECT p.id, p.source_id, v.id, c.chunk_index, c.embedding_model, c.embedding
FROM posts p JOIN post_versions v ON v.id = p.current_version_id
JOIN post_chunks c ON c.post_version_id = v.id AND c.embedding_model = v.embedding_model;
