import base64
import json

from threat_monitor.storage.db import rows


def post_cursor(cursor, *, ranked=False):
    if cursor is None:
        return 0 if ranked else None
    try:
        value = json.loads(base64.urlsafe_b64decode(cursor.encode()))
        key = "offset" if ranked else "before_sequence"
        position = value[key]
        if type(position) is not int or position < 0:
            raise ValueError
        return position
    except (ValueError, KeyError, TypeError, UnicodeError):
        raise ValueError("Invalid post cursor; restart this search") from None


def encode_cursor(key, value):
    return base64.urlsafe_b64encode(json.dumps({key: value}).encode()).decode()


async def retrieve(conn, query, where, params, model, vector):
    document = "to_tsvector('simple', (v.post->>'title') || ' ' || (v.post->>'text'))"
    if not query.query:
        before = post_cursor(query.cursor)
        if before is not None:
            where += " AND v.sequence < %s"
            params = params + [before]
        found = await rows(conn, f"SELECT v.* FROM post_versions v WHERE {where} "
                           "ORDER BY v.sequence DESC LIMIT %s", params + [query.limit + 1])
        cursor = encode_cursor("before_sequence", found[query.limit - 1]["sequence"]) if len(found) > query.limit else None
        return found[:query.limit], cursor, False

    offset = post_cursor(query.cursor, ranked=True)
    lexical = await rows(conn,
        f"SELECT v.id, ts_rank_cd({document}, websearch_to_tsquery('simple', %s)) AS score "
        f"FROM post_versions v WHERE {where} AND {document} @@ websearch_to_tsquery('simple', %s) "
        "ORDER BY score DESC, v.sequence DESC LIMIT 200", [query.query] + params + [query.query])
    scores = {row["id"]: float(row["score"]) for row in lexical}
    bounded = len(lexical) == 200
    if vector is not None:
        table = "post_chunks" if query.include_history else "current_search_chunks"
        eligible = (f"FROM {table} c WHERE c.embedding_model = %s AND EXISTS "
                    f"(SELECT 1 FROM post_versions v WHERE v.id = c.post_version_id AND {where})")
        eligible_params = [model] + params
        count = await rows(conn, f"SELECT count(*) AS n FROM (SELECT 1 {eligible} LIMIT 20001) candidates",
                           eligible_params)
        exact = query.include_history or count[0]["n"] <= 20000
        if exact:
            # Materialization prevents an approximate index path for selective subsets.
            semantic = await rows(conn,
                f"WITH eligible AS MATERIALIZED (SELECT c.post_version_id, c.embedding {eligible}) "
                "SELECT post_version_id, max(1 - (embedding <=> %s::vector)) AS score "
                "FROM eligible GROUP BY post_version_id ORDER BY score DESC, post_version_id LIMIT 200",
                eligible_params + [vector])
            bounded |= len(semantic) == 200
        else:
            await conn.execute("SET LOCAL hnsw.ef_search = 800")
            await conn.execute("SET LOCAL hnsw.iterative_scan = 'strict_order'")
            bound = 200
            while True:
                chunks = await rows(conn,
                    f"SELECT c.post_version_id, c.embedding <=> %s::vector AS distance {eligible} "
                    "ORDER BY c.embedding <=> %s::vector LIMIT %s",
                    [vector] + eligible_params + [vector, bound])
                best = {}
                for chunk in chunks:
                    best.setdefault(chunk["post_version_id"], 1 - float(chunk["distance"]))
                if len(best) >= 200 or len(chunks) < bound or bound == 2000:
                    break
                bound = min(bound * 2, 2000)
            semantic = [{"post_version_id": key, "score": value} for key, value in best.items()]
            bounded |= len(chunks) == bound
        for candidate in semantic:
            key = candidate["post_version_id"]
            scores[key] = scores.get(key, 0) + float(candidate["score"])
    if not scores:
        return [], None, bounded
    if vector is not None:
        found = await rows(conn,
            "SELECT v.*, COALESCE((SELECT max(1 - (c.embedding <=> %s::vector)) "
            f"FROM {table} c WHERE c.post_version_id = v.id AND c.embedding_model = %s), 0) + "
            f"ts_rank_cd({document}, websearch_to_tsquery('simple', %s)) AS score "
            "FROM post_versions v WHERE v.id = ANY(%s) ORDER BY score DESC, v.sequence DESC",
            (vector, model, query.query, list(scores)))
    else:
        found = await rows(conn, "SELECT * FROM post_versions WHERE id = ANY(%s)", (list(scores),))
        found.sort(key=lambda row: (scores[row["id"]], row["sequence"]), reverse=True)
    selected = found[offset:offset + query.limit]
    cursor = encode_cursor("offset", offset + query.limit) if len(found) > offset + query.limit else None
    return selected, cursor, bounded
