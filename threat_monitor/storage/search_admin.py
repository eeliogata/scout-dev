import argparse
import asyncio

from threat_monitor.config import get_settings
from threat_monitor.storage.db import Conflict, one
from threat_monitor.storage.repository import Store, lock_analysis_publication


async def run(args):
    store = Store(get_settings())
    await store.ready()
    if args.command == "rebuild":
        async with store.connection() as conn:
            await lock_analysis_publication(conn)
            await conn.execute("DELETE FROM current_search_chunks")
            await conn.execute(
                "INSERT INTO current_search_chunks "
                "SELECT p.id, p.source_id, v.id, c.chunk_index, c.embedding_model, c.embedding "
                "FROM posts p JOIN post_versions v ON v.id = p.current_version_id "
                "JOIN post_chunks c ON c.post_version_id = v.id AND c.embedding_model = v.embedding_model")
        print("Current search projection rebuilt.")
        return
    async with store.connection(autocommit=True) as conn:
        if not (await one(conn, "SELECT pg_try_advisory_lock(26004) AS locked"))["locked"]:
            raise Conflict("Another search-index operation is running")
        existing = await one(conn,
            "SELECT indisvalid FROM pg_index WHERE indexrelid = to_regclass('current_search_chunks_hnsw')")
        if existing and not existing["indisvalid"]:
            if not args.rebuild_invalid:
                raise Conflict("Index is invalid; rerun index --rebuild-invalid to replace it")
            await conn.execute("DROP INDEX CONCURRENTLY current_search_chunks_hnsw")
        await conn.execute(
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS current_search_chunks_hnsw "
            "ON current_search_chunks USING hnsw (embedding vector_cosine_ops) "
            "WITH (m = 16, ef_construction = 64)")
        await conn.execute("ANALYZE current_search_chunks")
        valid = await one(conn,
            "SELECT indisvalid FROM pg_index WHERE indexrelid = to_regclass('current_search_chunks_hnsw')")
        if not valid or not valid["indisvalid"]:
            raise Conflict("Search index creation did not produce a valid index")
    print("Current search HNSW index is valid.")


def main():
    parser = argparse.ArgumentParser(description="Maintain current vector search on the configured DATABASE_URL")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("rebuild")
    index = commands.add_parser("index")
    index.add_argument("--rebuild-invalid", action="store_true")
    asyncio.run(run(parser.parse_args()))


if __name__ == "__main__":
    main()
