import asyncio
import base64
import json
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from weakref import WeakKeyDictionary

import psycopg
from psycopg.rows import dict_row

from threat_monitor.config import Settings, get_settings
from threat_monitor.contracts import Page


SCHEMA_VERSION = 7
_CONNECTION_LIMITS = WeakKeyDictionary()


def run_database_command(coroutine):
    if sys.platform == "win32":
        return asyncio.run(coroutine, loop_factory=asyncio.SelectorEventLoop)
    return asyncio.run(coroutine)


class NotFound(Exception):
    pass


class Conflict(Exception):
    pass


class ConfigurationError(Exception):
    pass


async def one(conn, query, params=None):
    return await (await conn.execute(query, params)).fetchone()


async def rows(conn, query, params=None):
    return await (await conn.execute(query, params)).fetchall()


def offset_from_cursor(cursor):
    if cursor is None:
        return 0
    try:
        value = json.loads(base64.urlsafe_b64decode(cursor.encode()))
        offset = value["offset"]
        if type(offset) is not int or offset < 0:
            raise ValueError
        return offset
    except (ValueError, KeyError, TypeError) as exc:
        raise ValueError("Invalid pagination cursor") from exc


def page(items, limit, offset):
    next_cursor = None
    if len(items) > limit:
        payload = json.dumps({"offset": offset + limit}).encode()
        next_cursor = base64.urlsafe_b64encode(payload).decode()
    return Page(items=items[:limit], next_cursor=next_cursor)


class Database:
    def __init__(self, settings: Settings):
        self.settings = settings

    @asynccontextmanager
    async def connection(self, *, autocommit=False):
        if not self.settings.database_url:
            raise ConfigurationError("DATABASE_URL is not configured")
        loop = asyncio.get_running_loop()
        limit = _CONNECTION_LIMITS.setdefault(loop, asyncio.Semaphore(4))
        async with limit:
            conn = await psycopg.AsyncConnection.connect(
                self.settings.database_url.get_secret_value(),
                row_factory=dict_row,
                connect_timeout=5,
                autocommit=autocommit,
            )
            async with conn:
                yield conn

    async def migrate(self):
        async with self.connection() as conn:
            await conn.execute("SELECT pg_advisory_xact_lock(26001)")
            await conn.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations "
                "(version integer PRIMARY KEY, applied_at timestamptz DEFAULT now())"
            )
            for version, filename in ((1, "schema.sql"), (2, "migration_002.sql"),
                                      (3, "migration_003.sql"), (4, "migration_004.sql"),
                                      (5, "migration_005.sql"), (6, "migration_006.sql"),
                                      (7, "migration_007.sql")):
                if not await one(conn, "SELECT version FROM schema_migrations WHERE version = %s", (version,)):
                    await conn.execute(Path(__file__).with_name(filename).read_text(encoding="utf-8"))
                    await conn.execute("INSERT INTO schema_migrations(version) VALUES (%s)", (version,))

    async def ready(self):
        async with self.connection() as conn:
            if not await one(conn, "SELECT version FROM schema_migrations WHERE version = %s", (SCHEMA_VERSION,)):
                raise ConfigurationError("Run python -m threat_monitor.storage.db to update the database schema")


def main():
    try:
        run_database_command(Database(get_settings()).migrate())
    except ConfigurationError as exc:
        raise SystemExit(str(exc)) from exc
    except psycopg.Error as exc:
        raise SystemExit(f"Database initialization failed ({type(exc).__name__})") from exc
    print(f"Database schema is ready (version {SCHEMA_VERSION}).")


if __name__ == "__main__":
    main()
