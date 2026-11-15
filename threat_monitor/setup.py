import argparse
import json
import os
from pathlib import Path
import secrets
import tempfile
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen

from dotenv import set_key
import psycopg
from pydantic import SecretStr

from threat_monitor.config import get_settings
from threat_monitor.storage.db import ConfigurationError, Database, run_database_command


ENV_FILE = Path(".env")
CA_FILE = Path(".aiven/ca.pem")


def aiven_get(path, token):
    request = Request(
        "https://api.aiven.io/v1/" + path,
        headers={"Authorization": "aivenv1 " + token},
    )
    try:
        with urlopen(request, timeout=15) as response:
            return json.load(response)
    except HTTPError as exc:
        raise ConfigurationError(
            f"Aiven request failed (HTTP {exc.code}); check the token, permissions, and target"
        ) from None
    except (URLError, TimeoutError):
        raise ConfigurationError("Could not reach Aiven; check network connectivity") from None


def save_env(updates):
    descriptor, filename = tempfile.mkstemp(prefix=".env-setup-", dir=".")
    temporary = Path(filename)
    try:
        with os.fdopen(descriptor, "w") as output:
            template = ENV_FILE if ENV_FILE.exists() else Path(".env.example")
            output.write(template.read_text())
        for key, value in updates.items():
            set_key(temporary, key, value, quote_mode="always")
        temporary.chmod(0o600)
        temporary.replace(ENV_FILE)
    finally:
        temporary.unlink(missing_ok=True)


async def setup(args, settings):
    if not settings.aiven_token or not settings.aiven_token.get_secret_value().strip():
        raise ConfigurationError("Set AIVEN_TOKEN in .env or the environment before running setup")
    token = settings.aiven_token.get_secret_value().strip()
    project_path = "project/" + quote(args.project, safe="")
    response = aiven_get(
        project_path + "/service/" + quote(args.service, safe="") + "?include_secrets=true", token
    )
    service = response["service"]
    if service["service_type"] != "pg" or service["state"] != "RUNNING":
        raise ConfigurationError("The target must be a running PostgreSQL service")
    if args.database not in service["databases"]:
        raise ConfigurationError("The selected database does not exist on this service")
    parts = urlsplit(service["service_uri"])
    if not parts.hostname or not parts.username or not parts.password or unquote(parts.password) in {
        "<redacted>", "[REDACTED]",
    }:
        raise ConfigurationError("Aiven did not provide connection credentials; check secret-read permissions")
    certificate = aiven_get(project_path + "/kms/ca", token)["certificate"]
    if "BEGIN CERTIFICATE" not in certificate:
        raise ConfigurationError("Aiven did not return a CA certificate")
    parameters = dict(parse_qsl(parts.query))
    parameters.update(sslmode="verify-full", sslrootcert=CA_FILE.as_posix())
    database_url = urlunsplit((
        parts.scheme, parts.netloc, "/" + quote(args.database, safe=""), urlencode(parameters), "",
    ))

    # Verify the candidate certificate and connection before replacing local configuration.
    with tempfile.TemporaryDirectory(prefix="aiven-setup-") as folder:
        candidate_ca = Path(folder) / "ca.pem"
        candidate_ca.write_text(certificate)
        connection = await psycopg.AsyncConnection.connect(
            database_url, sslrootcert=str(candidate_ca), connect_timeout=5,
            options="-c default_transaction_read_only=on",
        )
        async with connection:
            await connection.execute("SELECT 1")

    api_key = settings.api_key.get_secret_value() if settings.api_key else secrets.token_urlsafe(32)
    CA_FILE.parent.mkdir(exist_ok=True)
    descriptor, filename = tempfile.mkstemp(prefix=".ca-", dir=CA_FILE.parent)
    temporary = Path(filename)
    try:
        with os.fdopen(descriptor, "w") as output:
            output.write(certificate)
        temporary.replace(CA_FILE)
    finally:
        temporary.unlink(missing_ok=True)
    save_env({"DATABASE_URL": database_url, "API_KEY": api_key})
    configured = settings.model_copy(update={
        "database_url": SecretStr(database_url), "api_key": SecretStr(api_key),
    })
    database = Database(configured)
    await database.migrate()
    await database.ready()


def main():
    parser = argparse.ArgumentParser(description="Configure local Aiven access and initialize the application schema.")
    parser.add_argument("--project", required=True)
    parser.add_argument("--service", required=True)
    parser.add_argument("--database", default="defaultdb")
    args = parser.parse_args()
    if not Path(".env.example").is_file():
        parser.error("Run setup from the project root directory")
    try:
        run_database_command(setup(args, get_settings()))
    except ConfigurationError as exc:
        raise SystemExit(str(exc)) from None
    except psycopg.Error as exc:
        raise SystemExit(f"Database setup failed ({type(exc).__name__}); check TLS, connectivity, and schema permissions") from None
    except (KeyError, TypeError, ValueError):
        raise SystemExit("Invalid configuration or unexpected Aiven response; check the target and settings") from None
    except OSError:
        raise SystemExit("Could not read or write local configuration; check file permissions") from None
    print("Aiven setup complete: .env and .aiven/ca.pem saved; the current schema is ready.")
    print("API:    uv run --locked python -m threat_monitor.api")
    print("Worker: uv run --locked python -m threat_monitor.worker")


if __name__ == "__main__":
    main()
