import argparse
import asyncio
import json
from pathlib import Path

from threat_monitor.config import get_settings
from threat_monitor.contracts import NormalizedPost
from threat_monitor.ingestion.pipeline import classify_post, embed_post, embed_query


async def run(args):
    settings = get_settings()
    if args.command == "embed-query":
        print(json.dumps(await embed_query(args.text, settings=settings)))
        return
    post = NormalizedPost.model_validate_json(args.post.read_text(encoding="utf-8"))
    if args.command == "classify":
        print((await classify_post(post, settings=settings)).model_dump_json())
        return
    chunks = await embed_post(post, settings=settings)
    print(json.dumps([chunk.model_dump() for chunk in chunks], ensure_ascii=False))


def main():
    parser = argparse.ArgumentParser(
        description="Run ingestion hooks against Gemini. Reads settings from .env.",
        epilog=(
            "Run from the project root using uv run --locked python -m threat_monitor.ingestion. "
            "Requires GEMINI_API_KEY. Classification defaults to gemini-4-hydrogen; "
            "GEMINI_FILTER_MODEL overrides the model. "
            "Post files must match the shared NormalizedPost contract."
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)
    classify = commands.add_parser("classify", help="Classify one normalized post JSON file")
    classify.add_argument("post", type=Path)
    embed = commands.add_parser("embed-post", help="Chunk and embed a normalized post JSON file")
    embed.add_argument("post", type=Path)
    query = commands.add_parser("embed-query", help="Generate one search-query embedding")
    query.add_argument("text")
    args = parser.parse_args()
    try:
        asyncio.run(run(args))
    except (OSError, ValueError, RuntimeError) as error:
        parser.exit(1, f"Ingestion failed: {error}\n")


if __name__ == "__main__":
    main()
