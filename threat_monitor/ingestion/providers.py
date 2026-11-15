import asyncio
import json
import re
from email.message import Message
from http.client import HTTPException
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

import requests

from threat_monitor.config import Settings
from threat_monitor.contracts import ContextExtraction
from threat_monitor.ingestion.urls import origin, resolve_url


async def fetch_page(url: str, *, settings: Settings, headers=None, wait_for=None) -> tuple[str, str]:
    _, hostname, _ = origin(url)
    if hostname.rstrip(".").endswith(".onion"):
        if headers:
            raise ValueError("Authenticated onion collection is not supported yet")
        proxy = settings.tor_socks_proxy
        if not proxy:
            raise ValueError("Set TOR_SOCKS_PROXY=socks5h://127.0.0.1:9050 before collecting onion pages")
        try:
            parts = urlsplit(proxy)
            valid = (
                parts.scheme == "socks5h" and parts.hostname and parts.port
                and parts.path in {"", "/"} and not parts.query and not parts.fragment
            )
        except ValueError:
            valid = False
        if not valid:
            raise ValueError("TOR_SOCKS_PROXY must be a socks5h://host:port URL")
        return await asyncio.to_thread(_fetch_tor_page, url, proxy)
    return await fetch_context_page(url, settings=settings, headers=headers, wait_for=wait_for)


def _fetch_tor_page(url: str, proxy: str) -> tuple[str, str]:
    allowed_origin = origin(url)
    url = resolve_url(url, url, allowed_origin)
    visited = set()
    try:
        with requests.Session() as session:
            session.trust_env = False
            for redirects in range(6):
                if url in visited:
                    raise RuntimeError("Tor fetch failed: repeated redirect URL")
                visited.add(url)
                with session.get(
                    url, proxies={"http": proxy, "https": proxy},
                    timeout=(30, 60), allow_redirects=False, verify=True,
                ) as response:
                    if response.status_code in {301, 302, 303, 307, 308}:
                        if redirects == 5:
                            raise RuntimeError("Tor fetch failed: more than five redirects")
                        url = resolve_url(url, response.headers.get("Location", ""), allowed_origin)
                        continue
                    if response.status_code != 200:
                        raise RuntimeError(f"Tor fetch failed: HTTP {response.status_code}")
                    content_type = Message()
                    content_type["Content-Type"] = response.headers.get("Content-Type", "")
                    if content_type.get_content_type() not in {"text/html", "application/xhtml+xml"}:
                        raise RuntimeError("Tor fetch failed: expected an HTML response")
                    if not response.content.strip():
                        raise RuntimeError("Tor fetch failed: empty HTML response")
                    response.encoding = content_type.get_content_charset() or response.apparent_encoding
                    return resolve_url(url, response.url, allowed_origin), response.text
    except requests.exceptions.ProxyError:
        raise RuntimeError("Tor fetch failed: SOCKS connection failed; check Tor bootstrap and TOR_SOCKS_PROXY") from None
    except requests.exceptions.Timeout:
        raise RuntimeError("Tor fetch failed: connection or read timeout") from None
    except requests.exceptions.SSLError:
        raise RuntimeError("Tor fetch failed: TLS certificate verification failed") from None
    except requests.exceptions.RequestException:
        raise RuntimeError("Tor fetch failed: connection or response error") from None
    except ValueError as error:
        raise RuntimeError(f"Tor fetch failed: {error}") from None


async def fetch_context_page(url: str, *, settings: Settings, headers=None, wait_for=None) -> tuple[str, str]:
    key = settings.context_dev_api_key
    if key is None or not key.get_secret_value().strip():
        raise ValueError("Set CONTEXT_DEV_API_KEY before collecting forum pages")
    shared = {}
    if headers:
        shared["headers"] = headers
    if wait_for:
        shared["waitFor"] = wait_for
    request = Request(
        "https://api.context.dev/v1/web/scrape",
        data=json.dumps({
            "url": url,
            "formats": {"html": True},
            **({"sharedParams": shared} if shared else {}),
            "maxAgeMs": 0,
            "timeoutOpts": {"milliseconds": settings.context_dev_timeout_seconds * 1000, "behavior": "fail"},
        }).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    request.add_unredirected_header("Authorization", f"Bearer {key.get_secret_value()}")
    return await asyncio.to_thread(_fetch_context_page, request, settings.context_dev_timeout_seconds + 5)


def _context_error(reason: str, request_id: object = None) -> RuntimeError:
    if isinstance(request_id, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,100}", request_id):
        reason += f" (request ID: {request_id})"
    return RuntimeError(f"Context.dev fetch failed: {reason}")


async def extract_context_html(html: str, *, settings: Settings) -> ContextExtraction:
    key = settings.context_dev_api_key
    if key is None or not key.get_secret_value().strip():
        raise ValueError("Set CONTEXT_DEV_API_KEY before extracting onion posts")
    request = Request(
        "https://api.context.dev/v1/parse?extension=html&useMainContentOnly=false&includeImages=false",
        data=html.encode("utf-8"),
        headers={"Content-Type": "application/octet-stream"},
        method="POST",
    )
    request.add_unredirected_header("Authorization", f"Bearer {key.get_secret_value()}")
    result = await asyncio.to_thread(_context_json, request, settings.context_dev_timeout_seconds + 5)
    request_id = result.get("request_id")
    markdown = result.get("markdown")
    if result.get("success") is not True or result.get("isPartial"):
        raise _context_error("HTML extraction failed or is partial", request_id)
    if not isinstance(markdown, str) or not markdown.strip():
        raise _context_error("HTML extraction is empty", request_id)
    if request_id is not None and not isinstance(request_id, str):
        raise _context_error("invalid extraction request ID")
    return ContextExtraction(markdown=markdown, request_id=request_id)


def _context_json(request: Request, timeout: int) -> dict:
    request_id = None
    try:
        with urlopen(request, timeout=timeout) as response:
            request_id = response.headers.get("X-Request-ID")
            result = json.load(response)
    except HTTPError as error:
        with error:
            request_id = error.headers.get("X-Request-ID") if error.headers else None
            if not request_id:
                try:
                    body = json.loads(error.read(16384))
                    if isinstance(body, dict):
                        request_id = body.get("request_id")
                except (ValueError, OSError, HTTPException):
                    pass
        raise _context_error(f"HTTP {error.code}", request_id) from None
    except (URLError, OSError, HTTPException):
        raise _context_error("connection error or timeout") from None
    except ValueError:
        raise _context_error("invalid JSON response", request_id) from None

    if not isinstance(result, dict):
        raise _context_error("unexpected response shape", request_id)
    if not result.get("request_id") and request_id:
        result["request_id"] = request_id
    return result


def _fetch_context_page(request: Request, timeout: int = 30) -> tuple[str, str]:
    result = _context_json(request, timeout)
    request_id = result.get("request_id")
    if result.get("isPartial"):
        raise _context_error("partial response", request_id)
    html = result.get("html")
    if not isinstance(html, dict) or html.get("success") is not True:
        reason = "HTML output failed or is missing"
        error_code = html.get("error_code") if isinstance(html, dict) else None
        if isinstance(error_code, str) and re.fullmatch(r"[A-Z][A-Z0-9_]{0,99}", error_code):
            reason += f" ({error_code})"
        raise _context_error(reason, request_id)
    if not isinstance(html.get("data"), str) or not html["data"].strip():
        raise _context_error("HTML output is empty", request_id)
    final_url = result.get("url")
    if not isinstance(final_url, str) or not final_url.strip():
        raise _context_error("page URL is missing", request_id)
    return final_url, html["data"]


async def request_gemini(
    model: str, method: str, payload: dict, *, settings: Settings
) -> dict:
    if settings.gemini_api_key is None or not settings.gemini_api_key.get_secret_value().strip():
        raise ValueError("Set GEMINI_API_KEY before calling Gemini")
    model = model.removeprefix("models/")
    if not re.fullmatch(r"[A-Za-z0-9._-]+", model):
        raise ValueError("Expected a Gemini model ID, optionally prefixed with models/")
    request = Request(
        f"https://generativelanguage.googleapis.com/v1beta/models/{model}:{method}",
        data=json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "x-goog-api-key": settings.gemini_api_key.get_secret_value(),
        },
        method="POST",
    )
    return await asyncio.to_thread(_send_request, request)


def _send_request(request: Request) -> dict:
    try:
        with urlopen(request, timeout=120) as response:
            result = json.load(response)
    except HTTPError as error:
        status = error.code
        error.close()
        raise RuntimeError(f"Gemini request failed with HTTP {status}") from None
    except (URLError, TimeoutError, OSError):
        raise RuntimeError("Gemini request failed due to a connection error or timeout") from None
    except (ValueError, UnicodeError):
        raise RuntimeError("Gemini returned an invalid JSON response") from None
    if not isinstance(result, dict):
        raise RuntimeError("Gemini returned an unexpected response shape")
    return result
