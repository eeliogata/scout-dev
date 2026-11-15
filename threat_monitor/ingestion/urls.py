from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit


def thread_key(url):
    parts = urlsplit(url)
    return parts.path, tuple(sorted(
        (name, value) for name, value in parse_qsl(parts.query, keep_blank_values=True)
        if name != "page"
    ))


def origin(url: str) -> tuple[str, str, int]:
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username is not None or parts.port == 0:
        raise ValueError("Expected an HTTP(S) forum URL without credentials")
    return parts.scheme, parts.hostname, parts.port or (443 if parts.scheme == "https" else 80)


def resolve_url(base: str, href: str, allowed_origin: tuple[str, str, int], *, permalink: bool = False) -> str:
    if not href or not href.strip():
        raise ValueError("Forum link is missing its href")
    if "\\" in href or any(char in href for char in "\t\r\n"):
        raise ValueError("Invalid characters in forum link URL")
    try:
        url = urljoin(base, href.strip())
        allowed = origin(url) == allowed_origin
    except ValueError:
        raise ValueError("Invalid forum link URL") from None
    if not allowed:
        raise ValueError("Forum link points outside the configured origin")
    parts = urlsplit(url)
    scheme, hostname, port = allowed_origin
    host = f"[{hostname}]" if ":" in hostname else hostname
    if port != (443 if scheme == "https" else 80):
        host += f":{port}"
    return urlunsplit((scheme, host, parts.path or "/", parts.query, parts.fragment if permalink else ""))
