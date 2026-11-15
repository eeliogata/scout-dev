import json
import os
import re
import time
from pathlib import Path
from urllib.parse import urlsplit

from threat_monitor.ingestion.urls import origin


SESSION_DIR = Path(__file__).resolve().parents[2] / '.sessions'


def session_path(reference):
    if not re.fullmatch(r'[a-zA-Z0-9_-]{1,64}', reference):
        raise ValueError('Session reference must contain only letters, digits, underscores or hyphens')
    return SESSION_DIR / f'{reference}.json'


def private_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), 'w', encoding='utf-8') as file:
        if os.name != 'nt':
            os.fchmod(file.fileno(), 0o600)
        json.dump(value, file, ensure_ascii=False, indent=2)


def import_session(reference, url, export):
    allowed = origin(url)
    if allowed[0] != 'https':
        raise ValueError('Imported forum sessions require HTTPS')
    try:
        data = json.loads(Path(export).read_text(encoding='utf-8'))
        cookies = data.get('cookies') if isinstance(data, dict) else data
        if not isinstance(cookies, list):
            raise ValueError()
        selected = []
        for cookie in cookies:
            if not isinstance(cookie, dict):
                raise ValueError()
            domain = cookie.get('domain', '')
            if not isinstance(domain, str):
                raise ValueError()
            if domain.lstrip('.').lower() != allowed[1].lower():
                continue
            name, value = cookie.get('name'), cookie.get('value')
            if not isinstance(name, str) or (not name or any(ord(c) <= 32 or ord(c) > 126 or c in ';=,' for c in name)):
                raise ValueError()
            if not isinstance(value, str) or any(ord(c) < 32 or ord(c) > 126 or c == ';' for c in value):
                raise ValueError()
            path = cookie.get('path', '/')
            expires = cookie.get('expires', -1)
            secure = cookie.get('secure', False)
            if not isinstance(path, str) or not path.startswith('/') or not isinstance(expires, (int, float)) or not isinstance(secure, bool):
                raise ValueError()
            selected.append(dict(name=name, value=value, domain=domain, path=path, expires=expires, secure=secure))
        if not selected:
            raise ValueError()
    except (ValueError, TypeError, OSError):
        raise ValueError('Invalid cookie export or no cookies for the configured forum') from None
    SESSION_DIR.mkdir(mode=0o700, exist_ok=True)
    if os.name != 'nt':
        SESSION_DIR.chmod(0o700)
    private_json(session_path(reference), {'origin': list(allowed), 'cookies': selected})
    return len(selected)


def session_headers(reference, url):
    path = session_path(reference)
    try:
        # Windows uses inherited ACLs, not POSIX permission bits.
        if os.name != 'nt' and path.stat().st_mode & 0o077:
            raise ValueError('Session file must have permissions 0600')
        data = json.loads(path.read_text(encoding='utf-8'))
        if list(origin(url)) != data['origin']:
            raise ValueError('Session cannot be used outside its configured origin')
        request_path = urlsplit(url).path or '/'
        cookies = []
        for cookie in data['cookies']:
            expires = cookie['expires']
            if expires >= 0 and expires <= time.time():
                continue
            cp = cookie['path']
            if request_path != cp and not (request_path.startswith(cp) and (cp.endswith('/') or request_path[len(cp):].startswith('/'))):
                continue
            if cookie['secure'] and urlsplit(url).scheme != 'https':
                continue
            cookies.append(cookie)
        cookies.sort(key=lambda c: len(c['path']), reverse=True)
        if not cookies:
            raise ValueError('No matching unexpired session cookies; log in and import again')
        header = '; '.join(f"{c['name']}={c['value']}" for c in cookies)
        if len(header) > 8192 or '\r' in header or '\n' in header:
            raise ValueError('Session cookies exceed the supported header format')
        return {'Cookie': header}
    except (OSError, KeyError, TypeError, json.JSONDecodeError):
        raise ValueError('Session file is missing or invalid; import it again') from None
