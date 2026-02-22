"""Browser cookie caching for authenticated web access.

Reads cookies from Chrome/Edge, encrypts and caches them locally.
WebFetchTool uses the cache to send cookies with requests automatically.
"""

import base64
import hashlib
import http.cookiejar
import json
import os
import platform
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from loguru import logger

# Cache location
CACHE_PATH = Path.home() / ".nanobot" / "cookie_cache"


# ---------------------------------------------------------------------------
# Machine-ID based encryption key
# ---------------------------------------------------------------------------

def _get_machine_id() -> str:
    """Get a stable machine identifier for key derivation."""
    system = platform.system()
    try:
        if system == "Darwin":
            out = subprocess.check_output(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                text=True,
            )
            for line in out.splitlines():
                if "IOPlatformUUID" in line:
                    return line.split('"')[-2]
        elif system == "Linux":
            return Path("/etc/machine-id").read_text().strip()
        elif system == "Windows":
            out = subprocess.check_output(
                ["wmic", "csproduct", "get", "UUID"],
                text=True,
            )
            lines = [l.strip() for l in out.splitlines() if l.strip() and l.strip() != "UUID"]
            if lines:
                return lines[0]
    except Exception as e:
        logger.debug(f"Failed to get machine ID: {e}")

    # Fallback: hostname + username
    import getpass
    return f"{platform.node()}:{getpass.getuser()}"


def _derive_key(machine_id: str) -> bytes:
    """Derive a Fernet key from the machine ID."""
    digest = hashlib.sha256(machine_id.encode()).digest()
    return base64.urlsafe_b64encode(digest)


def _get_fernet():
    """Create a Fernet instance with the machine-derived key."""
    from cryptography.fernet import Fernet
    return Fernet(_derive_key(_get_machine_id()))


# ---------------------------------------------------------------------------
# Browser detection
# ---------------------------------------------------------------------------

def detect_browsers() -> list[dict[str, str]]:
    """Detect installed Chrome and Edge browsers.

    Returns list of dicts: [{"key": "chrome", "name": "Google Chrome"}, ...]
    """
    system = platform.system()
    found = []

    if system == "Darwin":
        checks = [
            ("chrome", "Google Chrome", "/Applications/Google Chrome.app"),
            ("edge", "Microsoft Edge", "/Applications/Microsoft Edge.app"),
        ]
        for key, name, path in checks:
            if Path(path).exists():
                found.append({"key": key, "name": name})

    elif system == "Linux":
        import shutil
        checks = [
            ("chrome", "Google Chrome", ["google-chrome", "google-chrome-stable"]),
            ("edge", "Microsoft Edge", ["microsoft-edge", "microsoft-edge-stable"]),
        ]
        for key, name, binaries in checks:
            if any(shutil.which(b) for b in binaries):
                found.append({"key": key, "name": name})

    elif system == "Windows":
        checks = [
            ("chrome", "Google Chrome", [
                os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
                os.path.expandvars(r"%PROGRAMFILES%\Google\Chrome\Application\chrome.exe"),
            ]),
            ("edge", "Microsoft Edge", [
                os.path.expandvars(r"%PROGRAMFILES(X86)%\Microsoft\Edge\Application\msedge.exe"),
                os.path.expandvars(r"%PROGRAMFILES%\Microsoft\Edge\Application\msedge.exe"),
            ]),
        ]
        for key, name, paths in checks:
            if any(Path(p).exists() for p in paths):
                found.append({"key": key, "name": name})

    return found


# ---------------------------------------------------------------------------
# Cookie read / cache
# ---------------------------------------------------------------------------

def _cookiejar_to_list(cj: http.cookiejar.CookieJar) -> list[dict[str, Any]]:
    """Convert a CookieJar to a serializable list of dicts."""
    cookies = []
    for c in cj:
        cookies.append({
            "name": c.name,
            "value": c.value,
            "domain": c.domain,
            "path": c.path,
            "secure": c.secure,
        })
    return cookies


def load_from_browser(browser_key: str) -> list[dict[str, Any]]:
    """Read all cookies from the specified browser.

    Args:
        browser_key: "chrome" or "edge"

    Returns:
        List of cookie dicts.

    Raises:
        ImportError: if browser_cookie3 is not installed.
    """
    try:
        import browser_cookie3
    except ImportError:
        raise ImportError(
            "browser_cookie3 is required for cookie caching.\n"
            "Install it with: pip install browser_cookie3"
        )

    loaders = {
        "chrome": browser_cookie3.chrome,
        "edge": browser_cookie3.edge,
    }
    loader = loaders.get(browser_key)
    if not loader:
        raise ValueError(f"Unsupported browser: {browser_key}")

    cj = loader()
    return _cookiejar_to_list(cj)


def save_cache(cookies: list[dict[str, Any]]) -> None:
    """Encrypt and save cookies to the cache file."""
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(cookies, ensure_ascii=False).encode()
    encrypted = _get_fernet().encrypt(data)
    CACHE_PATH.write_bytes(encrypted)


def load_cache() -> list[dict[str, Any]] | None:
    """Load cookies from the encrypted cache file. Returns None if no cache."""
    if not CACHE_PATH.exists():
        return None
    try:
        encrypted = CACHE_PATH.read_bytes()
        data = _get_fernet().decrypt(encrypted)
        return json.loads(data)
    except Exception as e:
        logger.debug(f"Failed to load cookie cache: {e}")
        return None


# ---------------------------------------------------------------------------
# Domain matching & cookie lookup
# ---------------------------------------------------------------------------

def _domain_matches(cookie_domain: str, request_host: str) -> bool:
    """Check if a cookie domain matches the request host.

    Rules:
    - ".example.com" matches "sub.example.com" and "example.com"
    - "example.com" matches only "example.com"
    """
    cookie_domain = cookie_domain.lower()
    request_host = request_host.lower()

    if cookie_domain.startswith("."):
        # ".example.com" matches "example.com" and "*.example.com"
        base = cookie_domain[1:]
        return request_host == base or request_host.endswith(cookie_domain)
    else:
        return request_host == cookie_domain


def get_cookies_for_url(url: str) -> dict[str, str]:
    """Get matching cookies for a URL from the cache.

    Returns an empty dict if no cache exists or no cookies match.
    """
    cookies = load_cache()
    if not cookies:
        return {}

    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        path = parsed.path or "/"
        is_secure = parsed.scheme == "https"
    except Exception:
        return {}

    matched: dict[str, str] = {}
    for c in cookies:
        # Domain match
        if not _domain_matches(c.get("domain", ""), host):
            continue
        # Path match
        cookie_path = c.get("path", "/")
        if not path.startswith(cookie_path):
            continue
        # Secure flag: only send secure cookies over HTTPS
        if c.get("secure") and not is_secure:
            continue
        matched[c["name"]] = c["value"]

    return matched


# ---------------------------------------------------------------------------
# Set-Cookie response handling
# ---------------------------------------------------------------------------

def update_from_response(url: str, set_cookie_headers: list[str]) -> None:
    """Parse Set-Cookie headers and update the cache."""
    cookies = load_cache()
    if cookies is None:
        # No existing cache, create a new one with just the response cookies
        cookies = []

    try:
        parsed = urlparse(url)
        default_domain = parsed.hostname or ""
    except Exception:
        return

    for header in set_cookie_headers:
        cookie = _parse_set_cookie(header, default_domain)
        if cookie:
            # Update existing or add new
            cookies = [
                c for c in cookies
                if not (c["name"] == cookie["name"] and c["domain"] == cookie["domain"])
            ]
            cookies.append(cookie)

    save_cache(cookies)


def _parse_set_cookie(header: str, default_domain: str) -> dict[str, Any] | None:
    """Parse a single Set-Cookie header into a cookie dict."""
    parts = [p.strip() for p in header.split(";")]
    if not parts:
        return None

    # First part is name=value
    name_value = parts[0]
    if "=" not in name_value:
        return None
    name, _, value = name_value.partition("=")
    name = name.strip()
    value = value.strip()
    if not name:
        return None

    cookie: dict[str, Any] = {
        "name": name,
        "value": value,
        "domain": default_domain,
        "path": "/",
        "secure": False,
    }

    # Parse attributes
    for attr in parts[1:]:
        attr_lower = attr.lower().strip()
        if attr_lower.startswith("domain="):
            domain = attr_lower[7:].strip()
            if domain and not domain.startswith("."):
                domain = "." + domain
            cookie["domain"] = domain
        elif attr_lower.startswith("path="):
            cookie["path"] = attr[5:].strip()
        elif attr_lower == "secure":
            cookie["secure"] = True

    return cookie
