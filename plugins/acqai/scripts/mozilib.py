"""The Mozi (ACQ AI) send seam: ask Hormozi's business AI one question and
read its answer, through a paced, consent-gated, personal-use channel.

Two apps are supported (one learned route at a time):

  Portal (default)  https://portal.acquisition.com  UI /advisor
                    Aegis cookies; POST /api/sandbar/chat then chat-stream
  Legacy            https://ai.acquisition.com      UI /chat
                    Clerk __session (~60s); POST /api/chat (AI SDK body)

Set MOZI_BASE, or run login / login-legacy, to pick which login opens.
After a route is learned, base() follows that endpoint's host so later
sends stay on the same app without keeping MOZI_BASE set. A login whose
app differs from the route on file asks for one message and learns the
route again, so endpoint.json follows the app you signed into.

A chat belongs to the app that made it, and the portal answers 404 for the
messages of a chat the older app made. So the saved chat names its app,
as <id>@<host> (chat_ref), and a send posts it only to a route on that
host. Anything else stops before the first request (chat_mismatch).

Mozi offers no public API and no MCP (confirmed in the ACQ community). The
reachable path is each app's own internal HTTP endpoint, called with a
captured browser session, the way Hamel Husain's reverse-eng-site-skill and
skoollib both work.

AUTH IS A COOKIE HEADER. The default send builds it from the cookies the
browser login saved in storage-state.json (portal Aegis:
`__Secure-aegis-external.session_token` + `session_data`; legacy: Clerk
`__session`), so no token has to be captured by hand. MOZI_TOKEN, the whole
Cookie header from a signed-in request, overrides that when set. A 401 or
403 on this path, or no usable cookie on file, is MoziNoSession, and the
caller falls back to the browser transport, whose login refreshes
storage-state.json. The Set-Cookie headers a reply carries are written back
into storage-state.json so the saved session stays as fresh as the server
keeps it.

WHY THIS IS FENCED HARDER THAN THE READERS. Every other channel only reads.
This one writes into a paid third-party account through an undocumented route,
which can break Mozi's terms of service (the community's own HTTP-tips post
flags exactly this). So it is personal-use only, one request at a time, heavily
paced, and it never sends without a per-run consent flag. It touches Mozi's own
chat only, never the Skool community (that stays skoollib's job).

Secrets, both the member's own browser session, never committed:
  MOZI_TOKEN   the full Cookie header from a logged-in request (optional)
  MOZI_BASE    app origin (default https://portal.acquisition.com; legacy
               https://ai.acquisition.com)
The chat route and payload shape, learned by `discover` from a Copy-as-cURL of
a real send, land in endpoint.json under STATE_DIR (ACQAI_STATE_DIR, or
~/.config/acqai). The saved chat sits beside it in chat-id, and the login's
cookies in storage-state.json, which the browser login writes and this file
reads. The pace between sends is kept in last-send.json beside them, so the
floor holds across separate runs and both transports.
"""
from __future__ import annotations

import base64
import datetime
import email.utils
import http.cookies
import json
import os
import random
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

# The learned route, the chat id, the saved company, and the browser profile.
# A caller sets ACQAI_STATE_DIR before it imports this file. Unset, they sit
# in the member's home, so an update to the scripts never takes a login with it.
STATE_DIR = Path(os.environ.get("ACQAI_STATE_DIR", "").strip()
                 or "~/.config/acqai").expanduser()
ENDPOINT_FILE = STATE_DIR / "endpoint.json"
CHAT_ID_FILE = STATE_DIR / "chat-id"
CONFIG_FILE = STATE_DIR / "config.json"  # the saved company, when env has none
# The cookies the browser login saved (Playwright's storage_state JSON). The
# HTTP transport reads its session from here, and writes refreshed cookies
# back. mozi_browser keeps the same path as its STATE_FILE.
STORAGE_STATE_FILE = STATE_DIR / "storage-state.json"
# When the last send was posted and how it ended, so the pace between sends
# holds across runs, and ready can tell a login that works from one to check.
LAST_SEND_FILE = STATE_DIR / "last-send.json"
CHAT_ID_ENV = "MOZI_CHAT_ID"  # overrides the file for one process / nested send
# How a message names the command to run next, and the setup that installs the
# browser. The caller names its own script in ACQAI_CMD and ACQAI_SETUP_CMD.
CMD = os.environ.get("ACQAI_CMD", "").strip() or "acqai"
SETUP_CMD = os.environ.get("ACQAI_SETUP_CMD", "").strip() or f"{CMD} setup"
PORTAL_BASE = "https://portal.acquisition.com"
LEGACY_BASE = "https://ai.acquisition.com"
DEFAULT_BASE = PORTAL_BASE
USER_AGENT = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
              "AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/126.0.0.0 Safari/537.36")
# Portal Aegis session cookie, the one the HTTP transport needs on file.
_AEGIS_TOKEN = "__Secure-aegis-external.session_token"
# Legacy Clerk session cookie. Its JWT lives about a minute.
_CLERK_TOKEN = "__session"

_last_request = 0.0


class MoziError(RuntimeError):
    """Setup or parse trouble: missing token, no endpoint discovered yet."""


class MoziBlocked(MoziError):
    """The service said stop (401/403/429) or the session is logged out.
    `status` is the HTTP status that said so, or 0 when none did."""

    def __init__(self, message: str, status: int = 0) -> None:
        super().__init__(message)
        self.status = status


class MoziNoSession(MoziBlocked):
    """The HTTP path has no session to send with: no cookie on file, one
    that has expired, or one the server refused (401/403). The caller falls
    back to the browser, whose login refreshes the cookies on file."""


class MoziConsent(MoziError):
    """A send was attempted without the per-run MOZI_SEND_OK consent flag."""


class MoziChatElsewhere(MoziError):
    """The saved chat is from another app than the route posts to, or names
    no app. The send stops before any request and says how to go on."""


class MoziCutShort(MoziError):
    """The stream sent part of a reply, then an error or no closing event.
    The send fails, and the reply text it did send rides on `partial`, so a
    caller can keep it on the record. `reason` is one sentence."""

    def __init__(self, reason: str, partial: str) -> None:
        super().__init__(f"Mozi's reply stopped partway. {reason}")
        self.reason = reason
        self.partial = partial

    def logged(self) -> str:
        """The partial reply as a log keeps it, marked where it stopped."""
        return f"{self.partial}\n\n*(Cut short here. {self.reason})*"


def load_chat_id() -> str | None:
    """The saved Mozi chat as <id>@<host> (chat_ref), if any. Env wins so a
    nested send inside an ask can inherit without racing the file; otherwise
    the file under STATE_DIR carries the thread across separate runs. An id
    saved before chats named their app comes back bare, and a send stops on
    it rather than guess (chat_mismatch)."""
    env = os.environ.get(CHAT_ID_ENV, "").strip()
    if env:
        return env
    try:
        if CHAT_ID_FILE.is_file():
            return CHAT_ID_FILE.read_text(encoding="utf-8").strip() or None
    except OSError:
        return None
    return None


def save_chat_id(chat_id: str | None) -> None:
    """Remember the conversation so the next send continues it. The
    transport saves what chat_ref gives, so the chat carries its app."""
    cid = (chat_id or "").strip()
    if not cid:
        return
    os.environ[CHAT_ID_ENV] = cid
    try:
        CHAT_ID_FILE.parent.mkdir(parents=True, exist_ok=True)
        CHAT_ID_FILE.write_text(cid + "\n", encoding="utf-8")
    except OSError as err:
        print(f"acqai: chat-id save skipped ({err})", file=sys.stderr, flush=True)


def clear_chat_id() -> None:
    """Start a fresh Mozi conversation on the next send (`--new`)."""
    os.environ.pop(CHAT_ID_ENV, None)
    try:
        if CHAT_ID_FILE.is_file():
            CHAT_ID_FILE.unlink()
    except OSError as err:
        print(f"acqai: chat-id clear skipped ({err})", file=sys.stderr, flush=True)


# --- which app a chat belongs to ----------------------------------------------
def app_host(url: str | None) -> str | None:
    """The host an app answers on, lower case, from a URL, an origin, or a
    bare host. None when there is no host to read."""
    text = (url or "").strip()
    if not text:
        return None
    if "://" not in text:
        text = "https://" + text
    try:
        return urllib.parse.urlsplit(text).hostname or None
    except ValueError:
        return None


def chat_ref(chat_id: str | None, url: str | None) -> str | None:
    """A chat as the transport saves and logs it: <id>@<host>, where host is
    the app that made it (the route the send posted to). A bare id when the
    host cannot be read, and None for no id."""
    cid = (chat_id or "").strip()
    if not cid:
        return None
    host = app_host(url)
    return f"{cid}@{host}" if host else cid


def split_chat(saved: str | None) -> tuple[str, str | None]:
    """A saved chat as (the id its app knows, that app's host). The host is
    None for an id that names no app: one saved before chats named their
    app, or a bare MOZI_CHAT_ID."""
    text = (saved or "").strip()
    cid, at, host = text.rpartition("@")
    if not at or not cid:
        return text, None
    return cid, app_host(host)


def app_name(host: str | None) -> str:
    """How a message names an app: the portal, the older app, or its host."""
    if host and host == app_host(PORTAL_BASE):
        return "the portal"
    if host and host == app_host(LEGACY_BASE):
        return "the older app"
    return host or "no app"


def _login_for(host: str | None) -> str:
    """The command that signs into the app on this host and learns its route."""
    if host == app_host(LEGACY_BASE):
        return f"{CMD} login-legacy"
    if host == app_host(PORTAL_BASE):
        return f"{CMD} login"
    return f"MOZI_BASE=https://{host} {CMD} login"


def chat_mismatch(saved: str | None, cfg: dict | None = None) -> str:
    """Why a send must not post this saved chat to the learned route, or ""
    when it may. Empty with no chat, and with no route to compare against,
    since a send stops on the missing route first.

    The stop names both ways on, because the choice is the member's: a fresh
    thread on the route's app, or a login that moves the route back to the
    app that holds the chat. Nothing here drops the chat on its own."""
    if not (saved or "").strip():
        return ""
    cfg = cfg if cfg is not None else (endpoint() or {})
    route = app_host(cfg.get("url"))
    if not route:
        return ""
    cid, host = split_chat(saved)
    if host == route:
        return ""
    short = cid[:8] + "…"
    fresh = f"--new starts a fresh thread on {app_name(route)}"
    if not host:
        older, portal = app_host(LEGACY_BASE), app_host(PORTAL_BASE)
        return (f"Mozi chat {short} names no app, so nothing goes to Mozi. A "
                "chat continues only on the app that made it, and a saved "
                f"chat names that app after an @, as in <id>@{older} for the "
                f"older app or <id>@{portal} for the portal. {fresh}, where "
                "the route posts.")
    return (f"Mozi chat {short} is from {app_name(host)} ({host}), and the "
            f"route posts to {app_name(route)} ({route}). A chat continues "
            f"only on the app that made it, so nothing goes to Mozi. {fresh}. "
            f"{_login_for(host)} continues this chat on {app_name(host)}.")


def chat_for_route(saved: str | None, cfg: dict | None = None) -> str | None:
    """The id a send posts on the learned route, or None to start a new chat.

    Raises MoziChatElsewhere rather than post a chat the route's app did not
    make, and rather than trade it for a new thread without saying so."""
    why = chat_mismatch(saved, cfg)
    if why:
        raise MoziChatElsewhere(why)
    return split_chat(saved)[0] or None


def config() -> dict:
    """The saved settings (the company, for now). Empty where the caller
    exports MOZI_COMPANY instead."""
    try:
        data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def save_config(**fields) -> Path:
    """Merge the given settings into the config file and return its path."""
    data = config()
    data.update({k: v for k, v in fields.items() if v is not None})
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return CONFIG_FILE


# --- the cookies the browser login saved -------------------------------------
def _read_storage_state() -> dict:
    try:
        data = json.loads(STORAGE_STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def stored_cookies() -> list[dict]:
    """Every cookie in storage-state.json, as Playwright saved it: name,
    value, domain, path, expires (epoch seconds, -1 for a session cookie),
    secure, httpOnly, sameSite. Empty when there is no file."""
    cookies = _read_storage_state().get("cookies")
    return [c for c in cookies if isinstance(c, dict)] if isinstance(cookies, list) else []


def _cookie_matches(cookie: dict, host: str) -> bool:
    """True when a cookie's domain covers this host: an exact host, or a
    leading-dot domain the host sits under (.acquisition.com covers
    portal.acquisition.com and ai.acquisition.com both)."""
    domain = str(cookie.get("domain") or "").lower().lstrip(".")
    if not domain or not host:
        return False
    return host == domain or host.endswith("." + domain)


def _cookie_live(cookie: dict, now: float | None = None) -> bool:
    """True when a cookie has not expired. A session cookie (expires -1 or
    absent) counts as live."""
    exp = cookie.get("expires")
    if not isinstance(exp, (int, float)) or exp <= 0:
        return True
    return exp > (now if now is not None else time.time())


def cookies_for(host: str | None = None) -> list[dict]:
    """The live cookies on file for this host (default: the app's host)."""
    host = (host or app_host(base()) or "").lower()
    return [c for c in stored_cookies()
            if c.get("name") and _cookie_matches(c, host) and _cookie_live(c)]


def session_cookie(host: str | None = None) -> dict | None:
    """The session cookie on file for this host, live or not: portal Aegis
    session_token, else legacy Clerk __session. None when there is none."""
    host = (host or app_host(base()) or "").lower()
    found = None
    for c in stored_cookies():
        name = str(c.get("name") or "")
        if not _cookie_matches(c, host) or not str(c.get("value") or ""):
            continue
        if name == _AEGIS_TOKEN or name.endswith("aegis-external.session_token"):
            return c
        if name == _CLERK_TOKEN or name.startswith(_CLERK_TOKEN + "_"):
            found = found or c
    return found


def session_cookie_expires(host: str | None = None) -> float | None:
    """When the session cookie on file expires, as epoch seconds. None when
    there is no cookie, or it is a session cookie with no expiry."""
    c = session_cookie(host)
    if not c:
        return None
    exp = c.get("expires")
    return float(exp) if isinstance(exp, (int, float)) and exp > 0 else None


def session_expires_text(host: str | None = None) -> str:
    """The cookie's expiry as a line a member reads: the date, and how far
    off it is, or that there is none."""
    c = session_cookie(host)
    if not c:
        return "no login cookie on file"
    exp = session_cookie_expires(host)
    if exp is None:
        return "login cookie on file (no expiry recorded)"
    left = exp - time.time()
    when = time.strftime("%Y-%m-%d %H:%M", time.localtime(exp))
    if left <= 0:
        return f"login cookie EXPIRED {when}"
    if left < 3600:
        return f"login cookie expires {when} ({int(left // 60)} minutes left)"
    if left < 2 * 86400:
        return f"login cookie expires {when} ({left / 3600:.0f} hours left)"
    return f"login cookie expires {when} ({left / 86400:.1f} days left)"


def stored_cookie_header(host: str | None = None) -> str:
    """The Cookie header the live cookies on file make for this host, in
    the order they were saved, or "" when none."""
    return "; ".join(f"{c['name']}={c.get('value', '')}" for c in cookies_for(host))


# --- the last send: when it was posted, and how it ended ---------------------
def last_send() -> dict:
    """What last-send.json holds: `at`, when the last send was posted (epoch
    seconds); `ended`, when it ended; `ok`, True, False, or None while it
    runs; `transport`; and `error`, the reason when it failed. Empty when no
    send has been recorded."""
    try:
        data = json.loads(LAST_SEND_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_last_send(data: dict) -> None:
    try:
        LAST_SEND_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = LAST_SEND_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        tmp.replace(LAST_SEND_FILE)
    except OSError as err:
        print(f"acqai: last-send record skipped ({err})", file=sys.stderr,
              flush=True)


def mark_send_start(transport: str) -> None:
    """A send is about to post: stamp it, so the next send paces from it
    even when this one ends in an error."""
    _write_last_send({"at": time.time(), "ended": None, "ok": None,
                      "transport": transport, "error": ""})


def record_send(ok: bool, transport: str, error: str = "") -> None:
    """How the send ended. ready reads this: a login that answered a send
    in the last week needs no browser check, and one that failed does."""
    data = last_send()
    data.update({"ended": time.time(), "ok": bool(ok), "transport": transport,
                 "error": " ".join((error or "").split())[:300]})
    data.setdefault("at", data["ended"])
    _write_last_send(data)


def cookie_header() -> str:
    """The whole Cookie header: MOZI_TOKEN when set, else the cookies the
    browser login saved, for the app's host."""
    env = os.environ.get("MOZI_TOKEN", "").strip()
    return env or stored_cookie_header()


def _parse_set_cookie(header: str, host: str) -> dict | None:
    """One Set-Cookie header as a storage-state cookie, or None when it has
    no name. Domain and path default the way a browser defaults them for
    the request host. Max-Age wins over Expires, as in a browser."""
    try:
        jar = http.cookies.SimpleCookie()
        jar.load(header)
    except http.cookies.CookieError:
        return None
    for name, morsel in jar.items():
        out = {"name": name, "value": morsel.value,
               "domain": (morsel["domain"] or host).lower(),
               "path": morsel["path"] or "/",
               "expires": -1,
               "httpOnly": bool(morsel["httponly"]),
               "secure": bool(morsel["secure"]),
               "sameSite": (morsel["samesite"] or "Lax").capitalize()}
        if morsel["domain"] and not out["domain"].startswith("."):
            out["domain"] = "." + out["domain"]
        max_age = morsel["max-age"]
        if max_age:
            try:
                out["expires"] = int(time.time()) + int(max_age)
            except ValueError:
                pass
        elif morsel["expires"]:
            when = email.utils.parsedate_to_datetime(morsel["expires"]) \
                if morsel["expires"] else None
            if when is not None:
                if when.tzinfo is None:
                    when = when.replace(tzinfo=datetime.timezone.utc)
                out["expires"] = int(when.timestamp())
        return out
    return None


def store_set_cookies(headers: list[str], host: str | None = None) -> int:
    """Write the cookies a reply's Set-Cookie headers carry into
    storage-state.json, replacing a cookie of the same name and domain, so
    a session the server refreshed stays fresh on file. Returns how many
    cookies changed. A cookie the server cleared (Max-Age 0, or an expiry
    in the past) is dropped. Nothing is written when there is no file: the
    browser login makes it, and this only keeps it current."""
    host = (host or app_host(base()) or "").lower()
    if not headers or not STORAGE_STATE_FILE.is_file():
        return 0
    state = _read_storage_state()
    cookies = [c for c in state.get("cookies", []) if isinstance(c, dict)] \
        if isinstance(state.get("cookies"), list) else []
    changed = 0
    for header in headers:
        new = _parse_set_cookie(header, host)
        if not new:
            continue
        # The cookie it replaces: the same name and path, on the same domain
        # or on one that covers this host (a host-only reply cookie stands
        # in for the leading-dot one the browser saved).
        domain = new["domain"].lstrip(".")
        kept = [c for c in cookies
                if not (str(c.get("name")) == new["name"]
                        and str(c.get("path") or "/") == new["path"]
                        and (str(c.get("domain") or "").lstrip(".") == domain
                             or _cookie_matches(c, host)))]
        if _cookie_live(new):
            kept.append(new)
        cookies = kept
        changed += 1
    if not changed:
        return 0
    state["cookies"] = cookies
    state.setdefault("origins", [])
    try:
        tmp = STORAGE_STATE_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
        tmp.replace(STORAGE_STATE_FILE)
    except OSError as err:
        print(f"acqai: cookie refresh not saved ({err})", file=sys.stderr,
              flush=True)
        return 0
    return changed


def origin_from_endpoint(cfg: dict | None = None) -> str | None:
    """App origin learned from endpoint.json's chat URL, or None."""
    cfg = cfg if cfg is not None else endpoint()
    url = (cfg or {}).get("url") if isinstance(cfg, dict) else None
    if not isinstance(url, str) or not url.strip():
        return None
    m = re.match(r"(https?://[^/\s]+)", url.strip())
    return m.group(1).rstrip("/") if m else None


def base() -> str:
    """App origin: MOZI_BASE, else the learned endpoint's host, else portal."""
    env = os.environ.get("MOZI_BASE", "").strip()
    if env:
        return env.rstrip("/")
    learned = origin_from_endpoint()
    if learned:
        return learned
    return DEFAULT_BASE


def is_portal(origin: str | None = None) -> bool:
    """True when the origin (or base()) is the ACQ portal, not legacy AI."""
    host = (origin or base()).lower()
    return "portal.acquisition.com" in host


def page_path(origin: str | None = None) -> str:
    """Chat UI path: /advisor on portal, /chat on legacy."""
    return "/advisor" if is_portal(origin) else "/chat"


def chat_page_url(*, chat_id: str | None = None,
                  company_id: str | None = None,
                  origin: str | None = None) -> str:
    """The signed-in chat page, with optional portal query ids."""
    root = (origin or base()).rstrip("/")
    url = root + page_path(root)
    q: list[str] = []
    if chat_id:
        q.append("chatId=" + chat_id)
    if company_id:
        q.append("companyId=" + company_id)
    return url + (("?" + "&".join(q)) if q else "")


def send_allowed() -> bool:
    """A send needs explicit per-run consent, since it writes to a third party."""
    return os.environ.get("MOZI_SEND_OK", "").strip() in {"1", "true", "yes"}


def _int_env(name: str, default: int, lo: int, hi: int) -> int:
    try:
        return max(lo, min(hi, int(os.environ.get(name, ""))))
    except (TypeError, ValueError):
        return default


def has_session_cookie(header: str | None = None) -> bool:
    """True when the Cookie header carries portal Aegis or legacy Clerk auth."""
    h = header if header is not None else cookie_header()
    if not h:
        return False
    if _AEGIS_TOKEN in h or "aegis-external.session_token=" in h:
        return True
    return bool(re.search(r"(?:^|;\s*)__session(?:_[A-Za-z0-9]+)?=", h))


# --- token freshness: decode the __session JWT exp, warn when stale -----------
def session_expiry() -> int | None:
    """Seconds until the session expires (negative if already expired), or
    None when nothing says. With MOZI_TOKEN set, that is the Clerk __session
    JWT's exp, when the header carries one (Clerk tokens live ~60s). With the
    cookies on file, it is the session cookie's own expiry."""
    header = os.environ.get("MOZI_TOKEN", "").strip()
    if not header:
        exp = session_cookie_expires()
        return int(exp - time.time()) if exp is not None else None
    m = re.search(r"__session(?:_[A-Za-z0-9]+)?=([^;]+)", header)
    if not m:
        return None
    parts = m.group(1).split(".")
    if len(parts) < 2:
        return None
    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        claims = json.loads(base64.urlsafe_b64decode(payload))
        return int(claims["exp"]) - int(time.time())
    except Exception:
        return None


def _pace(transport: str = "HTTP") -> None:
    """One send at a time, a long jittered gap between them (default 12-30s):
    a send channel to a paid service earns a slower floor than a reader.
    Each transport calls this once, right before it posts a question. The
    gap is measured from the last send on file (last-send.json), so it
    holds across separate runs and across both transports, and from the
    last send in this process, whichever is later. Then the send is
    stamped as started, so the next one paces from it even when this one
    fails partway."""
    global _last_request
    lo = _int_env("MOZI_MIN_DELAY", 12, 8, 120)
    hi = max(lo, _int_env("MOZI_MAX_DELAY", 30, 8, 300))
    since = None
    if _last_request:
        since = time.monotonic() - _last_request
    last = last_send().get("at")
    if isinstance(last, (int, float)) and last > 0:
        on_file = time.time() - last
        if on_file >= 0 and (since is None or on_file < since):
            since = on_file
    if since is not None:
        wait = random.uniform(lo, hi) - since
        if wait > 0:
            print(f"acqai: pacing {wait:.0f}s before Mozi send…",
                  file=sys.stderr, flush=True)
            time.sleep(wait)
    _last_request = time.monotonic()
    mark_send_start(transport)


def require_cookie_header() -> str:
    """The Cookie header a send goes out with, or MoziNoSession when there
    is none to send with: no cookie on file (and no MOZI_TOKEN), or none
    that is a session cookie."""
    header = cookie_header()
    if not header:
        raise MoziNoSession(
            f"no login cookie on file for {base()} ({STORAGE_STATE_FILE}); "
            f"{CMD} login saves one, or set MOZI_TOKEN to the whole Cookie "
            "header from a signed-in request")
    if not has_session_cookie(header):
        raise MoziNoSession(
            "the cookies on file carry no Aegis or Clerk session cookie "
            f"({_AEGIS_TOKEN} or __session); {CMD} login saves a fresh one")
    return header


def _request(method: str, url: str, *, body: bytes | None = None,
             content_type: str = "application/json",
             timeout: int = 90,
             referer: str | None = None) -> tuple[int, bytes]:
    header = require_cookie_header()
    headers = {"User-Agent": USER_AGENT, "Cookie": header,
               "Origin": base(),
               "Referer": referer or chat_page_url(),
               "Accept": "text/event-stream, application/json, text/plain"}
    # Legacy /api/chat checks x-ui-nonce mirroring acq_ui_nonce; portal does not.
    nonce = re.search(r"acq_ui_nonce=([^;]+)", header)
    if nonce:
        headers["x-ui-nonce"] = nonce.group(1)
    if body is not None:
        headers["Content-Type"] = content_type
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    host = app_host(url)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            _keep_cookies(resp.headers, host)
            return resp.status, raw
    except urllib.error.HTTPError as err:
        _keep_cookies(err.headers, host)
        try:
            why = refusal(err.read())
        except Exception:
            why = ""
        why = f": {why}" if why else ""
        if err.code in (401, 403):
            raise MoziNoSession(
                f"{err.code} from mozi on {url}{why}", err.code) from err
        if err.code == 429:
            raise MoziBlocked(f"429 from mozi on {url}{why}", 429) from err
        raise MoziError(f"{err.code} on {url}{why}") from err
    except Exception as err:
        raise MoziError(f"{err} on {url}") from err


def _keep_cookies(headers, host: str | None) -> None:
    """Write a reply's Set-Cookie headers back to the cookies on file. A
    MOZI_TOKEN send leaves the file alone: that session is the shell's."""
    if headers is None or os.environ.get("MOZI_TOKEN", "").strip():
        return
    try:
        values = headers.get_all("Set-Cookie") or []
    except Exception:
        return
    if values:
        store_set_cookies(list(values), host)


def refusal(raw: "bytes | str | None") -> str:
    """The server's own reason from an error body, on one short line, or "".

    The portal answers {error, message, statusCode}. Its 403 for a session
    with no workspace picked reads "ACQ AI and Command Center access is not
    active.", which says more than the status does."""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    try:
        data = json.loads(raw or "")
    except ValueError:
        return ""
    if not isinstance(data, dict):
        return ""
    for key in ("message", "error"):
        val = data.get(key)
        if isinstance(val, str) and val.strip():
            return " ".join(val.split())[:200]
    return ""


# --- endpoint config, learned from a captured cURL ----------------------------
def endpoint() -> dict | None:
    try:
        return json.loads(ENDPOINT_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


_MSG_KEYS = ("message", "prompt", "text", "input", "query", "content", "question")


def _find_message_slot(body: object) -> str | None:
    """Where the user's message text sits in a captured body, as a small path
    language: "message.aisdk" for the AI SDK single-message shape (a `message`
    object with `parts`/`content`), "messages[-1].content" for a chat array, or
    "field" for a flat key. None if nothing message-shaped is found."""
    if isinstance(body, dict):
        m = body.get("message")
        if isinstance(m, dict) and ("content" in m or "parts" in m):
            return "message.aisdk"
        msgs = body.get("messages")
        if isinstance(msgs, list) and msgs and isinstance(msgs[-1], dict):
            for k in ("content", "text"):
                if k in msgs[-1]:
                    return f"messages[-1].{k}"
        for k in _MSG_KEYS:
            if isinstance(body.get(k), str):
                return k
    return None


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.") + f"{datetime.datetime.now().microsecond // 1000:03d}Z"


def _set_message(body: object, slot: str, question: str,
                 chat_id: str | None = None) -> object:
    body = json.loads(json.dumps(body))  # deep copy
    if slot == "message.aisdk":
        # Legacy AI SDK useChat body: one `message` object. Set its text and
        # give the message a fresh id + timestamp. The chat `id` is the
        # conversation: reuse chat_id to continue, or mint a new one per ask.
        m = body["message"]
        m["content"] = question
        text_parts = [p for p in m.get("parts", [])
                      if isinstance(p, dict) and p.get("type") == "text"]
        if text_parts:
            text_parts[0]["text"] = question
            m["parts"] = [p for p in m["parts"]
                          if not (isinstance(p, dict) and p.get("type") == "text")
                          or p is text_parts[0]]
        else:
            m["parts"] = [{"type": "text", "text": question}]
        m["id"] = str(uuid.uuid4())
        if "createdAt" in m:
            m["createdAt"] = _now_iso()
        if "id" in body:
            body["id"] = chat_id or str(uuid.uuid4())
        return body
    if slot.startswith("messages[-1]."):
        # Portal sandbar chat-stream: one user message in `messages`, ids in
        # toolContext.chatId / newMessageId / messageId, plus requestId.
        field = slot.split(".", 1)[1]
        msg = body["messages"][-1]
        msg[field] = question
        new_id = str(uuid.uuid4())
        if isinstance(msg, dict):
            msg["id"] = new_id
        if "requestId" in body:
            body["requestId"] = str(uuid.uuid4())
        if "clientLocalTime" in body:
            body["clientLocalTime"] = _now_iso()
        tc = body.get("toolContext")
        if isinstance(tc, dict):
            cid = chat_id or tc.get("chatId") or str(uuid.uuid4())
            tc["chatId"] = cid
            tc["newMessageId"] = new_id
            tc["messageId"] = str(uuid.uuid4())
        return body
    body[slot] = question
    return body


def _chat_id_of(body: object) -> str | None:
    if not isinstance(body, dict):
        return None
    tc = body.get("toolContext")
    if isinstance(tc, dict) and tc.get("chatId"):
        return str(tc["chatId"])
    cid = body.get("id")
    return str(cid) if cid else None


def build_body(question: str, chat_id: str | None = None) -> tuple[object, str | None]:
    """The request body for one question, and the chat id it belongs to (so a
    caller can pass it back to continue the dialogue). Shared by both transports
    (raw HTTP and the browser)."""
    cfg = endpoint() or {}
    tmpl, slot = cfg.get("body_template"), cfg.get("message_slot")
    if tmpl is not None and slot:
        body = _set_message(tmpl, slot, question, chat_id=chat_id)
    elif tmpl is not None:
        raise MoziError('the captured body has no detected message slot; add '
                        f'"message_slot" to {ENDPOINT_FILE} by hand')
    else:
        body = {"message": question}
    return body, _chat_id_of(body)


def is_sandbar(cfg: dict | None = None) -> bool:
    """True when the learned route is portal sandbar chat-stream."""
    cfg = cfg if cfg is not None else (endpoint() or {})
    url = (cfg.get("url") or "").lower()
    return "sandbar" in url and "chat-stream" in url


def create_url(cfg: dict | None = None) -> str | None:
    """POST URL that creates a sandbar chat, or None on legacy."""
    cfg = cfg if cfg is not None else (endpoint() or {})
    if cfg.get("create_url"):
        return str(cfg["create_url"])
    url = (cfg.get("url") or "").rstrip("/")
    if url.endswith("chat-stream"):
        return url[: -len("chat-stream")] + "chat"
    return None


def company_id_from_endpoint(cfg: dict | None = None) -> str | None:
    cfg = cfg if cfg is not None else (endpoint() or {})
    body = cfg.get("body_template")
    if not isinstance(body, dict):
        return None
    tc = body.get("toolContext")
    if isinstance(tc, dict):
        for key in ("clientServiceCompanyId", "companyId"):
            val = tc.get(key)
            if val:
                return str(val)
    return None


def _title_from(question: str) -> str:
    line = (question or "").strip().splitlines()[0] if question else ""
    line = re.sub(r"\s+", " ", line).strip()
    return (line[:80] if line else "Chat")


def create_chat_body(title: str, cfg: dict | None = None) -> dict:
    """JSON body for POST /api/sandbar/chat."""
    cfg = cfg if cfg is not None else (endpoint() or {})
    body: dict = {"title": _title_from(title)}
    company = company_id_from_endpoint(cfg)
    if company:
        body["clientServiceCompanyId"] = company
    return body


def parse_create_chat_id(raw: bytes) -> str:
    try:
        data = json.loads(raw.decode("utf-8", errors="replace"))
    except ValueError as err:
        raise MoziError(f"create chat returned non-JSON: {raw[:200]!r}") from err
    if not isinstance(data, dict):
        raise MoziError(f"create chat returned a non-object: {raw[:200]!r}")
    cid = data.get("id") or data.get("chatId")
    if not cid:
        raise MoziError(f"create chat returned no id: {raw[:200]!r}")
    return str(cid)


def create_chat(title: str, *, timeout: int = 60) -> str:
    """HTTP: create a portal sandbar chat and return its id."""
    cfg = endpoint() or {}
    url = create_url(cfg)
    if not url:
        raise MoziError("no sandbar create URL (learned route is not chat-stream)")
    body = create_chat_body(title, cfg)
    _status, raw = _request("POST", url, body=json.dumps(body).encode("utf-8"),
                            timeout=timeout)
    return parse_create_chat_id(raw)


def _with_create_url(cfg: dict) -> dict:
    """Attach create_url when learning a sandbar stream route."""
    out = dict(cfg)
    if not out.get("create_url"):
        derived = create_url(out)
        if derived:
            out["create_url"] = derived
    return out


def parse_curl(text: str) -> dict:
    """Learn the chat endpoint from a Copy-as-cURL blob: url, method, JSON body
    template, and where the message slots in. The cookie is read but never
    stored (it's the live secret; it belongs in MOZI_TOKEN)."""
    # URL: the first http(s) token, quoted or bare (--url FORM included).
    m = re.search(r"""curl\s+(?:-[A-Za-z-]+\s+)*['"]?(https?://[^'"\s]+)""", text)
    if not m:
        m = re.search(r"""--url\s+['"]?(https?://[^'"\s]+)""", text)
    if not m:
        m = re.search(r"""['"](https?://[^'"\s]+)['"]""", text)
    if not m:
        raise MoziError("no URL found in the cURL blob")
    url = m.group(1)
    method = "POST"
    xm = re.search(r"(?:-X|--request)\s+['\"]?([A-Z]+)", text)
    if xm:
        method = xm.group(1)
    bm = re.search(r"(?:--data-raw|--data-binary|--data|-d)\s+'((?:[^'\\]|\\.)*)'",
                   text, re.S)
    if not bm:
        bm = re.search(r'(?:--data-raw|--data-binary|--data|-d)\s+"((?:[^"\\]|\\.)*)"',
                       text, re.S)
    body_template = None
    message_slot = None
    if bm:
        raw = bm.group(1).encode().decode("unicode_escape") if "\\" in bm.group(1) else bm.group(1)
        try:
            body_template = json.loads(raw)
            message_slot = _find_message_slot(body_template)
        except ValueError:
            body_template = None
        if method == "POST" and not xm and body_template is None:
            method = "POST"
    stream = ("text/event-stream" in text or "/api/chat" in url
              or "chat-stream" in url)
    return _with_create_url({
        "url": url, "method": method, "body_template": body_template,
        "message_slot": message_slot, "stream": stream,
    })


def learn_from_request(url: str, method: str, post_data: "str | None") -> "dict | None":
    """The route config from one request the app made itself: the POST that
    carries a chat message. login listens for it, so a member who sends one
    message in the window has taught the transport the route with no cURL to
    copy. A GET, another path, or a body with no message slot is None.

    Accepts legacy /api/chat and portal /api/sandbar/chat-stream. Skips
    /api/sandbar/chat (create-only; no message slot)."""
    if (method or "").upper() != "POST" or not post_data:
        return None
    clean = (url or "").split("?", 1)[0]
    path = clean.lower()
    if "/api/" not in path:
        return None
    leaf = path.rsplit("/", 1)[-1]
    # chat-stream (portal) or chat (legacy /api/chat). Not chat-list, etc.
    if leaf not in ("chat", "chat-stream") and "chat-stream" not in leaf:
        return None
    if leaf == "chat" and "/sandbar/" in path:
        return None  # create-or-get, no user message
    try:
        body = json.loads(post_data)
    except ValueError:
        return None
    slot = _find_message_slot(body)
    if not slot:
        return None
    return _with_create_url({
        "url": clean, "method": "POST", "body_template": body,
        "message_slot": slot, "stream": True,
    })


def save_endpoint(cfg: dict) -> Path:
    ENDPOINT_FILE.parent.mkdir(parents=True, exist_ok=True)
    cfg = _with_create_url(cfg)
    safe = {k: cfg.get(k) for k in
            ("url", "method", "body_template", "message_slot", "stream",
             "answer_path", "create_url")}
    ENDPOINT_FILE.write_text(json.dumps(safe, indent=2) + "\n", encoding="utf-8")
    return ENDPOINT_FILE


# --- response parsing: JSON, SSE, NDJSON, or Vercel AI SDK data stream --------
_TEXT_DELTA_TYPES = ("text-delta", "response.output_text.delta")


def _event_text(event: dict) -> str:
    """The reply text one typed stream event carries, or "". These are the
    three shapes the portal's own reader (its client bundle) takes text
    from, so a reasoning event yields nothing even when it has a `delta`."""
    kind = event.get("type")
    delta = event.get("delta")
    if kind in _TEXT_DELTA_TYPES and isinstance(delta, str):
        return delta
    text = event.get("text")
    if kind == "text" and isinstance(text, str):
        return text
    text_delta = event.get("textDelta")
    return text_delta if isinstance(text_delta, str) else ""


def _error_reason(event: dict) -> str:
    """The reason an error event gives, on one line, or "": its errorText,
    message, or error string, else the message of an error object."""
    for key in ("errorText", "message", "error"):
        val = event.get(key)
        if isinstance(val, str) and val.strip():
            return " ".join(val.split())[:200]
    err = event.get("error")
    msg = err.get("message") if isinstance(err, dict) else None
    return " ".join(msg.split())[:200] if isinstance(msg, str) else ""


# The finish reasons the portal's reader takes as the end of a reply.
_FINISH_REASONS = ("stop", "length", "content-filter", "error", "other",
                   "abort")
_CLOSING_TYPES = ("finish", "error", "response.completed", "response.error")


def _closes(event: dict) -> bool:
    """True for the event the portal's reader stops at: a closing type, or a
    finish reason it knows. A response that completed to call tools goes on."""
    reason = event.get("finishReason")
    reason = reason if isinstance(reason, str) else ""
    if event.get("type") == "response.completed" and reason == "tool-calls":
        return False
    return reason in _FINISH_REASONS or event.get("type") in _CLOSING_TYPES


def _closed_on_error(event: dict) -> bool:
    """True when a closing event ends the reply on an error, the way the
    portal's reader resolves it: its finish reason, else the error types,
    or an error event that says what went wrong."""
    reason = event.get("finishReason")
    if not (isinstance(reason, str) and reason in _FINISH_REASONS):
        reason = ("error" if event.get("type") in ("error", "response.error")
                  else "stop")
    return reason == "error" or bool(
        event.get("type") == "error" and _error_reason(event))


def _sent_error(why: str) -> str:
    """One sentence on an error the stream sent, with its reason if any."""
    return (f"The stream sent an error: {why.rstrip('.!?')}." if why
            else "The stream sent an error and gave no reason.")


def _error_sentence(event: dict) -> str:
    """One sentence on the error a closing event carries."""
    why = _error_reason(event)
    if why or event.get("type") == "error":
        return _sent_error(why)
    return "The stream finished on an error."


def _content_text(value: object) -> str:
    """Text from a message's content or parts: a string, a text object, or a
    list of text parts."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict) and isinstance(value.get("text"), str):
        return value["text"]
    if isinstance(value, list):
        return "".join(p["text"] for p in value if isinstance(p, dict)
                       and p.get("type") == "text"
                       and isinstance(p.get("text"), str))
    return ""


def _closing_text(event: dict) -> str:
    """The whole reply a closing event can carry: its own text, else its
    responseMessage's content or parts. The portal's page shows it only when
    no reply text streamed before it."""
    text = event.get("text")
    if isinstance(text, str) and text:
        return text
    message = event.get("responseMessage")
    if not isinstance(message, dict):
        return ""
    return (_content_text(message.get("content"))
            or _content_text(message.get("parts")))


def _no_reply(events: list[dict]) -> str:
    """Why a typed stream carried no reply text: its own error, else the
    event types it did carry. Never the reasoning itself."""
    for event in events:
        why = _error_reason(event) if event.get("type") == "error" else ""
        if why:
            return "Mozi's stream carried an error and no reply: " + why
    kinds = dict.fromkeys(e["type"] for e in events
                          if isinstance(e.get("type"), str))
    return ("Mozi's stream carried no reply text, only these events: "
            + ", ".join(kinds))


def _typed_answer(events: list[dict]) -> str:
    """The reply a typed stream carries, read the way the portal's chat page
    reads its sandbar stream. Text comes from each event in order, up to the
    first closing event, and nothing after it counts. When nothing streamed,
    the closing event's own text is the reply. The read raises when the
    reply closes on an error, when no closing event came, and when there is
    no reply text. Returning the part would let the send exit 0 and file it
    as the whole answer, so a part rides on MoziCutShort and the log keeps
    it."""
    parts: list[str] = []
    for n, event in enumerate(events):
        parts.append(_event_text(event))
        if not _closes(event):
            continue
        answer = "".join(parts).strip() or _closing_text(event).strip()
        if _closed_on_error(event):
            if answer:
                raise MoziCutShort(_error_sentence(event), answer)
            why = _error_reason(event)
            raise MoziError("Mozi's stream carried an error and no reply: "
                            + why if why else _no_reply(events[:n + 1]))
        if answer:
            return answer
        # Returning "" would let the send exit 0 as a sent ask, and taking
        # every `delta` would put the reasoning back in the answer.
        raise MoziError(_no_reply(events[:n + 1]))
    # The page reads a stream that stops before a closing event as a reply
    # that was interrupted.
    answer = "".join(parts).strip()
    if answer:
        raise MoziCutShort("The stream ended before it finished.", answer)
    raise MoziError(_no_reply(events))


# One line of an AI SDK data stream, the older app's: a one-character type, a
# colon, then a JSON value. Type 0 is reply text and type 3 an error.
_DATA_PART = re.compile(r"^([0-9a-z]):(.+)$")


def _data_stream_answer(text: str) -> str | None:
    """The reply an AI SDK data stream carries, read in stream order, or None
    when the text holds no text part and no error part. The first error part
    ends the read, the way the AI SDK's own reader throws on one: after some
    reply text it raises MoziCutShort, and with none it raises MoziError."""
    parts: list[str] = []
    seen = False
    for line in text.splitlines():
        m = _DATA_PART.match(line.strip())
        if not m or m.group(1) not in ("0", "3"):
            continue
        try:
            val, _end = json.JSONDecoder().raw_decode(m.group(2))
        except ValueError:
            continue
        if not isinstance(val, str):
            continue
        seen = True
        if m.group(1) == "0":
            parts.append(val)
            continue
        why = " ".join(val.split())[:200]
        answer = "".join(parts).strip()
        if answer:
            raise MoziCutShort(_sent_error(why), answer)
        raise MoziError("Mozi's stream carried an error and no reply: "
                        + (why or "the error part gave no reason"))
    return "".join(parts).strip() if seen else None


def extract_answer(raw: bytes, cfg: dict) -> str:
    text = raw.decode("utf-8", errors="replace").strip()
    # The older app's AI SDK data stream: 0:"…" text parts, 3:"…" errors.
    answer = _data_stream_answer(text)
    if answer is not None:
        return answer
    # SSE or NDJSON: one JSON event per line.
    events: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("data:"):
            line = line[5:].strip()
        if line in ("", "[DONE]"):
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if isinstance(obj, dict):
            events.append(obj)
    if any(isinstance(e.get("type"), str) for e in events):
        # A typed stream, the portal's: the answer is its text events alone.
        return _typed_answer(events)
    # Untyped JSON lines: every delta field, else a dug-out text field.
    deltas: list[str] = []
    chunks: list[str] = []
    for obj in events:
        d = obj.get("delta")
        if isinstance(d, str) and d:
            deltas.append(d)
            continue
        dug = _dig_text(obj)
        if dug:
            chunks.append(dug)
    if deltas:
        return "".join(deltas).strip()
    if chunks:
        return "".join(chunks).strip()
    # Plain JSON.
    try:
        data = json.loads(text)
    except ValueError:
        return text
    for key in cfg.get("answer_path") or []:
        if isinstance(data, dict):
            data = data.get(key, "")
    return data if isinstance(data, str) else _dig_text(data)


def _dig_text(obj: object) -> str:
    """Best-effort: pull a content/text/delta string out of a chunk object."""
    if isinstance(obj, str):
        return obj
    if isinstance(obj, dict):
        for k in ("content", "text", "delta", "message", "answer"):
            v = obj.get(k)
            if isinstance(v, str):
                return v
            if isinstance(v, dict):
                inner = _dig_text(v)
                if inner:
                    return inner
    return ""


def ask(question: str, *, chat_id: str | None = None,
        timeout: int = 120) -> tuple[str, str | None]:
    """Send one question to Mozi and return (answer, chat), the chat as
    chat_ref gives it. Reuses the saved conversation unless chat_id is passed
    (a chat as this returns it, or "" for a new one) or cleared via
    clear_chat_id / --new. Portal sandbar creates a chat first when none is
    saved. Refuses without the per-run consent flag or a discovered endpoint,
    never guesses a route, and never posts a chat from another app."""
    if not send_allowed():
        raise MoziConsent(
            "a Mozi send writes to your paid account through an undocumented "
            "route; set MOZI_SEND_OK=1 for this run to allow it")
    cfg = endpoint()
    if not cfg or not cfg.get("url"):
        raise MoziError(
            f"no Mozi endpoint learned yet ({ENDPOINT_FILE}). Send one message "
            f"in the window {CMD} login opens, or capture a Copy-as-cURL of a "
            f"real send and run: {CMD} discover --from-curl <file>")
    cid = chat_for_route(chat_id if chat_id is not None else load_chat_id(),
                         cfg)
    # No session, no request: the caller falls back to the browser before
    # anything is paced or posted.
    require_cookie_header()
    exp = session_expiry()
    if exp is not None and exp < 5:
        if os.environ.get("MOZI_TOKEN", "").strip():
            raise MoziNoSession(
                f"the captured __session looks expired ({exp}s left); Clerk "
                "tokens live ~60s, so grab a fresh cookie right before the ask "
                "(or use the browser transport, which never races the token)")
        raise MoziNoSession(
            f"the login cookie on file has expired ({session_expires_text()}); "
            f"{CMD} login saves a fresh one")
    created = False
    # One pace per question: the chat create and the post are one send.
    _pace("HTTP")
    if not cid and is_sandbar(cfg):
        print("acqai: creating portal chat…", file=sys.stderr, flush=True)
        cid = create_chat(question, timeout=min(60, timeout))
        created = True
    payload, used = build_body(question, cid)
    if created and used:
        print(f"acqai: new portal chat {used[:8]}…",
              file=sys.stderr, flush=True)
    elif cid:
        print(f"acqai: continuing Mozi chat {cid[:8]}…",
              file=sys.stderr, flush=True)
    else:
        print("acqai: new Mozi chat…", file=sys.stderr, flush=True)
    company = company_id_from_endpoint(cfg)
    referer = chat_page_url(chat_id=used or cid, company_id=company)
    print("acqai: posting to Mozi…", file=sys.stderr, flush=True)
    _status, raw = _request(cfg.get("method", "POST"), cfg["url"],
                            body=json.dumps(payload).encode("utf-8"),
                            timeout=timeout, referer=referer)
    print("acqai: Mozi answered.", file=sys.stderr, flush=True)
    chat = chat_ref(used, cfg["url"])
    save_chat_id(chat)
    return extract_answer(raw, cfg), chat
