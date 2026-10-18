#!/usr/bin/env python3
"""Command line client for the leaksear.ch OSINT / breach-data API.

Stdlib only (no third-party dependencies).  The typical workflow is:

    leaksearch.py --config ~/.config/leaksearch.ini search foo@example.com

which runs a search, polls it until the backend finishes, and prints the
redacted summary.  Adding --unlock spends credits and streams the full
records to stdout (or --output FILE) as JSONL.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import configparser
import csv
import hashlib
import json
import logging
import math
import os
import re
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import Counter, OrderedDict

__version__ = "1.0.0"

LOG = logging.getLogger("leaksearch")

DEFAULT_BASE_URL = "https://leaksear.ch"
DEFAULT_CONFIG_PATHS = (
    "~/.config/leaksearch/config.ini",
    "~/.config/leaksearch.ini",
    "~/.leaksearch.ini",
    "~/.leaksearch.json",
)

# Exit codes
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_AUTH = 3
EXIT_CREDITS = 4
EXIT_TIMEOUT = 5
EXIT_INTERRUPTED = 130

# Enumerations lifted from the OpenAPI document (api-1.json).
FIELDS = [
    "email", "domain", "username", "name", "password", "phone", "ipAddress",
    "address", "dateOfBirth", "country", "hashedPassword", "cryptoAddress", "vin",
]
MATCH_TYPES = ["EXACT", "WILDCARD"]
CATEGORIES = [
    "DIRECT_BREACH", "THIRD_PARTY_BREACH", "CREDENTIAL_COMBO", "INFO_STEALER_LOG",
    "RANSOMWARE_LEAK", "EXPOSED_DATABASE", "EXPOSED_CLOUD_STORAGE", "MALWARE_LOG",
    "PHISHING_DATA", "INSIDER_LEAK", "SOURCE_CODE_LEAK", "AGGREGATED_COLLECTION",
    "SCRAPED_DATA", "OTHER",
]
AUTHENTICITIES = ["VERIFIED", "LIKELY_AUTHENTIC", "UNVERIFIED", "DISPUTED"]
VISIBILITIES = ["ALL", "PUBLIC", "PRIVATE"]

MAX_PAGE_SIZE = 100          # GET /search/{id} pageSize cap
RESULTS_PER_CREDIT = 1000    # each credit unlocks up to 1000 results

OUTPUT_FORMATS = ["jsonl", "json", "csv", "tsv", "table"]
CREDIT_TX_TYPES = [
    "SUBSCRIPTION_RENEWAL", "PURCHASE", "SEARCH_UNLOCK", "FREE_SEARCH",
    "MONTHLY_FREE_CREDITS", "MONTHLY_CREDITS_USE", "MONTHLY_CREDITS_REFRESH",
    "ADMIN_ADJUSTMENT", "LEAK_SUBMISSION_REWARD",
]
MAX_SEEN_IDS = 250000        # cap on record ids remembered by watch state
# Columns used by the tabular formats when --fields is not given.
DEFAULT_RECORD_FIELDS = [
    "_query", "leakSourceId", "email", "username", "password", "hashedPassword",
    "phone", "name", "ipAddress", "country", "dateOfBirth", "address",
    "cryptoAddress", "vin", "dateBreached",
]
# Redacted by --redact-passwords, keeping equal values equal so that reuse
# analysis still works on a shareable file.
SECRET_FIELDS = ("password", "hashedPassword", "salt", "pepper")


# --------------------------------------------------------------------------
# Errors
# --------------------------------------------------------------------------

class LeakSearchError(Exception):
    """Base error, carries a process exit code."""

    exit_code = EXIT_ERROR


class ConfigError(LeakSearchError):
    exit_code = EXIT_USAGE


class APIError(LeakSearchError):
    def __init__(self, status, code=None, message=None, details=None, body=None):
        self.status = status
        self.code = code
        self.details = details
        self.body = body
        text = message or body or "HTTP %s" % status
        if code:
            text = "%s (%s)" % (text, code)
        super().__init__("HTTP %s: %s" % (status, text))

    @property
    def exit_code(self):
        if self.status in (401, 403):
            return EXIT_AUTH
        if self.status == 402:
            return EXIT_CREDITS
        return EXIT_ERROR


class SearchFailed(LeakSearchError):
    pass


class PollTimeout(LeakSearchError):
    exit_code = EXIT_TIMEOUT


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

class Config:
    """Settings from the --config file, overridable by env vars and flags."""

    def __init__(self, values=None, path=None):
        self.path = path
        v = dict(values or {})
        self.api_key = _str(v.get("api_key") or v.get("apikey") or v.get("token"))
        self.base_url = (_str(v.get("base_url") or v.get("url")) or DEFAULT_BASE_URL).rstrip("/")
        self.auth_header = _str(v.get("auth_header")) or "Authorization"
        # Set auth_scheme to an empty string to send the bare key.
        scheme = v.get("auth_scheme")
        self.auth_scheme = "Bearer" if scheme is None else _str(scheme)
        self.user_agent = _str(v.get("user_agent")) or "leaksearch-cli/%s" % __version__
        self.request_timeout = _float(v.get("request_timeout"), 60.0)
        self.poll_interval = _float(v.get("poll_interval"), 3.0)
        self.poll_timeout = _float(v.get("poll_timeout"), 900.0)
        self.page_size = _int(v.get("page_size"), MAX_PAGE_SIZE)
        self.max_retries = _int(v.get("max_retries"), 4)
        ledger = v.get("ledger")
        if ledger is None:
            self.ledger = os.path.join(state_dir(), "searches.jsonl")
        elif str(ledger).strip().lower() in ("off", "none", "false", ""):
            self.ledger = None
        else:
            self.ledger = os.path.expanduser(str(ledger).strip())
        self.max_credits_per_run = (
            None if v.get("max_credits_per_run") is None
            else _int(v.get("max_credits_per_run"), None))
        self.watch_state_dir = os.path.expanduser(
            _str(v.get("watch_state_dir")) or os.path.join(state_dir(), "watch"))
        self.verify_tls = _bool(v.get("verify_tls"), True)


def _str(value):
    return None if value is None else str(value).strip()


def _int(value, default):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError, AttributeError):
        return default


def _float(value, default):
    try:
        return float(str(value).strip())
    except (TypeError, ValueError, AttributeError):
        return default


def _bool(value, default):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def load_config(path):
    """Load a config file.

    The file may be JSON, or INI with the settings under a [leaksearch]
    section (a bare `key = value` file works too).  When --config is not
    given, the well-known paths are tried, then the environment.
    """
    explicit = path is not None
    candidates = [path] if explicit else list(DEFAULT_CONFIG_PATHS)
    for candidate in candidates:
        expanded = os.path.expanduser(candidate)
        if not os.path.exists(expanded):
            continue
        LOG.debug("reading config from %s", expanded)
        values = _parse_config_file(expanded)
        _warn_on_loose_permissions(expanded)
        return Config(values, path=expanded)
    if explicit:
        raise ConfigError("config file not found: %s" % path)
    LOG.debug("no config file found, using defaults and environment")
    return Config()


def _parse_config_file(path):
    with open(path, "r", encoding="utf-8") as handle:
        raw = handle.read()
    stripped = raw.lstrip()
    if stripped.startswith("{"):
        try:
            data = json.loads(raw)
        except ValueError as exc:
            raise ConfigError("invalid JSON in %s: %s" % (path, exc))
        if not isinstance(data, dict):
            raise ConfigError("config in %s must be a JSON object" % path)
        # Allow either a flat object or one nested under "leaksearch".
        section = data.get("leaksearch")
        return {str(k): v for k, v in (section if isinstance(section, dict) else data).items()}

    parser = configparser.ConfigParser(inline_comment_prefixes=(";", "#"))
    has_section_header = re.search(r"^\s*\[[^]]+\]", raw, re.M) is not None
    try:
        parser.read_string(raw if has_section_header else "[leaksearch]\n" + raw)
    except configparser.Error as exc:
        raise ConfigError("invalid config in %s: %s" % (path, exc))
    values = {}
    for name in ("leaksearch", "DEFAULT", "default", "api"):
        if parser.has_section(name) or name == "DEFAULT":
            values.update(dict(parser.items(name)))
    return values


def _warn_on_loose_permissions(path):
    try:
        mode = os.stat(path).st_mode & 0o777
    except OSError:
        return
    if mode & 0o077:
        LOG.warning("config file %s is readable by other users (mode %o); "
                    "consider: chmod 600 %s", path, mode, path)


def resolve_api_key(config, cli_key):
    key = cli_key or os.environ.get("LEAKSEARCH_API_KEY") or config.api_key
    if not key:
        raise ConfigError(
            "no API key: pass --api-key, set LEAKSEARCH_API_KEY, or put "
            "'api_key = ...' in the --config file")
    return key


# --------------------------------------------------------------------------
# HTTP client
# --------------------------------------------------------------------------

class Client:
    def __init__(self, config, api_key):
        self.config = config
        self.api_key = api_key
        if config.verify_tls:
            context = ssl.create_default_context()
        else:
            context = ssl._create_unverified_context()
            LOG.warning("TLS certificate verification is disabled")
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context))

    # -- low level ---------------------------------------------------------
    def request(self, method, path, params=None, body=None, headers=None):
        url = self.config.base_url + path
        if params:
            query = {k: v for k, v in params.items() if v is not None}
            if query:
                url += "?" + urllib.parse.urlencode(query)

        payload = None
        request_headers = {
            "Accept": "application/json",
            "User-Agent": self.config.user_agent,
        }
        scheme = self.config.auth_scheme
        request_headers[self.config.auth_header] = (
            "%s %s" % (scheme, self.api_key) if scheme else self.api_key)
        if body is not None:
            payload = json.dumps(body).encode("utf-8")
            request_headers["Content-Type"] = "application/json"
        if headers:
            request_headers.update(headers)

        attempt = 0
        while True:
            attempt += 1
            self._log_request(method, url, request_headers, body)
            request = urllib.request.Request(
                url, data=payload, headers=request_headers, method=method)
            started = time.time()
            try:
                with self._opener.open(request, timeout=self.config.request_timeout) as response:
                    raw = response.read().decode("utf-8", "replace")
                    status = response.getcode()
                    self._log_response(status, raw, time.time() - started)
                    return _decode_json(raw)
            except urllib.error.HTTPError as exc:
                raw = exc.read().decode("utf-8", "replace")
                self._log_response(exc.code, raw, time.time() - started)
                retry_after = _retry_delay(exc, attempt)
                if self._should_retry(exc.code, attempt) and retry_after is not None:
                    LOG.warning("HTTP %s from %s, retrying in %.1fs (attempt %d/%d)",
                                exc.code, path, retry_after, attempt, self.config.max_retries)
                    time.sleep(retry_after)
                    continue
                raise _api_error(exc.code, raw)
            except urllib.error.URLError as exc:
                if attempt <= self.config.max_retries:
                    delay = min(30.0, 2.0 ** attempt)
                    LOG.warning("network error (%s), retrying in %.1fs (attempt %d/%d)",
                                exc.reason, delay, attempt, self.config.max_retries)
                    time.sleep(delay)
                    continue
                raise LeakSearchError("network error contacting %s: %s" % (url, exc.reason))

    def _should_retry(self, status, attempt):
        return attempt <= self.config.max_retries and (status == 429 or 500 <= status < 600)

    def _log_request(self, method, url, headers, body):
        if not LOG.isEnabledFor(logging.DEBUG):
            return
        LOG.debug(">>> %s %s", method, url)
        for name, value in sorted(headers.items()):
            LOG.debug(">>> %s: %s", name, _redact(name, value))
        if body is not None:
            LOG.debug(">>> body: %s", json.dumps(body))

    def _log_response(self, status, raw, elapsed):
        if not LOG.isEnabledFor(logging.DEBUG):
            return
        LOG.debug("<<< HTTP %s (%.2fs, %d bytes)", status, elapsed, len(raw))
        LOG.debug("<<< body: %s", raw if len(raw) <= 4000 else raw[:4000] + "...[truncated]")

    # -- endpoints ---------------------------------------------------------
    def search(self, body, cancel_token=None):
        headers = {"x-search-cancel-token": cancel_token} if cancel_token else None
        return self.request("POST", "/api/v1/search", body=body, headers=headers)

    def get_search(self, search_id, page=None, page_size=None, sources=None):
        params = {"page": page, "pageSize": page_size, "sources": sources}
        return self.request("GET", "/api/v1/search/%s" % urllib.parse.quote(str(search_id)),
                            params=params)

    def unlock(self, search_id, credits=None):
        body = {} if credits is None else {"credits": int(credits)}
        return self.request("POST", "/api/v1/search/%s/unlock"
                            % urllib.parse.quote(str(search_id)), body=body)

    def cancel(self, token):
        return self.request("POST", "/api/v1/search/cancel", body={"token": token})

    def history(self, page=1, page_size=20):
        return self.request("GET", "/api/v1/search/history",
                            params={"page": page, "pageSize": page_size})

    def credits(self):
        return self.request("GET", "/api/v1/user/credits")

    def credits_history(self, page=1, page_size=25):
        return self.request("GET", "/api/v1/user/credits/history",
                            params={"page": page, "pageSize": page_size})

    def profile(self):
        return self.request("GET", "/api/v1/user/profile")

    def leak_sources(self, **params):
        return self.request("GET", "/api/v1/leak-sources", params=params)

    def leak_source(self, source_id):
        return self.request("GET", "/api/v1/leak-sources/%s"
                            % urllib.parse.quote(str(source_id)))

    def leak_source_stats(self):
        return self.request("GET", "/api/v1/leak-sources/stats")

    def health(self):
        return self.request("GET", "/api/v1/health")


def _decode_json(raw):
    if not raw.strip():
        return {}
    try:
        return json.loads(raw)
    except ValueError:
        raise LeakSearchError("server returned a non-JSON response: %s" % raw[:200])


def _api_error(status, raw):
    code = message = details = None
    try:
        data = json.loads(raw)
    except ValueError:
        data = None
    if isinstance(data, dict):
        code = data.get("code")
        message = data.get("error") or data.get("message")
        details = data.get("details")
    return APIError(status, code=code, message=message, details=details,
                    body=raw[:500] or None)


def _retry_delay(exc, attempt):
    header = exc.headers.get("Retry-After") if exc.headers else None
    if header:
        try:
            return max(0.0, float(header.strip()))
        except ValueError:
            pass
    return min(30.0, 2.0 ** attempt)


def _redact(name, value):
    if name.lower() in ("authorization", "x-api-key", "api-key", "x-auth-token"):
        text = str(value)
        tail = text[-4:] if len(text) > 12 else ""
        return "<redacted%s>" % (":..." + tail if tail else "")
    return value


# --------------------------------------------------------------------------
# Output handling
# --------------------------------------------------------------------------

class Output:
    """Writes to --output FILENAME, or stdout by default.

    Files are created 0600: unlocked records routinely contain plaintext
    passwords, so they must not land in a world-readable file.
    """

    def __init__(self, filename=None, append=False):
        self.filename = filename
        self._append = append
        self._handle = None
        self._owned = False

    def __enter__(self):
        if self.filename and self.filename != "-":
            self._handle = _open_private(self.filename, self._append)
            self._owned = True
        else:
            self._handle = sys.stdout
        return self

    def __exit__(self, *exc_info):
        try:
            self._handle.flush()
        except (ValueError, OSError):
            pass
        if self._owned:
            self._handle.close()
        return False

    @property
    def handle(self):
        return self._handle

    def write_line(self, text):
        self._handle.write(text + "\n")

    def write_json(self, obj):
        self.write_line(json.dumps(obj, indent=2, sort_keys=False, default=str))

    def write_jsonl(self, obj):
        self.write_line(json.dumps(obj, separators=(",", ":"), default=str))

    def flush(self):
        try:
            self._handle.flush()
        except (ValueError, OSError):
            pass


def _open_private(filename, append=False):
    """Open a file for writing, restricted to the current user."""
    existed = os.path.exists(filename)
    flags = os.O_WRONLY | os.O_CREAT | (os.O_APPEND if append else os.O_TRUNC)
    handle = os.fdopen(os.open(filename, flags, 0o600), "a" if append else "w",
                       encoding="utf-8")
    if not existed or not append:
        try:
            os.chmod(filename, 0o600)
        except OSError as exc:
            LOG.debug("could not chmod %s: %s", filename, exc)
    elif existed:
        try:
            if os.stat(filename).st_mode & 0o077:
                LOG.warning("appending to %s, which is readable by other users", filename)
        except OSError:
            pass
    return handle


# --------------------------------------------------------------------------
# Record formatting (--format / --fields / --redact-passwords)
# --------------------------------------------------------------------------

def redact_record(record):
    """Replace secrets with a stable digest so reuse analysis still works."""
    clean = dict(record)
    for field in SECRET_FIELDS:
        value = clean.get(field)
        if value:
            digest = hashlib.sha1(str(value).encode("utf-8")).hexdigest()[:10]
            clean[field] = "redacted:%s" % digest
    return clean


def flatten_value(value):
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, separators=(",", ":"), default=str)
    return value


class RecordWriter:
    """Streams records to an Output in the requested format."""

    def __init__(self, out, fmt="jsonl", fields=None, redact=False, dedupe=False):
        if fmt not in OUTPUT_FORMATS:
            raise ConfigError("unknown --format %r: choose from %s"
                              % (fmt, ", ".join(OUTPUT_FORMATS)))
        self.out = out
        self.fmt = fmt
        self.fields = fields
        self.redact = redact
        self.dedupe = dedupe
        self.count = 0
        self.skipped = 0
        self._seen = set()
        self._csv = None
        self._rows = []
        self._started = False

    def write(self, record):
        """Write one record. Returns False when --dedupe skipped it."""
        if self.dedupe:
            key = record.get("_id") or json.dumps(record, sort_keys=True, default=str)
            if key in self._seen:
                self.skipped += 1
                return False
            self._seen.add(key)
        if self.redact:
            record = redact_record(record)
        self.count += 1

        if self.fmt == "jsonl":
            self.out.write_jsonl(record)
        elif self.fmt == "json":
            prefix = "[" if not self._started else ","
            self.out.write_line(prefix + json.dumps(record, default=str))
            self._started = True
        elif self.fmt in ("csv", "tsv"):
            self._write_row(record)
        else:  # table, buffered so columns can be sized
            self._rows.append(record)
        return True

    def _columns(self):
        return self.fields or DEFAULT_RECORD_FIELDS

    def _write_row(self, record):
        if self._csv is None:
            columns = self._columns()
            self._csv = csv.writer(self.out.handle,
                                   delimiter="\t" if self.fmt == "tsv" else ",",
                                   lineterminator="\n")
            self._csv.writerow(columns)
        self._csv.writerow([flatten_value(record.get(c)) for c in self._columns()])

    def close(self):
        if self.fmt == "json":
            self.out.write_line("[]" if not self._started else "]")
        elif self.fmt == "table":
            self._write_table()
        self.out.flush()
        if self.skipped:
            note("skipped %d duplicate record(s)", self.skipped)
        return self.count

    def _write_table(self):
        if not self._rows:
            note("no records")
            return
        columns = self.fields or [c for c in DEFAULT_RECORD_FIELDS
                                  if any(r.get(c) not in (None, "") for r in self._rows)]
        widths = [len(c) for c in columns]
        cells = []
        for record in self._rows:
            row = [str(flatten_value(record.get(c))) for c in columns]
            widths = [max(w, len(v)) for w, v in zip(widths, row)]
            cells.append(row)
        widths = [min(w, 48) for w in widths]
        fmt = "  ".join("%%-%ds" % w for w in widths)
        self.out.write_line(fmt % tuple(columns))
        self.out.write_line(fmt % tuple("-" * w for w in widths))
        for row in cells:
            self.out.write_line(fmt % tuple(v[:48] for v in row))


# --------------------------------------------------------------------------
# Credit budget
# --------------------------------------------------------------------------

def spendable_credits(credits):
    """Total credits an unlock can draw on: purchased plus monthly allowance.

    GET /user/credits reports them separately; the website shows the sum.
    """
    return int(credits.get("credits") or 0) + int(credits.get("monthlyCredits") or 0)


class Budget:
    """Caps what one invocation may spend, and pre-checks the live balance.

    Turning a 402 into a refusal *before* anything is spent matters when a
    batch of 500 terms is running unattended.
    """

    def __init__(self, client, limit=None):
        self.client = client
        self.limit = None if limit is None else max(0, int(limit))
        self.spent = 0
        self._balance = None

    def balance(self, refresh=False):
        if self._balance is None or refresh:
            try:
                self._balance = spendable_credits(self.client.credits())
            except LeakSearchError as exc:
                LOG.debug("balance check failed: %s", exc)
                return None
        return self._balance

    @property
    def remaining(self):
        return None if self.limit is None else max(0, self.limit - self.spent)

    def allow(self, wanted, label=""):
        """Return how many credits may actually be spent (0 = nothing)."""
        wanted = max(0, int(wanted))
        if wanted == 0:
            return 0
        allowed = wanted
        if self.remaining is not None and allowed > self.remaining:
            allowed = self.remaining
            note("budget: capping %s to %d credit(s) (%d of %d used)%s",
                 label or "unlock", allowed, self.spent, self.limit,
                 "" if allowed else " - budget exhausted")
        balance = self.balance()
        if balance is not None and allowed > balance - self.spent:
            allowed = max(0, balance - self.spent)
            note("balance: only %d credit(s) available, capping %s",
                 max(0, balance - self.spent), label or "unlock")
        return allowed

    def charge(self, credits):
        self.spent += max(0, int(credits or 0))


# --------------------------------------------------------------------------
# Local ledger of searches
# --------------------------------------------------------------------------

def state_dir():
    base = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
    return os.path.join(base, "leaksearch")


class Ledger:
    """Append-only local record of every search, so nothing is lost or paid
    for twice. Later entries for the same searchId update earlier ones."""

    def __init__(self, path, enabled=True):
        self.path = path
        self.enabled = enabled and bool(path)

    def record(self, search_id, **fields):
        if not self.enabled or not search_id:
            return
        entry = {"searchId": search_id,
                 "updatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        entry.update({k: v for k, v in fields.items() if v is not None})
        try:
            directory = os.path.dirname(self.path)
            if directory and not os.path.isdir(directory):
                os.makedirs(directory, mode=0o700, exist_ok=True)
            with _open_private(self.path, append=True) as handle:
                handle.write(json.dumps(entry, default=str) + "\n")
        except OSError as exc:
            LOG.warning("could not write ledger %s: %s", self.path, exc)

    def entries(self):
        """Merged newest-last view of the ledger."""
        merged = OrderedDict()
        if not self.path or not os.path.exists(self.path):
            return []
        try:
            with open(self.path, "r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except ValueError:
                        continue
                    search_id = entry.get("searchId")
                    if not search_id:
                        continue
                    if search_id in merged:
                        merged[search_id].update(entry)
                    else:
                        merged[search_id] = entry
        except OSError as exc:
            LOG.warning("could not read ledger %s: %s", self.path, exc)
        return list(merged.values())

    def find(self, search_id):
        for entry in self.entries():
            if entry.get("searchId") == search_id:
                return entry
        return None


class Session:
    """Per-invocation state shared by the commands (attached to args)."""

    def __init__(self, client, config, ledger, budget):
        self.client = client
        self.config = config
        self.ledger = ledger
        self.budget = budget


def note(message, *args):
    """Progress/summary chatter, always on stderr so stdout stays pure data."""
    sys.stderr.write((message % args if args else message) + "\n")
    sys.stderr.flush()


# --------------------------------------------------------------------------
# Search helpers
# --------------------------------------------------------------------------

_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_PHONE = re.compile(r"^\+?[\d\s().-]{7,}$")
_DOMAIN = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+$")


def guess_field(query):
    """Best-effort field detection for a bare search string."""
    text = query.strip()
    probe = text.replace("*", "").replace("?", "")
    if "@" in probe:
        return "email"
    if _IPV4.match(probe) or (":" in probe and re.match(r"^[0-9A-Fa-f:]+$", probe)):
        return "ipAddress"
    if _DOMAIN.match(probe):
        return "domain"
    if _PHONE.match(probe) and sum(c.isdigit() for c in probe) >= 7:
        return "phone"
    return "username"


def parse_filter(spec):
    """Parse --filter FIELD:QUERY, FIELD:TYPE:QUERY (":" or "=" as separator)."""
    match = re.match(r"^\s*([A-Za-z]+)\s*[:=](.*)$", spec, re.S)
    if not match:
        raise ConfigError("invalid --filter %r: expected FIELD:QUERY or FIELD:TYPE:QUERY" % spec)
    field, rest = match.group(1), match.group(2)
    if field not in FIELDS:
        raise ConfigError("invalid --filter field %r: choose from %s"
                          % (field, ", ".join(FIELDS)))
    match_type = None
    type_match = re.match(r"^(EXACT|WILDCARD)[:=](.*)$", rest, re.S | re.I)
    if type_match:
        match_type = type_match.group(1).upper()
        rest = type_match.group(2)
    if not rest:
        raise ConfigError("invalid --filter %r: empty query" % spec)
    return make_filter(field, rest, match_type)


def make_filter(field, query, match_type=None):
    if match_type is None:
        match_type = "WILDCARD" if ("*" in query or "?" in query) else "EXACT"
    return {"field": field, "query": query, "type": match_type}


def build_search_body(args, base_filters=None):
    filters = list(base_filters or [])
    if args.query and not base_filters:
        field = args.field or guess_field(args.query)
        if not args.field:
            note("no --field given, searching field '%s' (override with --field)", field)
        filters.append(make_filter(field, args.query, args.type))
    for spec in args.filter or []:
        filters.append(parse_filter(spec))
    if not filters:
        raise ConfigError("nothing to search for: give a QUERY or at least one --filter")
    if len(filters) > 5:
        raise ConfigError("the API accepts at most 5 filters (got %d)" % len(filters))

    body = {"filters": filters, "operator": args.operator}
    if args.operators:
        operators = [op.strip().upper() for op in args.operators.split(",") if op.strip()]
        bad = [op for op in operators if op not in ("AND", "OR")]
        if bad:
            raise ConfigError("invalid --operators value(s): %s" % ", ".join(bad))
        body["operators"] = operators
    if args.source:
        body["leakSourceIds"] = list(args.source)

    source_filters = {}
    for key, value in (
        ("breachedSince", args.breached_since),
        ("breachedUntil", args.breached_until),
        ("indexedSince", args.indexed_since),
        ("indexedUntil", args.indexed_until),
        ("minimumRecords", args.source_min_records),
        ("maximumRecords", args.source_max_records),
        ("categoryMatch", args.category_match),
    ):
        if value is not None:
            source_filters[key] = value
    if args.visibility and args.visibility != "ALL":
        source_filters["visibility"] = args.visibility
    if args.required_field:
        source_filters["requiredFields"] = list(args.required_field)
    if args.category:
        source_filters["includeCategories"] = list(args.category)
    if args.exclude_category:
        source_filters["excludeCategories"] = list(args.exclude_category)
    if args.authenticity:
        source_filters["authenticityStatuses"] = list(args.authenticity)
    if args.exclude_source:
        source_filters["excludeLeakSourceIds"] = list(args.exclude_source)
    if source_filters:
        body["leakSourceFilters"] = source_filters
    return body


def poll_until_ready(client, search_id, interval, timeout, phase_label="search",
                     page_size=1):
    """Poll GET /search/{id} until the backend stops reporting PENDING."""
    deadline = time.time() + timeout if timeout else None
    delay = max(0.5, interval)
    waited = 0.0
    while True:
        result = client.get_search(search_id, page=1, page_size=page_size)
        status = result.get("status")
        if status == "FAILED":
            raise SearchFailed("%s failed: %s"
                               % (phase_label, result.get("error") or "unknown error"))
        if status != "PENDING":
            if waited:
                note("%s ready after %.0fs", phase_label, waited)
            return result
        if deadline and time.time() >= deadline:
            raise PollTimeout(
                "%s still PENDING after %.0fs (search id %s); re-check later with: "
                "status %s" % (phase_label, timeout, search_id, search_id))
        note("%s pending (phase %s%s), waiting %.1fs...",
             phase_label, result.get("phase", "?"),
             ", complex" if result.get("complex") else "", delay)
        time.sleep(delay)
        waited += delay
        delay = min(delay * 1.5, 30.0)


def summarize(result, credits_used=None):
    sources = result.get("leakSources") or []
    lines = [
        "search id     : %s" % result.get("searchId"),
        "status        : %s%s" % (result.get("status", "COMPLETED"),
                                  " (unlocked)" if result.get("unlocked") else ""),
        "total results : %s" % result.get("totalResults", 0),
        "search time   : %sms" % result.get("searchTimeMs", 0),
        "leak sources  : %d%s" % (len(sources),
                                  " (capped)" if result.get("leakSourcesCapped") else ""),
    ]
    if credits_used is not None:
        lines.append("credits used  : %s" % credits_used)
    for source in sorted(sources, key=lambda s: s.get("count", 0), reverse=True)[:25]:
        lines.append("  %8s  %s%s%s" % (
            source.get("count", 0), source.get("name", "?"),
            "  [private]" if source.get("private") else "",
            "  breached %s" % source["dateBreached"] if source.get("dateBreached") else ""))
    if len(sources) > 25:
        lines.append("  ... and %d more sources" % (len(sources) - 25))
    note("\n".join(lines))


def download_records(client, search_id, writer, page_size, sources=None,
                     max_records=None, annotate=None, label=""):
    """Stream every page of an unlocked search through `writer`."""
    page_size = max(1, min(int(page_size), MAX_PAGE_SIZE))
    written = 0
    page = 1
    total_pages = None
    prefix = ("%s: " % label) if label else ""
    while True:
        result = client.get_search(search_id, page=page, page_size=page_size,
                                   sources=sources)
        if not result.get("unlocked"):
            raise LeakSearchError(
                "search %s is not unlocked; run `unlock %s` first" % (search_id, search_id))
        if total_pages is None:
            total_pages = result.get("totalPages")
            if not total_pages:
                total = result.get("totalResults") or 0
                total_pages = max(1, math.ceil(total / page_size)) if total else 1
        records = result.get("records") or []
        for record in records:
            if annotate:
                record = dict(record, **annotate)
            writer.write(record)
            written += 1
            if max_records and written >= max_records:
                writer.out.flush()
                note("%swrote %d record(s) (--max-records reached)", prefix, written)
                return written
        writer.out.flush()
        note("%spage %d/%s: %d record(s), %d total",
             prefix, page, total_pages or "?", len(records), written)
        if not records or page >= (total_pages or page):
            break
        page += 1
    note("%swrote %d record(s)", prefix, written)
    return written


def make_writer(args, out):
    fields = None
    if getattr(args, "fields", None):
        fields = [f.strip() for f in args.fields.split(",") if f.strip()]
    return RecordWriter(out,
                        fmt=getattr(args, "format", None) or "jsonl",
                        fields=fields,
                        redact=getattr(args, "redact_passwords", False),
                        dedupe=getattr(args, "dedupe", False))


def credits_needed(total_results):
    return max(1, math.ceil((total_results or 0) / RESULTS_PER_CREDIT))


def confirm(prompt, assume_yes):
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        raise LeakSearchError("%s (refusing in a non-interactive session; pass --yes)" % prompt)
    # Ask on stderr: stdout may be the record stream (or redirected to a file),
    # where the question would be swallowed and the run would appear to hang.
    sys.stderr.write("%s [y/N] " % prompt)
    sys.stderr.flush()
    answer = sys.stdin.readline().strip().lower()
    return answer in ("y", "yes")


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------

def cmd_search(client, args, out):
    terms = load_terms(args)
    if terms is not None:
        return run_batch(client, args, out, terms)

    writer = make_writer(args, out)
    try:
        outcome = run_one_search(client, args, writer, build_search_body(args))
    finally:
        if writer.count:
            writer.close()
    if outcome.get("error"):
        return EXIT_ERROR
    if not outcome.get("records") and outcome.get("result") is not None:
        out.write_json(outcome["result"])
    return EXIT_OK


def run_one_search(client, args, writer, body, term=None):
    """Run one search end to end. Returns a summary dict (never raises for
    an ordinary API failure when running a batch)."""
    session = args.session
    label = term or ""
    prefix = ("%s: " % label) if label else ""
    outcome = {"query": term, "searchId": None, "totalResults": 0,
               "credits": 0, "records": 0, "unlocked": False, "result": None}

    LOG.debug("search body: %s", json.dumps(body))
    cancel_token = str(uuid.uuid4())
    try:
        result = client.search(body, cancel_token=cancel_token)
    except KeyboardInterrupt:
        _try_cancel(client, cancel_token)
        raise

    search_id = result.get("searchId")
    if not search_id:
        raise LeakSearchError("server did not return a searchId: %s"
                              % json.dumps(result)[:300])
    outcome["searchId"] = search_id
    note("%ssearch id %s", prefix, search_id)
    session.ledger.record(search_id, query=term, filters=body.get("filters"),
                          operator=body.get("operator"),
                          createdAt=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                          baseUrl=client.config.base_url, status="PENDING")

    if result.get("status") == "PENDING":
        try:
            result = poll_until_ready(client, search_id, args.poll_interval,
                                      args.poll_timeout, "%ssearch" % prefix)
        except KeyboardInterrupt:
            _try_cancel(client, cancel_token)
            raise
    total = result.get("totalResults") or 0
    outcome.update(totalResults=total, result=result,
                   unlocked=bool(result.get("unlocked")))
    session.ledger.record(search_id, status=result.get("status", "COMPLETED"),
                          totalResults=total, unlocked=bool(result.get("unlocked")),
                          leakSources=len(result.get("leakSources") or []))
    if not term:
        summarize(result)
    else:
        note("%s%d result(s) across %d source(s)", prefix, total,
             len(result.get("leakSources") or []))

    if not args.unlock or total == 0:
        if args.unlock and total == 0:
            note("%sno results to unlock", prefix)
        return outcome

    if result.get("unlocked"):
        note("%salready unlocked, downloading without spending credits", prefix)
        outcome["records"] = download_records(
            client, search_id, writer, args.page_size, sources=args.sources,
            max_records=args.max_records, annotate=_annotation(args, term), label=label)
        session.ledger.record(search_id, records=outcome["records"],
                              output=args.output or "-")
        return outcome

    spent, written = unlock_and_download(client, args, writer, search_id, total, term=term)
    outcome.update(credits=spent, records=written, unlocked=bool(spent))
    return outcome


def _annotation(args, term):
    if term is None or getattr(args, "no_annotate", False):
        return None
    return {"_query": term}


def cmd_unlock(client, args, out):
    writer = make_writer(args, out)
    try:
        result = client.get_search(args.search_id, page=1, page_size=1)
        if result.get("status") == "PENDING":
            result = poll_until_ready(client, args.search_id, args.poll_interval,
                                      args.poll_timeout, "search")
        if result.get("unlocked"):
            note("search %s is already unlocked, downloading", args.search_id)
            download_records(client, args.search_id, writer, args.page_size,
                             sources=args.sources, max_records=args.max_records)
            return EXIT_OK
        summarize(result)
        unlock_and_download(client, args, writer, args.search_id,
                            result.get("totalResults") or 0)
    finally:
        writer.close()
    return EXIT_OK


def unlock_and_download(client, args, writer, search_id, total, term=None):
    """Spend credits (respecting --dry-run and the budget) and download.

    Returns (credits_spent, records_written).
    """
    session = args.session
    prefix = ("%s: " % term) if term else ""
    wanted = credits_needed(total) if args.credits is None else max(1, int(args.credits))
    if args.max_credits is not None and wanted > args.max_credits:
        wanted = int(args.max_credits)
        note("%scapped to %d credit(s) by --max-credits", prefix, wanted)

    if args.dry_run:
        note("%sdry run: %d result(s) would cost %d credit(s) (%d per credit); "
             "nothing spent", prefix, total, wanted, RESULTS_PER_CREDIT)
        session.ledger.record(search_id, dryRun=True, wouldCost=wanted)
        return 0, 0

    spend = session.budget.allow(wanted, label="search %s" % search_id)
    if spend <= 0:
        note("%sskipping unlock: no credits available within the budget", prefix)
        return 0, 0
    reachable = min(total, spend * RESULTS_PER_CREDIT)
    note("%sunlocking %d of %d result(s) for %d credit(s)", prefix, reachable, total, spend)
    if not confirm("Spend %d credit(s) to unlock search %s?" % (spend, search_id), args.yes):
        note("aborted, no credits spent")
        return 0, 0

    result = client.unlock(search_id, credits=spend)
    if result.get("status") == "PENDING":
        result = poll_until_ready(client, search_id, args.poll_interval,
                                  args.poll_timeout, "%sunlock" % prefix,
                                  page_size=min(args.page_size, MAX_PAGE_SIZE))
    used = result.get("creditsUsed")
    session.budget.charge(spend if used is None else used)
    if not term:
        summarize(result, credits_used=used)
    session.ledger.record(search_id, unlocked=True, creditsUsed=used or spend,
                          totalResults=result.get("totalResults"))

    written = download_records(client, search_id, writer, args.page_size,
                               sources=args.sources, max_records=args.max_records,
                               annotate=_annotation(args, term), label=term or "")
    session.ledger.record(search_id, records=written, output=args.output or "-")
    return (used if used is not None else spend), written


def cmd_download(client, args, out):
    writer = make_writer(args, out)
    try:
        _download_cmd_body(client, args, writer, args.search_id)
    finally:
        writer.close()
    return EXIT_OK


def _download_cmd_body(client, args, writer, search_id):
    result = client.get_search(search_id, page=1, page_size=1)
    if result.get("status") == "PENDING":
        result = poll_until_ready(client, search_id, args.poll_interval,
                                  args.poll_timeout, "search")
    if not result.get("unlocked"):
        raise LeakSearchError(
            "search %s is not unlocked (no records available); unlock it with: "
            "unlock %s" % (search_id, search_id))
    written = download_records(client, search_id, writer, args.page_size,
                               sources=args.sources, max_records=args.max_records)
    args.session.ledger.record(search_id, records=written, unlocked=True,
                               output=args.output or "-")
    return written


# --------------------------------------------------------------------------
# Batch mode (--input)
# --------------------------------------------------------------------------

def load_terms(args):
    """Read search terms from --input (a file, or "-" for stdin).

    Returns None when not in batch mode.  Blank lines and #-comments are
    skipped; a line may override the field with "field:term".
    """
    source = getattr(args, "input", None)
    if not source:
        return None
    if source == "-":
        lines = sys.stdin.read().splitlines()
    else:
        try:
            with open(os.path.expanduser(source), "r", encoding="utf-8") as handle:
                lines = handle.read().splitlines()
        except OSError as exc:
            raise ConfigError("cannot read --input %s: %s" % (source, exc))
    terms = []
    seen = set()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line in seen:
            continue
        seen.add(line)
        terms.append(line)
    if not terms:
        raise ConfigError("no search terms found in %s" % source)
    return terms


def term_to_body(args, term):
    """Build a request body for one batch line ("field:value" or a bare value)."""
    match = re.match(r"^([A-Za-z]+)[:=](.+)$", term)
    if match and match.group(1) in FIELDS:
        filters = [make_filter(match.group(1), match.group(2), args.type)]
    else:
        field = args.field or guess_field(term)
        filters = [make_filter(field, term, args.type)]
    body = build_search_body(args, base_filters=filters)
    return body


def run_batch(client, args, out, terms):
    note("batch: %d term(s) from %s, %d at a time%s", len(terms), args.input,
         args.concurrency, " (dry run)" if args.dry_run else "")
    if args.unlock and not args.yes and not args.dry_run:
        raise ConfigError("batch unlocking spends credits per term: pass --yes "
                          "(ideally with --budget N) or --dry-run")
    writer = make_writer(args, out)
    lock = threading.Lock()
    results = []
    stop = threading.Event()

    class _SerializedWriter:
        """Wraps the shared writer so worker threads cannot interleave rows."""

        def __init__(self, inner):
            self.inner = inner
            self.out = inner.out

        def write(self, record):
            with lock:
                return self.inner.write(record)

    safe_writer = _SerializedWriter(writer)

    def work(term):
        if stop.is_set():
            return {"query": term, "skipped": True}
        try:
            return run_one_search(client, args, safe_writer, term_to_body(args, term), term)
        except KeyboardInterrupt:
            stop.set()
            raise
        except LeakSearchError as exc:
            note("%s: error: %s", term, exc)
            return {"query": term, "error": str(exc), "totalResults": 0,
                    "credits": 0, "records": 0}

    try:
        if args.concurrency <= 1:
            for term in terms:
                results.append(work(term))
        else:
            with concurrent.futures.ThreadPoolExecutor(
                    max_workers=args.concurrency) as pool:
                for outcome in pool.map(work, terms):
                    results.append(outcome)
    except KeyboardInterrupt:
        stop.set()
        note("interrupted, %d of %d term(s) finished", len(results), len(terms))
    finally:
        writer.close()

    _batch_summary(args, results, writer)
    return EXIT_ERROR if any(r.get("error") for r in results) else EXIT_OK


def _batch_summary(args, results, writer):
    hits = [r for r in results if (r.get("totalResults") or 0) > 0]
    errors = [r for r in results if r.get("error")]
    credits = sum(r.get("credits") or 0 for r in results)
    lines = ["", "batch summary", "-------------",
             "terms searched : %d" % len(results),
             "with results   : %d" % len(hits),
             "records written: %d" % writer.count,
             "credits spent  : %d" % credits]
    if errors:
        lines.append("errors         : %d" % len(errors))
    for outcome in sorted(hits, key=lambda r: r.get("totalResults") or 0, reverse=True)[:20]:
        lines.append("  %8s  %s%s" % (outcome.get("totalResults"), outcome.get("query"),
                                      "  (%d records)" % outcome["records"]
                                      if outcome.get("records") else ""))
    if len(hits) > 20:
        lines.append("  ... and %d more with results" % (len(hits) - 20))
    for outcome in errors[:10]:
        lines.append("  ERROR  %s: %s" % (outcome.get("query"), outcome.get("error")))
    note("\n".join(lines))


# --------------------------------------------------------------------------
# Watch mode
# --------------------------------------------------------------------------

def watch_state_path(args, body):
    if getattr(args, "state", None):
        return os.path.expanduser(args.state)
    key = json.dumps(body, sort_keys=True, default=str)
    digest = hashlib.sha1(key.encode("utf-8")).hexdigest()[:16]
    return os.path.join(args.session.config.watch_state_dir, "%s.json" % digest)


def load_watch_state(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            state = json.load(handle)
    except (OSError, ValueError):
        return {"totalResults": None, "sources": {}, "seen": [], "checks": 0}
    state.setdefault("sources", {})
    state.setdefault("seen", [])
    state.setdefault("checks", 0)
    return state


def save_watch_state(path, state):
    try:
        directory = os.path.dirname(path)
        if directory and not os.path.isdir(directory):
            os.makedirs(directory, mode=0o700, exist_ok=True)
        with _open_private(path, append=False) as handle:
            json.dump(state, handle, default=str)
    except OSError as exc:
        LOG.warning("could not save watch state %s: %s", path, exc)


def cmd_watch(client, args, out):
    """Re-run a search on an interval and report only what is new.

    Checking costs nothing: only the free metadata view is polled, and credits
    are spent only when --unlock is given *and* the result count has grown.
    """
    body = build_search_body(args)
    path = watch_state_path(args, body)
    state = load_watch_state(path)
    note("watching every %ds, state in %s%s", args.interval, path,
         "" if args.unlock else " (metadata only, no credits spent)")
    writer = make_writer(args, out)
    checks = 0
    exit_code = EXIT_OK
    try:
        while True:
            checks += 1
            try:
                exit_code = _watch_once(client, args, writer, body, state, path) or exit_code
            except LeakSearchError as exc:
                note("check failed: %s", exc)
                exit_code = EXIT_ERROR
            if args.count and checks >= args.count:
                break
            time.sleep(max(5, args.interval))
    except KeyboardInterrupt:
        note("watch stopped after %d check(s)", checks)
    finally:
        writer.close()
    return exit_code


def _watch_once(client, args, writer, body, state, path):
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    result = client.search(body)
    search_id = result.get("searchId")
    if result.get("status") == "PENDING":
        result = poll_until_ready(client, search_id, args.poll_interval,
                                  args.poll_timeout, "search")
    total = result.get("totalResults") or 0
    previous = state.get("totalResults")
    sources = {src.get("leakSourceId"): src.get("count", 0)
               for src in result.get("leakSources") or []}
    new_sources = [src for src in result.get("leakSources") or []
                   if src.get("leakSourceId") not in (state.get("sources") or {})]

    state["checks"] = state.get("checks", 0) + 1
    state["lastCheck"] = stamp
    state["lastSearchId"] = search_id
    args.session.ledger.record(search_id, watch=True, totalResults=total,
                               query=args.query, status=result.get("status"))

    if previous is None:
        note("baseline: %d result(s) across %d source(s)", total, len(sources))
    elif total > previous:
        note("NEW: %d result(s), up from %d (+%d)%s", total, previous, total - previous,
             "" if not new_sources else "; new source(s): "
             + ", ".join(s.get("name", "?") for s in new_sources))
    else:
        note("no change: %d result(s) (checked %s)", total, stamp)

    grew = previous is not None and total > previous
    event = {"checkedAt": stamp, "searchId": search_id, "totalResults": total,
             "previousTotal": previous, "new": bool(grew),
             "newSources": [s.get("name") for s in new_sources]}

    written = 0
    if grew and args.unlock:
        seen = set(state.get("seen") or [])
        collector = _NewRecordCollector(writer, seen, args.max_new)
        spent, _ = unlock_and_download(client, args, collector, search_id, total)
        written = collector.new_count
        event["creditsSpent"] = spent
        event["newRecords"] = written
        state["seen"] = list(seen)[-MAX_SEEN_IDS:]
        note("%d new record(s) written", written)
    elif grew and not args.unlock:
        note("run with --unlock (and a --budget) to download the new records")

    state["totalResults"] = total
    state["sources"] = sources
    save_watch_state(path, state)

    if grew and args.exec_command:
        _run_hook(args.exec_command, event)
    if previous is None and not args.emit_baseline:
        return EXIT_OK
    if grew or args.emit_all or previous is None:
        _emit_event(args, writer, event)
    return EXIT_OK


def _emit_event(args, writer, event):
    """Write the change event without corrupting the record stream."""
    line = json.dumps(event, default=str)
    if args.events:
        try:
            with _open_private(os.path.expanduser(args.events), append=True) as handle:
                handle.write(line + "\n")
        except OSError as exc:
            note("could not write --events %s: %s", args.events, exc)
        return
    if args.unlock and args.format != "jsonl":
        # csv/tsv/table records are going to the output; keep it parsable.
        LOG.debug("event: %s", line)
        return
    writer.out.write_line(line)
    writer.out.flush()


class _NewRecordCollector:
    """Writer wrapper that drops records already seen on an earlier check."""

    def __init__(self, writer, seen, max_new=None):
        self.writer = writer
        self.out = writer.out
        self.seen = seen
        self.max_new = max_new
        self.new_count = 0

    def write(self, record):
        key = record.get("_id")
        if key and key in self.seen:
            return False
        if key:
            self.seen.add(key)
        if self.max_new and self.new_count >= self.max_new:
            return False
        self.new_count += 1
        return self.writer.write(record)


def _run_hook(command, event):
    """Run --exec with the event on stdin and a few LEAKSEARCH_* env vars."""
    env = dict(os.environ)
    env.update({
        "LEAKSEARCH_SEARCH_ID": str(event.get("searchId") or ""),
        "LEAKSEARCH_TOTAL": str(event.get("totalResults") or 0),
        "LEAKSEARCH_PREVIOUS": str(event.get("previousTotal") or 0),
        "LEAKSEARCH_NEW_RECORDS": str(event.get("newRecords") or 0),
    })
    try:
        proc = subprocess.run(command, shell=True, env=env,
                              input=json.dumps(event, default=str).encode("utf-8"),
                              timeout=120)
        if proc.returncode:
            note("--exec command exited %d", proc.returncode)
    except (OSError, subprocess.SubprocessError) as exc:
        note("--exec command failed: %s", exc)


# --------------------------------------------------------------------------
# Ledger / resume
# --------------------------------------------------------------------------

def cmd_ledger(client, args, out):
    entries = args.session.ledger.entries()
    if not entries:
        note("ledger is empty (%s)", args.session.ledger.path or "disabled")
        return EXIT_OK
    entries.sort(key=lambda e: e.get("updatedAt") or "", reverse=True)
    if args.query:
        needle = args.query.lower()
        entries = [e for e in entries
                   if needle in json.dumps(e, default=str).lower()]
    if args.unlocked:
        entries = [e for e in entries if e.get("unlocked")]
    entries = entries[:args.limit]
    if args.format in ("json", "jsonl"):
        if args.format == "jsonl":
            for entry in entries:
                out.write_jsonl(entry)
        else:
            out.write_json(entries)
        return EXIT_OK
    header = "%-26s  %-19s  %9s  %8s  %7s  %s" % (
        "SEARCH ID", "UPDATED", "RESULTS", "UNLOCKED", "CREDITS", "QUERY")
    out.write_line(header)
    out.write_line("-" * len(header))
    for entry in entries:
        out.write_line("%-26s  %-19s  %9s  %8s  %7s  %s" % (
            (entry.get("searchId") or "?")[:26],
            (entry.get("updatedAt") or "")[:19],
            entry.get("totalResults", "?"),
            "yes" if entry.get("unlocked") else "no",
            entry.get("creditsUsed", 0),
            _ledger_query(entry)))
    note("%d entry/entries from %s", len(entries), args.session.ledger.path)
    return EXIT_OK


def _ledger_query(entry):
    if entry.get("query"):
        return entry["query"]
    filters = entry.get("filters") or []
    return " ".join("%s=%s" % (f.get("field"), f.get("query")) for f in filters)[:60]


def cmd_resume(client, args, out):
    """Pick a search back up: poll it, then download it if it is unlocked."""
    entry = args.session.ledger.find(args.search_id) or {}
    if entry:
        note("ledger: %s, %s result(s), unlocked=%s, last seen %s",
             _ledger_query(entry) or "(no query recorded)",
             entry.get("totalResults", "?"), bool(entry.get("unlocked")),
             entry.get("updatedAt", "?"))
    writer = make_writer(args, out)
    try:
        result = client.get_search(args.search_id, page=1, page_size=1)
        if result.get("status") == "PENDING":
            result = poll_until_ready(client, args.search_id, args.poll_interval,
                                      args.poll_timeout, "search")
        summarize(result)
        if result.get("unlocked"):
            _download_cmd_body(client, args, writer, args.search_id)
        elif args.unlock:
            unlock_and_download(client, args, writer, args.search_id,
                                result.get("totalResults") or 0)
        else:
            note("not unlocked; re-run with --unlock to spend credits on it")
            out.write_json(result)
    finally:
        writer.close()
    return EXIT_OK


# --------------------------------------------------------------------------
# Reporting over downloaded JSONL
# --------------------------------------------------------------------------

def read_jsonl(paths):
    for path in paths:
        if path == "-":
            handle, close = sys.stdin, False
        else:
            try:
                handle, close = open(os.path.expanduser(path), "r", encoding="utf-8"), True
            except OSError as exc:
                raise ConfigError("cannot read %s: %s" % (path, exc))
        try:
            for number, line in enumerate(handle, 1):
                line = line.strip()
                if not line or line[0] not in "{":
                    continue
                try:
                    yield json.loads(line)
                except ValueError:
                    LOG.debug("%s:%d: skipping unparsable line", path, number)
        finally:
            if close:
                handle.close()


def build_report(records, top=15):
    report = {
        "records": 0, "uniqueEmails": 0, "uniqueUsernames": 0,
        "withPlaintextPassword": 0, "withHashedPassword": 0, "withPhone": 0,
        "sources": [], "emailDomains": [], "topPasswords": [],
        "reusedPasswords": 0, "queries": [],
    }
    emails, usernames = set(), set()
    sources, domains, passwords, queries = Counter(), Counter(), Counter(), Counter()
    password_accounts = {}

    for record in records:
        report["records"] += 1
        email = (record.get("email") or "").strip().lower()
        username = (record.get("username") or "").strip().lower()
        password = record.get("password")
        if email:
            emails.add(email)
            if "@" in email:
                domains[email.rsplit("@", 1)[1]] += 1
        if username:
            usernames.add(username)
        if password:
            report["withPlaintextPassword"] += 1
            passwords[password] += 1
            password_accounts.setdefault(password, set()).add(email or username or "?")
        if record.get("hashedPassword"):
            report["withHashedPassword"] += 1
        if record.get("phone"):
            report["withPhone"] += 1
        source = record.get("leakSourceName") or record.get("leakSourceId") or "?"
        sources[source] += 1
        if record.get("_query"):
            queries[record["_query"]] += 1

    report["uniqueEmails"] = len(emails)
    report["uniqueUsernames"] = len(usernames)
    report["uniqueAccounts"] = len(emails | usernames)
    report["sources"] = [{"source": k, "records": v} for k, v in sources.most_common(top)]
    report["sourceCount"] = len(sources)
    report["emailDomains"] = [{"domain": k, "records": v} for k, v in domains.most_common(top)]
    report["topPasswords"] = [
        {"password": k, "count": v, "accounts": len(password_accounts.get(k, ()))}
        for k, v in passwords.most_common(top)]
    report["uniquePasswords"] = len(passwords)
    report["reusedPasswords"] = sum(
        1 for pw, accounts in password_accounts.items() if len(accounts) > 1)
    report["queries"] = [{"query": k, "records": v} for k, v in queries.most_common(top)]
    return report


def render_report(report, fmt, redacted):
    if fmt == "json":
        return None  # caller writes JSON directly
    bullet = "- " if fmt == "md" else "  "
    head = (lambda text: "## " + text) if fmt == "md" else (lambda text: text + "\n" + "-" * len(text))
    lines = ["# leaksear.ch report" if fmt == "md" else "leaksear.ch report", ""]
    lines.append(head("Overview"))
    lines.extend([
        "%srecords: %d" % (bullet, report["records"]),
        "%sunique email addresses: %d" % (bullet, report["uniqueEmails"]),
        "%sunique usernames: %d" % (bullet, report["uniqueUsernames"]),
        "%sleak sources: %d" % (bullet, report.get("sourceCount", 0)),
        "%splaintext passwords: %d of %d records" % (
            bullet, report["withPlaintextPassword"], report["records"]),
        "%shashed passwords: %d" % (bullet, report["withHashedPassword"]),
        "%sunique passwords: %d, reused across accounts: %d" % (
            bullet, report.get("uniquePasswords", 0), report["reusedPasswords"]),
        "",
    ])
    def table(title, rows, columns):
        if not rows:
            return
        lines.append(head(title))
        if fmt == "md":
            lines.append("| " + " | ".join(columns) + " |")
            lines.append("|" + "|".join(["---"] * len(columns)) + "|")
            for row in rows:
                lines.append("| " + " | ".join(str(c) for c in row) + " |")
        else:
            for row in rows:
                extra = "".join("  (%s %s)" % (row[i], columns[i])
                                for i in range(2, len(row)))
                lines.append("  %8s  %s%s" % (row[1], row[0], extra))
        lines.append("")

    table("Leak sources", [(s["source"], s["records"]) for s in report["sources"]],
          ["source", "records"])
    table("Email domains", [(d["domain"], d["records"]) for d in report["emailDomains"]],
          ["domain", "records"])
    if report["topPasswords"]:
        title = "Most common passwords" + (" (redacted digests)" if redacted else "")
        table(title, [(p["password"], p["count"], p["accounts"])
                      for p in report["topPasswords"]],
              ["password", "count", "accounts"])
    table("Search terms", [(q["query"], q["records"]) for q in report["queries"]],
          ["query", "records"])
    return "\n".join(lines)


def resolve_source_names(client, report):
    """Turn leak source ids in a report into their names (one API call each)."""
    cache = {}
    for row in report.get("sources") or []:
        source_id = row.get("source")
        if not source_id or source_id == "?":
            continue
        if source_id not in cache:
            try:
                cache[source_id] = (client.leak_source(source_id).get("name")
                                    or source_id)
            except LeakSearchError as exc:
                LOG.debug("could not resolve %s: %s", source_id, exc)
                cache[source_id] = source_id
        row["sourceId"] = source_id
        row["source"] = cache[source_id]
    return report


def cmd_report(client, args, out):
    records = read_jsonl(args.files or ["-"])
    if args.redact_passwords:
        records = (redact_record(r) for r in records)
    report = build_report(records, top=args.top)
    if args.resolve_sources and report["records"]:
        if not client.api_key:
            raise ConfigError("--resolve-sources needs an API key (--api-key, "
                              "$LEAKSEARCH_API_KEY or a --config file)")
        resolve_source_names(client, report)
    if not report["records"]:
        note("no records found in %s", ", ".join(args.files or ["stdin"]))
        return EXIT_ERROR
    if args.format == "json":
        out.write_json(report)
    else:
        out.write_line(render_report(report, args.format, args.redact_passwords))
    note("analysed %d record(s)", report["records"])
    return EXIT_OK


def cmd_status(client, args, out):
    if args.wait:
        result = poll_until_ready(client, args.search_id, args.poll_interval,
                                  args.poll_timeout, "search")
    else:
        result = client.get_search(args.search_id, page=1, page_size=1)
    summarize(result)
    out.write_json(result)
    return EXIT_OK


def cmd_cancel(client, args, out):
    out.write_json(client.cancel(args.token))
    return EXIT_OK


def cmd_history(client, args, out):
    result = client.history(page=args.page, page_size=args.page_size)
    if args.jsonl:
        for entry in result.get("data") or []:
            out.write_jsonl(entry)
    else:
        out.write_json(result)
    return EXIT_OK


def cmd_credits(client, args, out):
    if not args.history:
        out.write_json(client.credits())
        return EXIT_OK
    return cmd_credits_history(client, args, out)


def fetch_credit_history(client, page, page_size, fetch_all, limit=None):
    """Yield credit transactions, following pages when fetch_all is set."""
    page_size = max(1, min(int(page_size), 100))
    yielded = 0
    while True:
        result = client.credits_history(page=page, page_size=page_size)
        rows = result.get("data") or []
        for row in rows:
            yield row
            yielded += 1
            if limit and yielded >= limit:
                return
        total_pages = int(result.get("totalPages") or 1)
        if not fetch_all or not rows or page >= total_pages:
            return
        page += 1


def cmd_credits_history(client, args, out):
    """credits --history: the API's own record of every credit movement."""
    wanted_types = set(args.type or [])
    rows = []
    for row in fetch_credit_history(client, args.page, args.page_size, args.all,
                                    limit=None if wanted_types else args.limit):
        if wanted_types and row.get("type") not in wanted_types:
            continue
        rows.append(row)
        if args.limit and len(rows) >= args.limit:
            break
    if args.search:
        rows = [r for r in rows if r.get("referenceId") == args.search]

    # Link spend back to what was searched, using the local ledger.
    ledger = {e["searchId"]: e for e in args.session.ledger.entries()}
    for row in rows:
        entry = ledger.get(row.get("referenceId") or "")
        if entry:
            row["_query"] = _ledger_query(entry)

    spent = -sum(r.get("amount") or 0 for r in rows if (r.get("amount") or 0) < 0)
    gained = sum(r.get("amount") or 0 for r in rows if (r.get("amount") or 0) > 0)

    fmt = args.format
    if fmt == "json":
        out.write_json(rows)
    elif fmt in ("jsonl", "csv", "tsv"):
        writer = RecordWriter(out, fmt=fmt, fields=CREDIT_HISTORY_FIELDS)
        for row in rows:
            writer.write(row)
        writer.close()
    else:
        _credit_history_table(out, rows)
    note("%d transaction(s): %d credit(s) spent, %d added%s", len(rows), spent, gained,
         "" if args.all else " (this page only; --all for everything)")
    return EXIT_OK


CREDIT_HISTORY_FIELDS = ["createdAt", "type", "amount", "balanceAfter", "reason",
                         "referenceId", "_query"]


def _credit_history_table(out, rows):
    if not rows:
        note("no credit transactions")
        return
    header = "%-19s  %-23s  %6s  %7s  %s" % ("WHEN (UTC)", "TYPE", "AMOUNT", "BALANCE",
                                             "REASON / SEARCH")
    out.write_line(header)
    out.write_line("-" * len(header))
    for row in rows:
        detail = row.get("reason") or ""
        if row.get("_query"):
            detail = "%s  [%s]" % (detail, row["_query"])
        elif row.get("referenceId"):
            detail = "%s  [%s]" % (detail, row["referenceId"])
        amount = row.get("amount") or 0
        out.write_line("%-19s  %-23s  %6s  %7s  %s" % (
            (row.get("createdAt") or "")[:19].replace("T", " "),
            row.get("type") or "?",
            ("+%d" % amount) if amount > 0 else str(amount),
            row.get("balanceAfter", ""),
            detail[:90]))


def cmd_status_check(client, args, out):
    """--status: verify the API key works and report the credit balance."""
    report = {
        "ok": False,
        "baseUrl": client.config.base_url,
        "configFile": client.config.path,
        "apiKey": _key_fingerprint(client.api_key),
    }
    try:
        credits = client.credits()
    except APIError as exc:
        report["error"] = str(exc)
        report["errorCode"] = exc.code
        if exc.status in (401, 403):
            note("api key    : REJECTED by %s (%s)", client.config.base_url, exc)
            note("             check api_key in %s, or the auth_header/auth_scheme settings",
                 client.config.path or "the config file")
        else:
            note("api key    : could not be verified (%s)", exc)
        out.write_json(report)
        return exc.exit_code

    report["ok"] = True
    report["credits"] = credits.get("credits", 0)
    report["monthlyCredits"] = credits.get("monthlyCredits", 0)
    report["available"] = spendable_credits(credits)
    report["subscription"] = credits.get("subscription")

    lines = ["api key    : OK (%s)" % report["apiKey"],
             "endpoint   : %s" % client.config.base_url,
             "config     : %s" % (client.config.path or "<none, key from CLI/environment>")]

    # Best effort extras: neither should turn a working key into a failure.
    try:
        profile = client.profile()
        report["profile"] = profile
        who = profile.get("email") or profile.get("name") or profile.get("id")
        if who:
            lines.append("account    : %s" % who)
    except (LeakSearchError, AttributeError) as exc:
        LOG.debug("profile lookup failed: %s", exc)

    lines.append("credits    : %s available (%s purchased + %s monthly)"
                 % (report["available"], report["credits"], report["monthlyCredits"]))
    lines.append("unlocks    : up to %s results (%d per credit)"
                 % (report["available"] * RESULTS_PER_CREDIT, RESULTS_PER_CREDIT))
    subscription = report["subscription"]
    if isinstance(subscription, dict):
        lines.append("plan       : %s until %s" % (subscription.get("status", "?"),
                                                   subscription.get("currentPeriodEnd", "?")))
    else:
        lines.append("plan       : none")

    try:
        health = client.health()
        report["health"] = health
        lines.append("service    : %s (database %s, opensearch %s)"
                     % (health.get("status", "?"),
                        "up" if health.get("database") else "down",
                        health.get("opensearchStatus", "?")))
    except LeakSearchError as exc:
        LOG.debug("health check failed: %s", exc)

    note("\n".join(lines))
    out.write_json(report)
    return EXIT_OK


def _key_fingerprint(key):
    if len(key) <= 8:
        return "***"
    return "%s...%s" % (key[:4], key[-4:])


def cmd_profile(client, args, out):
    out.write_json(client.profile())
    return EXIT_OK


def cmd_sources(client, args, out):
    if args.stats:
        out.write_json(client.leak_source_stats())
        return EXIT_OK
    if args.id:
        out.write_json(client.leak_source(args.id))
        return EXIT_OK
    params = {
        "page": args.page,
        "pageSize": args.page_size,
        "search": args.search,
        "visibility": args.visibility,
        "categories": ",".join(args.category) if args.category else None,
        "authenticities": ",".join(args.authenticity) if args.authenticity else None,
        "sortBy": args.sort_by,
        "sortOrder": args.sort_order,
    }
    result = client.leak_sources(**params)
    if args.jsonl:
        for source in result.get("leakSources") or []:
            out.write_jsonl(source)
    else:
        out.write_json(result)
    return EXIT_OK


def cmd_health(client, args, out):
    out.write_json(client.health())
    return EXIT_OK


def _try_cancel(client, token):
    note("interrupted, asking the server to cancel the running search...")
    try:
        client.cancel(token)
        note("cancel request sent")
    except Exception as exc:  # best effort only
        LOG.debug("cancel failed: %s", exc)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def add_poll_options(parser):
    group = parser.add_argument_group("polling")
    group.add_argument("--poll-interval", type=float, default=None, metavar="SECONDS",
                       help="seconds between status polls (default: 3, config: poll_interval)")
    group.add_argument("--poll-timeout", type=float, default=None, metavar="SECONDS",
                       help="give up polling after this long, 0 to wait forever "
                            "(default: 900, config: poll_timeout)")


def _add_source_filter_options(parser):
    source_group = parser.add_argument_group("leak source filters")
    source_group.add_argument("--source", action="append", metavar="ID",
                              help="only search these leak source IDs, repeatable")
    source_group.add_argument("--exclude-source", action="append", metavar="ID",
                              help="exclude these leak source IDs, repeatable")
    source_group.add_argument("--breached-since", metavar="YYYY-MM-DD")
    source_group.add_argument("--breached-until", metavar="YYYY-MM-DD")
    source_group.add_argument("--indexed-since", metavar="YYYY-MM-DD")
    source_group.add_argument("--indexed-until", metavar="YYYY-MM-DD")
    source_group.add_argument("--visibility", choices=VISIBILITIES, default="ALL")
    source_group.add_argument("--source-min-records", type=int, metavar="N",
                              help="only search sources holding at least N records")
    source_group.add_argument("--source-max-records", type=int, metavar="N",
                              help="only search sources holding at most N records")
    source_group.add_argument("--required-field", action="append", choices=FIELDS,
                              metavar="FIELD", help="source must expose FIELD, repeatable")
    source_group.add_argument("--category", action="append", choices=CATEGORIES,
                              metavar="CATEGORY", help="include category, repeatable")
    source_group.add_argument("--exclude-category", action="append", choices=CATEGORIES,
                              metavar="CATEGORY", help="exclude category, repeatable")
    source_group.add_argument("--category-match", choices=["ANY", "ALL"], default=None)
    source_group.add_argument("--authenticity", action="append", choices=AUTHENTICITIES,
                              metavar="STATUS", help="authenticity status, repeatable")


def add_format_options(parser, default_format="jsonl"):
    group = parser.add_argument_group("output format")
    group.add_argument("--format", choices=OUTPUT_FORMATS, default=default_format,
                       help="output format (default: %s)" % default_format)
    group.add_argument("--fields", metavar="A,B,C",
                       help="columns for csv/tsv/table output, in order")
    group.add_argument("--redact-passwords", action="store_true",
                       help="replace passwords with a stable digest so results "
                            "stay shareable and reuse analysis still works")


def add_spend_options(parser, include_unlock=True):
    group = parser.add_argument_group("unlocking (spends credits)")
    if include_unlock:
        group.add_argument("--unlock", action="store_true",
                           help="spend credits to unlock and download the records")
    else:
        parser.set_defaults(unlock=True)
    group.add_argument("--credits", type=int, metavar="N",
                       help="credits to spend per search, each unlocks up to %d "
                            "results (default: enough for all results)" % RESULTS_PER_CREDIT)
    group.add_argument("--max-credits", type=int, metavar="N",
                       help="never spend more than N credits on a single search")
    group.add_argument("--budget", type=int, metavar="N",
                       help="total credits this run may spend across all searches "
                            "(config: max_credits_per_run)")
    group.add_argument("--dry-run", action="store_true",
                       help="search and report what unlocking would cost, "
                            "without spending anything")
    group.add_argument("-y", "--yes", action="store_true",
                       help="do not ask before spending credits")
    return group


def add_paging_options(parser):
    group = parser.add_argument_group("result download")
    group.add_argument("--page-size", type=int, default=None, metavar="N",
                       help="records per API page, max %d (default: %d)"
                            % (MAX_PAGE_SIZE, MAX_PAGE_SIZE))
    group.add_argument("--max-records", type=int, default=None, metavar="N",
                       help="stop after writing N records")
    group.add_argument("--sources", metavar="IDS",
                       help="comma-separated leak source IDs to restrict downloaded records to")


GLOBAL_DEFAULTS = {
    "config": None, "api_key": None, "base_url": None, "output": None,
    "append": False, "debug": False, "quiet": False, "insecure": False,
    "status": False, "no_ledger": False,
}


def build_global_parser():
    """Global options, shared by the top level and every subcommand.

    Defaults are SUPPRESSed so that `--output x search ...` is not clobbered
    by the subparser re-parsing the same option; see apply_global_defaults().
    """
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", metavar="FILE", default=argparse.SUPPRESS,
                        help="configuration file holding the API key "
                             "(default: first of %s)" % ", ".join(DEFAULT_CONFIG_PATHS))
    common.add_argument("--api-key", metavar="KEY", default=argparse.SUPPRESS,
                        help="API key, overrides the config file and $LEAKSEARCH_API_KEY")
    common.add_argument("--base-url", metavar="URL", default=argparse.SUPPRESS,
                        help="API base URL override")
    common.add_argument("--output", metavar="FILENAME", default=argparse.SUPPRESS,
                        help="write output to FILENAME (default: stdout)")
    common.add_argument("--append", action="store_true", default=argparse.SUPPRESS,
                        help="append to --output instead of truncating it")
    common.add_argument("--debug", action="store_true", default=argparse.SUPPRESS,
                        help="log HTTP requests and responses to stderr (API key redacted)")
    common.add_argument("--quiet", action="store_true", default=argparse.SUPPRESS,
                        help="suppress progress messages on stderr")
    common.add_argument("--insecure", action="store_true", default=argparse.SUPPRESS,
                        help="do not verify TLS certificates")
    common.add_argument("--no-ledger", action="store_true", default=argparse.SUPPRESS,
                        help="do not record this run in the local search ledger")
    common.add_argument("--status", action="store_true", default=argparse.SUPPRESS,
                        help="check that the API key works and show the credit "
                             "balance, then exit (no search is run)")
    return common


def apply_global_defaults(args):
    for name, default in GLOBAL_DEFAULTS.items():
        if not hasattr(args, name):
            setattr(args, name, default)
    return args


def build_parser():
    common = build_global_parser()
    parser = argparse.ArgumentParser(
        prog="leaksearch",
        parents=[common],
        description="Query the leaksear.ch breach-data API.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  leaksearch --config ~/.leaksearch.ini --status
  leaksearch --config ~/.leaksearch.ini search foo@example.com
  leaksearch search 'john*' --field username --unlock --output hits.jsonl
  leaksearch search example.com -f domain --category INFO_STEALER_LOG --breached-since 2023-01-01
  leaksearch download 018f... --output records.jsonl
  leaksearch credits

Global options (--config, --output, --debug, ...) may be given before or
after the subcommand.

config file (INI, or JSON with the same keys):
  [leaksearch]
  api_key = lsk_live_...
  base_url = https://leaksear.ch
  poll_interval = 3
  poll_timeout = 900
""")
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)

    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    # search ---------------------------------------------------------------
    search = subparsers.add_parser(
        "search", parents=[common], help="search breach records (optionally unlock and download them)",
        description="Search indexed breach records for a string, poll until the "
                    "search completes, and optionally spend credits to download "
                    "the full records as JSONL.")
    search.add_argument("query", nargs="?", help="string to search for")
    search.add_argument("-f", "--field", choices=FIELDS,
                        help="field to match QUERY against (default: guessed from QUERY)")
    search.add_argument("-t", "--type", choices=MATCH_TYPES, default=None,
                        help="match type (default: WILDCARD if QUERY contains * or ?, "
                             "else EXACT)")
    search.add_argument("--filter", action="append", metavar="FIELD:[TYPE:]QUERY",
                        help="extra filter, repeatable (max 5 filters in total)")
    search.add_argument("--operator", choices=["AND", "OR"], default="AND",
                        help="how filters are combined (default: AND)")
    search.add_argument("--operators", metavar="OP,OP",
                        help="per-gap operators for 3+ filters, e.g. AND,OR")
    batch_group = search.add_argument_group("batch input")
    batch_group.add_argument("-i", "--input", metavar="FILE",
                             help="search one term per line from FILE ('-' for stdin); "
                                  "a line may be 'field:term' to override the field")
    batch_group.add_argument("--concurrency", type=int, default=2, metavar="N",
                             help="how many batch searches to run at once (default: 2)")
    batch_group.add_argument("--dedupe", action="store_true",
                             help="drop records already written in this run")
    batch_group.add_argument("--no-annotate", action="store_true",
                             help="do not add the matching term as _query to each record")
    add_spend_options(search)
    _add_source_filter_options(search)
    add_poll_options(search)
    add_paging_options(search)
    add_format_options(search)
    search.set_defaults(func=cmd_search)

    # unlock ---------------------------------------------------------------
    unlock = subparsers.add_parser(
        "unlock", parents=[common], help="spend credits to unlock an existing search and download it")
    unlock.add_argument("search_id")
    add_spend_options(unlock, include_unlock=False)
    add_poll_options(unlock)
    add_paging_options(unlock)
    add_format_options(unlock)
    unlock.set_defaults(func=cmd_unlock)

    # download -------------------------------------------------------------
    download = subparsers.add_parser(
        "download", parents=[common], help="download the records of an already unlocked search as JSONL")
    download.add_argument("search_id")
    add_poll_options(download)
    add_paging_options(download)
    add_format_options(download)
    download.set_defaults(func=cmd_download)

    # watch ----------------------------------------------------------------
    watch = subparsers.add_parser(
        "watch", parents=[common],
        help="re-run a search on an interval and report only what is new",
        description="Poll a search on a schedule and report when its result "
                    "count grows. Checking is free; credits are spent only with "
                    "--unlock, and only when something new appears.")
    watch.add_argument("query", nargs="?", help="string to watch for")
    watch.add_argument("-f", "--field", choices=FIELDS)
    watch.add_argument("-t", "--type", choices=MATCH_TYPES, default=None)
    watch.add_argument("--filter", action="append", metavar="FIELD:[TYPE:]QUERY")
    watch.add_argument("--operator", choices=["AND", "OR"], default="AND")
    watch.add_argument("--operators", metavar="OP,OP")
    watch.add_argument("--interval", type=int, default=3600, metavar="SECONDS",
                       help="seconds between checks (default: 3600, minimum 5)")
    watch.add_argument("--count", type=int, default=0, metavar="N",
                       help="stop after N checks (default: 0, run until interrupted)")
    watch.add_argument("--state", metavar="FILE",
                       help="where to remember what has been seen "
                            "(default: derived from the query)")
    watch.add_argument("--max-new", type=int, default=None, metavar="N",
                       help="write at most N new records per check")
    watch.add_argument("--exec", dest="exec_command", metavar="CMD",
                       help="shell command to run when new results appear; the "
                            "event JSON is on stdin and in LEAKSEARCH_* env vars")
    watch.add_argument("--events", metavar="FILE",
                       help="append change events as JSON lines to FILE instead "
                            "of mixing them into the record output")
    watch.add_argument("--emit-all", action="store_true",
                       help="write an event on every check, not only on changes")
    watch.add_argument("--emit-baseline", action="store_true",
                       help="also write the event for the first (baseline) check")
    _add_source_filter_options(watch)
    add_spend_options(watch)
    add_poll_options(watch)
    add_paging_options(watch)
    add_format_options(watch)
    watch.set_defaults(func=cmd_watch, input=None, dedupe=False, no_annotate=True)

    # resume ---------------------------------------------------------------
    resume = subparsers.add_parser(
        "resume", parents=[common],
        help="pick a past search back up by id and download it")
    resume.add_argument("search_id")
    add_spend_options(resume)
    add_poll_options(resume)
    add_paging_options(resume)
    add_format_options(resume)
    resume.set_defaults(func=cmd_resume)

    # ledger ---------------------------------------------------------------
    ledger = subparsers.add_parser(
        "ledger", parents=[common],
        help="list the searches this tool has run locally (ids, spend, output)")
    ledger.add_argument("query", nargs="?", help="only entries matching this text")
    ledger.add_argument("--limit", type=int, default=25)
    ledger.add_argument("--unlocked", action="store_true",
                        help="only searches that were unlocked")
    ledger.add_argument("--format", choices=["table", "json", "jsonl"], default="table")
    ledger.set_defaults(func=cmd_ledger, needs_key=False)

    # report ---------------------------------------------------------------
    report = subparsers.add_parser(
        "report", parents=[common],
        help="summarise downloaded JSONL records (sources, domains, password reuse)")
    report.add_argument("files", nargs="*", metavar="FILE",
                        help="JSONL files written by this tool ('-' or none for stdin)")
    report.add_argument("--format", choices=["text", "md", "json"], default="text")
    report.add_argument("--top", type=int, default=15, metavar="N",
                        help="rows per table (default: 15)")
    report.add_argument("--redact-passwords", action="store_true",
                        help="digest passwords before reporting")
    report.add_argument("--resolve-sources", action="store_true",
                        help="look leak source names up from the API (needs a key)")
    report.set_defaults(func=cmd_report, needs_key=False)

    # status ---------------------------------------------------------------
    status = subparsers.add_parser("status", parents=[common], help="show the status of a search")
    status.add_argument("search_id")
    status.add_argument("--wait", action="store_true",
                        help="poll until the search is no longer pending")
    add_poll_options(status)
    status.set_defaults(func=cmd_status)

    # cancel ---------------------------------------------------------------
    cancel = subparsers.add_parser("cancel", parents=[common], help="cancel an in-flight search by its token")
    cancel.add_argument("token")
    cancel.set_defaults(func=cmd_cancel)

    # history --------------------------------------------------------------
    history = subparsers.add_parser("history", parents=[common], help="list your past searches")
    history.add_argument("--page", type=int, default=1)
    history.add_argument("--page-size", type=int, default=20)
    history.add_argument("--jsonl", action="store_true", help="one search per line")
    history.set_defaults(func=cmd_history)

    # credits / profile ----------------------------------------------------
    credits = subparsers.add_parser(
        "credits", parents=[common],
        help="show your credit balance, or --history of credit transactions")
    credits.add_argument("--history", action="store_true",
                         help="list credit transactions (purchases, unlocks, refreshes)")
    credits.add_argument("--all", action="store_true",
                         help="with --history: fetch every page, not just one")
    credits.add_argument("--page", type=int, default=1, metavar="N")
    credits.add_argument("--page-size", type=int, default=25, metavar="N",
                         help="transactions per page, max 100 (default: 25)")
    credits.add_argument("--limit", type=int, metavar="N",
                         help="stop after N matching transactions")
    credits.add_argument("--type", action="append", choices=CREDIT_TX_TYPES,
                         metavar="TYPE", help="only this transaction type, repeatable: "
                                              + ", ".join(CREDIT_TX_TYPES))
    credits.add_argument("--search", metavar="SEARCH_ID",
                         help="only transactions referencing this search id")
    credits.add_argument("--format", choices=["table", "json", "jsonl", "csv", "tsv"],
                         default="table", help="--history output format (default: table)")
    credits.set_defaults(func=cmd_credits)
    subparsers.add_parser("profile", parents=[common], help="show your account profile").set_defaults(
        func=cmd_profile)
    subparsers.add_parser("health", parents=[common], help="check API health").set_defaults(func=cmd_health)

    # sources --------------------------------------------------------------
    sources = subparsers.add_parser("sources", parents=[common], help="list or inspect indexed leak sources")
    sources.add_argument("--id", metavar="ID", help="show one leak source")
    sources.add_argument("--stats", action="store_true", help="show aggregate statistics")
    sources.add_argument("--search", metavar="TEXT")
    sources.add_argument("--page", type=int, default=1)
    sources.add_argument("--page-size", type=int, default=50)
    sources.add_argument("--visibility", choices=VISIBILITIES, default=None)
    sources.add_argument("--category", action="append", choices=CATEGORIES, metavar="CATEGORY")
    sources.add_argument("--authenticity", action="append", choices=AUTHENTICITIES,
                         metavar="STATUS")
    sources.add_argument("--sort-by", metavar="FIELD",
                         help="name, dateIndexed, dateBreached or recordCount")
    sources.add_argument("--sort-order", choices=["asc", "desc"], default=None)
    sources.add_argument("--jsonl", action="store_true", help="one source per line")
    sources.set_defaults(func=cmd_sources)

    return parser


def configure_logging(debug, quiet):
    level = logging.DEBUG if debug else (logging.ERROR if quiet else logging.WARNING)
    logging.basicConfig(stream=sys.stderr, level=level,
                        format="%(asctime)s %(levelname)s %(message)s",
                        datefmt="%H:%M:%S")


def main(argv=None):
    parser = build_parser()
    args = apply_global_defaults(parser.parse_args(argv))
    if not getattr(args, "func", None) and not args.status:
        parser.print_help()
        return EXIT_USAGE

    configure_logging(args.debug, args.quiet)
    if args.quiet:
        global note
        note = lambda *a, **k: None  # noqa: E731

    try:
        config = load_config(args.config)
        if args.base_url:
            config.base_url = args.base_url.rstrip("/")
        if args.insecure:
            config.verify_tls = False
        # Fill polling/paging defaults from the config file when not given on the CLI.
        if getattr(args, "poll_interval", None) is None:
            args.poll_interval = config.poll_interval
        if getattr(args, "poll_timeout", None) is None:
            args.poll_timeout = config.poll_timeout
        if vars(args).get("page_size") is None:
            args.page_size = config.page_size
        if getattr(args, "needs_key", True) or args.status:
            api_key = resolve_api_key(config, args.api_key)
        else:
            # `report` and `ledger` work purely locally.
            api_key = (args.api_key or os.environ.get("LEAKSEARCH_API_KEY")
                       or config.api_key or "")
        LOG.debug("base url %s, config %s", config.base_url, config.path or "<none>")

        client = Client(config, api_key)
        ledger = Ledger(config.ledger, enabled=not args.no_ledger)
        budget_limit = getattr(args, "budget", None)
        if budget_limit is None:
            budget_limit = config.max_credits_per_run
        args.session = Session(client, config, ledger,
                               Budget(client, limit=budget_limit))
        with Output(args.output, append=args.append) as out:
            if args.status:
                return cmd_status_check(client, args, out)
            return args.func(client, args, out)
    except KeyboardInterrupt:
        note("interrupted")
        return EXIT_INTERRUPTED
    except LeakSearchError as exc:
        LOG.debug("", exc_info=True)
        sys.stderr.write("error: %s\n" % exc)
        if isinstance(exc, APIError) and exc.details:
            sys.stderr.write("details: %s\n" % json.dumps(exc.details, default=str))
        return exc.exit_code
    except BrokenPipeError:
        return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
