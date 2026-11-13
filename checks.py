#!/usr/bin/env python3
"""checks.py — real, bounded checks for the categories that can be scripted.

This is the honest middle ground between the old demo table and a full scanner:
each category below makes a small, fixed number of ordinary requests, records
exactly which URLs were touched, and only emits a finding when a response is
actual evidence (an exposed file, a reflected payload, a redirect to a host we
chose). Everything is scope-checked through scope_guard before it is fetched.

Categories that need an authenticated browser session, a second account, or a
destructive payload are deliberately *not* automated. They return a note saying
so, plus the tool/manual test that would cover them. A note is better than a
fiction.

The pure helpers (`scan_js_text`, `cname_candidates`, `redirect_location`) are
covered by selftest.py without any network access.
"""

import html
import json
import re
import shutil
import socket
import subprocess
import time
import urllib.parse

import scope_guard
import surface

MAX_SECONDS = 40          # per category, wall clock
MAX_REQUESTS = 40         # hard cap on outbound requests per category
MAX_FINDINGS = 12
MAX_ASSETS = 120

PROBE_ORIGIN = surface.PROBE_ORIGIN

SCRIPT_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
ENDPOINT_RE = re.compile(
    r"""["'`]((?:https?://[^"'`\s<>]+)|(?:/[A-Za-z0-9_\-./{}?=&%:]+))["'`]""")
SOURCE_MAP_RE = re.compile(r"sourceMappingURL=([^\s*\"']+)")
SECRET_PATTERNS = [
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("Stripe secret key", re.compile(r"\bsk_live_[0-9A-Za-z]{20,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b")),
    ("private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
]
GENERIC_SECRET_RE = re.compile(
    r"(?i)(?:api[_-]?key|secret|token|password)\s*[:=]\s*[\"']([A-Za-z0-9_\-]{20,})[\"']")

# CNAME suffixes that are worth looking at, and the body text each service
# returns when nobody has claimed the name. The fingerprint matters more than
# the CNAME: a CNAME into S3 is normal until the bucket answer is NoSuchBucket.
TAKEOVER_SERVICES = [
    ("Amazon S3", re.compile(r"(?:^|\.)s3[.-][a-z0-9-]*\.amazonaws\.com$|"
                             r"\.s3\.amazonaws\.com$|s3-website", re.I),
     ("NoSuchBucket", "The specified bucket does not exist")),
    ("GitHub Pages", re.compile(r"(?:^|\.)github\.io$", re.I),
     ("There isn't a GitHub Pages site here",)),
    ("Heroku", re.compile(r"(?:^|\.)herokuapp\.com$", re.I),
     ("No such app",)),
    ("Azure App Service", re.compile(r"(?:^|\.)azurewebsites\.net$", re.I),
     ("404 Web Site not found",)),
    ("CloudFront", re.compile(r"(?:^|\.)cloudfront\.net$", re.I),
     ("ERROR: The request could not be satisfied",)),
    ("Fastly", re.compile(r"(?:^|\.)fastly\.net$", re.I),
     ("Fastly error: unknown domain",)),
    ("Read the Docs", re.compile(r"(?:^|\.)readthedocs\.io$", re.I),
     ("This documentation does not exist",)),
    ("Surge.sh", re.compile(r"(?:^|\.)surge\.sh$", re.I),
     ("project not found",)),
    ("Netlify", re.compile(r"(?:^|\.)netlify\.app$", re.I),
     ("Not Found - Request ID",)),
]

SPEC_PATHS = [
    "/openapi.json", "/swagger.json", "/v3/api-docs",
    "/api-docs", "/swagger/v1/swagger.json",
]

REDIRECT_PAYLOAD = "//example.invalid/"
REDIRECT_CANDIDATES = [
    ("/login", "next"), ("/login", "redirect"), ("/", "url"),
    ("/redirect", "url"), ("/", "next"),
]

XSS_CANDIDATES = [("/", "q"), ("/search", "q"), ("/", "s"), ("/search", "query")]

MANUAL = {
    "auth_session": "needs an authenticated session and a second account: compare "
                    "reset-token reuse, session fixation and MFA replay by hand. "
                    "Use jwt_tool for token-shaped sessions.",
    "access_control": "needs two accounts: replay object ids/roles with account B's "
                      "cookie (IDOR/BOLA). Automating this without credentials would "
                      "only produce noise.",
    "injection": "needs an authenticated request and a safe target: sqlmap or ghauri "
                 "with the captured request, rate-limited. No blind fuzzing here.",
    "ssrf": "needs an out-of-band listener: run interactsh-client and inject its URL "
            "into fetch-style parameters, then check for callbacks.",
    "deserialization": "framework-specific payloads (Java/PHP/Python/Node) need a "
                       "captured request. Probe with ysoserial/phpggc only on a target "
                       "you are allowed to test.",
    "jwt_crypto": "capture a token first, then: jwt_tool <token> -M at -C -d wordlist.txt",
    "file_upload": "needs a real upload form and a writable account: test double "
                   "extensions, content-type confusion and path traversal by hand.",
    "rate_limiting": "requires repeated authentication attempts; doing that "
                     "automatically against a live login is indistinguishable from "
                     "credential stuffing. Use a small manual sample.",
    "business_logic": "application-specific: no generic CLI can tell whether a coupon, "
                      "price or workflow transition is wrong. Map the flow by hand.",
    "http_smuggling": "desync probes can poison shared caches: run smuggler or "
                      "h2cSmuggler manually, with explicit permission, never as part "
                      "of an unattended sweep.",
}

SEVERITIES = ("confirmed", "likely", "dig")


class Budget:
    """Wall-clock + request-count guard so no category can wander off."""

    def __init__(self, seconds=MAX_SECONDS, requests=MAX_REQUESTS):
        self.started = time.time()
        self.seconds = seconds
        self.max_requests = requests
        self.requests = []

    def left(self):
        return (time.time() - self.started < self.seconds
                and len(self.requests) < self.max_requests)

    def record(self, url, obs=None, note=None):
        self.requests.append({
            "url": url,
            "status": (obs or {}).get("status"),
            "error": (obs or {}).get("error"),
            "note": note,
        })


class Result:
    def __init__(self, category, host, task_desc):
        self.category = category
        self.host = host
        self.task_desc = task_desc
        self.findings = []
        self.assets = []
        self.notes = []
        self.budget = Budget()

    def note(self, text):
        if text and text not in self.notes:
            self.notes.append(text)

    def finding(self, title, severity, url, evidence, command,
                param=None, payload=None):
        if len(self.findings) >= MAX_FINDINGS:
            return
        if severity not in SEVERITIES:
            severity = "likely"
        self.findings.append({
            "title": title,
            "severity": severity,
            "category": self.category,
            "host": self.host,
            "url": url,
            "param": param,
            "payload": payload,
            "evidence": evidence,
            "command": command,
            "task_desc": self.task_desc,
            "demo": False,
        })

    def asset(self, kind, value, source):
        if len(self.assets) >= MAX_ASSETS:
            return
        self.assets.append({"kind": kind, "value": value, "source": source})

    def as_dict(self):
        return {
            "category": self.category,
            "findings": self.findings,
            "assets": self.assets,
            "notes": self.notes,
            "requests": self.budget.requests,
        }


# --- request helpers -------------------------------------------------------

def _get(result, url, follow=True, data=None, extra_headers=None, note=None):
    """Scope-check, fetch, record. Returns None when the budget is spent."""
    allowed, reason = scope_guard.check(url)
    if not allowed:
        result.note("request skipped (scope): %s — %s" % (url, reason))
        return None
    if not result.budget.left():
        result.note("request budget reached; remaining checks skipped")
        return None
    obs = surface._request(url, follow=follow, data=data,
                           extra_headers=extra_headers)
    result.budget.record(url, obs, note)
    return obs


def _base(result, host):
    """Pick https or http once, and return (base_url, root_response)."""
    for scheme in ("https", "http"):
        url = "%s://%s/" % (scheme, host)
        obs = _get(result, url)
        if obs and obs.get("status") is not None:
            if scheme == "http":
                result.note("https did not answer; checks used plain http")
            return "%s://%s" % (scheme, host), obs
        if not result.budget.left():
            break
    return "https://%s" % host, None


def _with_param(url, param, value):
    parts = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    query.append((param, value))
    return urllib.parse.urlunsplit((
        parts.scheme, parts.netloc, parts.path or "/",
        urllib.parse.urlencode(query), ""))


def _with_raw_param(url, param, value):
    """Like _with_param, but leave `/` and `:` readable.

    Some redirect handlers compare the raw query string before decoding it, so
    sending `url=%2F%2Fexample.invalid%2F` can hide a real open redirect. This
    form sends `url=//example.invalid/`, which is also what a browser sends.
    """
    parts = urllib.parse.urlsplit(url)
    addition = "%s=%s" % (urllib.parse.quote(param, safe=""),
                          urllib.parse.quote(value, safe="/:"))
    query = parts.query + ("&" if parts.query else "") + addition
    return urllib.parse.urlunsplit((
        parts.scheme, parts.netloc, parts.path or "/", query, ""))


def _absolute(base, link):
    return urllib.parse.urljoin(base + "/", link)


def _redact(value):
    if len(value) <= 12:
        return value[:2] + "…"
    return value[:4] + "…" + value[-4:]


# --- pure helpers (unit-tested) -------------------------------------------

def scan_js_text(text):
    """Return endpoints and secrets found in one JavaScript body.

    Endpoints are de-duplicated and stop at 40; secrets are additionally
    checked for a generic `api_key: "..."` shape. The caller decides what to
    report — an endpoint is an asset, a credential is a finding.
    """
    text = text or ""
    endpoints, seen = [], set()
    for raw in ENDPOINT_RE.findall(text):
        value = raw.strip()
        if len(value) < 3 or len(value) > 200 or value in seen:
            continue
        if re.search(r"\.(?:png|jpe?g|gif|svg|ico|css|woff2?|ttf|eot|map)"
                     r"(?:[?#]|$)", value, re.I):
            continue
        if value.startswith(("data:", "javascript:", "mailto:", "#")):
            continue
        seen.add(value)
        endpoints.append(value)
        if len(endpoints) >= 40:
            break

    secrets, seen_kinds = [], set()
    for label, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            if label in seen_kinds:
                break
            seen_kinds.add(label)
            secrets.append({"kind": label, "value": _redact(match.group(0))})
    for match in GENERIC_SECRET_RE.finditer(text):
        if match.group(1).lower() in ("document", "undefined", "null"):
            continue
        secrets.append({"kind": "generic secret assignment",
                        "value": _redact(match.group(1))})
        break
    return {"endpoints": endpoints, "secrets": secrets}


def cname_candidates(host):
    """Best-effort CNAME lookup: dig when present, socket aliases otherwise."""
    out = []
    dig = shutil.which("dig")
    if dig:
        try:
            done = subprocess.run(
                [dig, "+short", "CNAME", host],
                capture_output=True, text=True, timeout=6)
            for line in (done.stdout or "").splitlines():
                name = line.strip().rstrip(".")
                if name and re.match(r"^[A-Za-z0-9_.-]+$", name):
                    out.append(name)
        except Exception:
            pass
    if not out:
        try:
            _canonical, aliases, _ips = socket.gethostbyname_ex(host)
            out = [a.strip().rstrip(".") for a in aliases if a.strip()]
        except OSError:
            pass
    # A CNAME chain can return several names; keep order, drop duplicates.
    seen, unique = set(), []
    for name in out:
        if name.lower() not in seen:
            seen.add(name.lower())
            unique.append(name)
    return unique


def redirect_location(location):
    """True when a Location header leaves the original host for our marker.

    Only `example.invalid` counts, so a normal login redirect to `/dashboard`
    or even to the same origin is never reported as an open redirect.
    """
    if not location:
        return False
    value = location.strip()
    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError:
        return False
    if value.startswith("//"):
        return parsed.netloc.lower().split(":")[0] == "example.invalid"
    return parsed.scheme in ("http", "https") and \
        parsed.hostname == "example.invalid"


def takeover_match(cname, body):
    """-> (service, evidence) when the CNAME is an unclaimed service name."""
    lower = (body or "").lower()
    for service, pattern, markers in TAKEOVER_SERVICES:
        if not pattern.search(cname or ""):
            continue
        for marker in markers:
            if marker.lower() in lower:
                return service, marker
    return None, None


def _resolves(name):
    if not name:
        return False
    try:
        socket.getaddrinfo(name, None)
        return True
    except OSError:
        return False


# --- category checks -------------------------------------------------------

def _check_recon(result, host):
    dns_host = scope_guard.host_of(host) or host
    try:
        _canonical, aliases, ips = socket.gethostbyname_ex(dns_host)
        result.note("DNS: %s -> %s%s" % (
            dns_host, ", ".join(ips[:8]) or "no addresses",
            " (aliases: %s)" % ", ".join(aliases[:5]) if aliases else ""))
    except OSError as exc:
        result.note("DNS lookup failed for %s: %s" % (dns_host, exc))
        return

    subfinder = shutil.which("subfinder")
    if not subfinder:
        result.note("subfinder is not installed; only the apex DNS record was checked")
        return
    if not result.budget.left():
        return
    result.budget.record("subfinder -d %s -silent" % dns_host, note="subprocess")
    try:
        done = subprocess.run(
            [subfinder, "-d", dns_host, "-silent", "-timeout", "10"],
            capture_output=True, text=True, timeout=25)
    except Exception as exc:
        result.note("subfinder did not complete: %s" % exc)
        return
    names = []
    for line in (done.stdout or "").splitlines():
        name = line.strip().lower().rstrip(".")
        if not name or name == dns_host:
            continue
        allowed, _reason = scope_guard.check(name)
        if not allowed:
            continue
        if name not in names:
            names.append(name)
    for name in names[:80]:
        result.asset("subdomain", name, "subfinder")
    result.note("subfinder returned %d in-scope name(s)" % len(names))


def _check_info_disclosure(result, host):
    # profile_target already makes the nine ordinary GETs used by the Target
    # Check panel, and it is scope-checked. Reuse it instead of a second scan.
    profile = surface.profile_target(host)
    for req in profile.get("requests") or []:
        result.budget.requests.append(req)
    if not profile.get("ok"):
        result.note("surface check failed: %s" % (profile.get("error") or "no response"))
        return

    for exposure in profile.get("exposures") or []:
        if exposure.get("severity") not in ("high", "medium"):
            continue
        path = exposure.get("path")
        result.finding(
            "Exposed %s on %s" % (path, host),
            "confirmed",
            profile.get("base_url", "https://" + host) + path,
            "GET %s returned %s: %s" % (path, exposure.get("status"), exposure.get("note")),
            "curl -s %s%s" % (profile.get("base_url", "https://" + host), path),
        )

    signals = {s["id"]: s["detail"] for s in profile.get("signals") or []}
    if "stack_trace" in signals:
        result.finding(
            "Verbose error output on %s" % host, "likely",
            profile.get("final_url") or profile.get("base_url"),
            signals["stack_trace"],
            "curl -s %s" % (profile.get("final_url") or profile.get("base_url")),
        )
    if "directory_listing" in signals:
        result.finding(
            "Directory listing enabled on %s" % host, "confirmed",
            profile.get("final_url") or profile.get("base_url"),
            signals["directory_listing"],
            "curl -s %s" % (profile.get("final_url") or profile.get("base_url")),
        )
    if "sourcemap" in signals:
        result.finding(
            "Source map referenced by %s" % host, "dig",
            profile.get("final_url") or profile.get("base_url"),
            signals["sourcemap"],
            "curl -s %s | grep sourceMappingURL" % (profile.get("final_url") or profile.get("base_url")),
        )
    robots = profile.get("robots") or {}
    if robots.get("interesting"):
        result.finding(
            "robots.txt discloses sensitive paths on %s" % host, "dig",
            profile.get("base_url", "https://" + host) + "/robots.txt",
            "robots.txt points at: %s" % ", ".join(robots["interesting"][:8]),
            "curl -s %s/robots.txt" % profile.get("base_url", "https://" + host),
        )
    # Keep the technologies and suggested categories visible in the log even
    # though the lead already stores the full profile in meta.json.
    techs = ", ".join(t["name"] for t in profile.get("technologies") or []) or "no stack"
    result.note("surface: %s; %d request(s)" % (techs, len(profile.get("requests") or [])))


def _check_csrf_cors(result, host):
    base, root = _base(result, host)
    if not root:
        result.note("no HTTP response; CORS/clickjacking checks skipped")
        return

    headers = root.get("headers") or {}
    acao = (headers.get("access-control-allow-origin") or "").strip()
    acac = (headers.get("access-control-allow-credentials") or "").strip().lower()
    if acao.lower() == PROBE_ORIGIN and acac == "true":
        result.finding(
            "CORS reflects arbitrary Origin with credentials on %s" % host,
            "confirmed", root.get("url") or base,
            "Origin: %s -> Access-Control-Allow-Origin: %s, "
            "Access-Control-Allow-Credentials: true" % (PROBE_ORIGIN, acao),
            "curl -sI -H 'Origin: %s' %s" % (PROBE_ORIGIN, base),
        )
    elif acao == "*" and acac == "true":
        result.finding(
            "CORS wildcard is combined with credentials on %s" % host,
            "likely", root.get("url") or base,
            "Access-Control-Allow-Origin: * and "
            "Access-Control-Allow-Credentials: true",
            "curl -sI -H 'Origin: %s' %s" % (PROBE_ORIGIN, base),
        )

    # `Origin: null` is what a sandboxed iframe sends; reflecting it with
    # credentials is the same bug class as reflecting any other origin.
    null_obs = _get(result, base, extra_headers={"Origin": "null"}, note="origin-null")
    if null_obs:
        nh = null_obs.get("headers") or {}
        if (nh.get("access-control-allow-origin") or "").strip().lower() == "null" and \
                (nh.get("access-control-allow-credentials") or "").strip().lower() == "true":
            result.finding(
                "CORS trusts the null Origin on %s" % host, "confirmed",
                null_obs.get("url") or base,
                "Origin: null -> Access-Control-Allow-Origin: null with credentials",
                "curl -sI -H 'Origin: null' %s" % base,
            )

    csp = (headers.get("content-security-policy") or "").lower()
    if not headers.get("x-frame-options") and "frame-ancestors" not in csp:
        result.finding(
            "No frame protection (clickjacking) on %s" % host, "likely",
            root.get("url") or base,
            "no X-Frame-Options header and no CSP frame-ancestors directive",
            "curl -sI %s" % base,
        )

    body = root.get("body") or ""
    post_forms = [f for f in surface.FORM_RE.findall(body)
                  if re.search(r'method=["\']?post', f, re.I)]
    if post_forms and not re.search(
            r"csrf|authenticity_token|__requestverificationtoken", body, re.I):
        result.finding(
            "POST form without a CSRF token on %s" % host, "likely",
            root.get("url") or base,
            "%d POST form(s) on the landing page have no visible CSRF token"
            % len(post_forms),
            "manual: capture the form POST, replay it without the token",
        )


def _check_redirect(result, host):
    base, root = _base(result, host)
    if not root:
        result.note("no HTTP response; redirect checks skipped")
        return
    body = root.get("body") or ""
    candidates, seen = [], set()
    for raw in surface.HREF_RE.findall(body)[:400]:
        link = html.unescape(raw.replace("&amp;", "&"))
        try:
            parts = urllib.parse.urlsplit(link)
        except ValueError:
            continue
        for key in urllib.parse.parse_qs(parts.query):
            key_l = key.lower()
            if key_l in surface.REDIRECT_PARAMS and (parts.path or "/", key_l) not in seen:
                seen.add((parts.path or "/", key_l))
                candidates.append((parts.path or "/", key_l))
    for path, param in REDIRECT_CANDIDATES:
        if (path, param) not in seen:
            seen.add((path, param))
            candidates.append((path, param))

    tested = 0
    for path, param in candidates:
        if tested >= 6 or not result.budget.left():
            break
        url = _with_raw_param(base + path, param, REDIRECT_PAYLOAD)
        obs = _get(result, url, follow=False)
        tested += 1
        if not obs:
            continue
        location = (obs.get("headers") or {}).get("location") or ""
        if obs.get("status") in (301, 302, 303, 307, 308) and redirect_location(location):
            result.finding(
                "Open redirect via %s on %s%s" % (param, host, path),
                "confirmed", url,
                "%s answered %s with Location: %s"
                % (urllib.parse.urlsplit(url).path, obs.get("status"), location),
                "curl -sI '%s'" % url,
                param=param, payload=REDIRECT_PAYLOAD,
            )
            break
    result.note("redirect check: %d candidate parameter(s) tested" % tested)


def _candidate_params(body):
    """(path, param) pairs advertised by links and inputs, search-ish first."""
    pairs, seen = [], set()
    for raw in surface.HREF_RE.findall(body or "")[:400]:
        link = html.unescape(raw.replace("&amp;", "&"))
        try:
            parts = urllib.parse.urlsplit(link)
        except ValueError:
            continue
        for key in urllib.parse.parse_qs(parts.query):
            key_l = key.lower()
            if key_l in surface.SEARCH_PARAMS and (parts.path or "/", key_l) not in seen:
                seen.add((parts.path or "/", key_l))
                pairs.append((parts.path or "/", key_l))
    for tag in surface.INPUT_RE.findall(body or "")[:200]:
        match = re.search(r'name=["\']([^"\']+)', tag, re.I)
        if not match:
            continue
        key_l = match.group(1).lower()
        if key_l in surface.SEARCH_PARAMS and ("/", key_l) not in seen:
            seen.add(("/", key_l))
            pairs.append(("/", key_l))
    return pairs


def _check_xss(result, host):
    base, root = _base(result, host)
    if not root:
        result.note("no HTTP response; reflection checks skipped")
        return
    candidates = _candidate_params(root.get("body") or "")[:4]
    for candidate in XSS_CANDIDATES:
        if candidate not in candidates and len(candidates) < 4:
            candidates.append(candidate)

    token = "%x" % int(time.time())
    marker = "huntx%s" % token[-6:]
    payload = marker + '<svg/onload=alert(1)>'
    tested = 0
    for path, param in candidates[:4]:
        if not result.budget.left():
            break
        url = _with_param(base + path, param, payload)
        obs = _get(result, url)
        tested += 1
        if not obs or obs.get("status") not in (200, 201):
            continue
        body = obs.get("body") or ""
        if payload not in body:
            continue
        idx = body.find(payload)
        snippet = re.sub(r"\s+", " ", body[max(0, idx - 60):idx + len(payload) + 60])
        result.finding(
            "Raw HTML reflection in %s on %s%s" % (param, host, path),
            "likely", url,
            "payload returned unencoded in a %s response: …%s…"
            % (obs.get("status"), snippet),
            "dalfox url '%s'" % _with_param(base + path, param, "test"),
            param=param, payload=payload,
        )
    result.note("reflection check: %d parameter(s) tested" % tested)


def _check_js_audit(result, host):
    base, root = _base(result, host)
    if not root:
        result.note("no HTTP response; JavaScript audit skipped")
        return
    body = root.get("body") or ""
    scripts, seen = [], set()
    for raw in SCRIPT_RE.findall(body):
        url = _absolute(base, html.unescape(raw))
        if url in seen:
            continue
        seen.add(url)
        scripts.append(url)
        if len(scripts) >= 6:
            break
    if not scripts:
        result.note("landing page loads no external JavaScript file")

    for url in scripts:
        allowed, _reason = scope_guard.check(url)
        if not allowed:
            result.note("script skipped (out of scope): %s" % url)
            continue
        obs = _get(result, url)
        if not obs or obs.get("status") != 200:
            continue
        text = obs.get("body") or ""
        found = scan_js_text(text)
        for endpoint in found["endpoints"][:40]:
            absolute = _absolute(base, endpoint)
            allowed, _reason = scope_guard.check(absolute)
            if allowed:
                result.asset("url", absolute, "js:%s" % url.rsplit("/", 1)[-1][:60])

        if found["secrets"]:
            kinds = ", ".join(s["kind"] for s in found["secrets"])
            samples = ", ".join("%s=%s" % (s["kind"], s["value"])
                                for s in found["secrets"][:3])
            result.finding(
                "Potential credential material in JavaScript on %s" % host,
                "likely", url,
                "%s found in %s (%s); value redacted" % (kinds, url, samples),
                "curl -s %s | trufflehog stdin --no-update" % url,
            )

        map_match = SOURCE_MAP_RE.search(text)
        if map_match:
            map_url = _absolute(base, map_match.group(1).strip())
            allowed, _reason = scope_guard.check(map_url)
            if allowed:
                map_obs = _get(result, map_url)
                if map_obs and map_obs.get("status") == 200 and \
                        (map_obs.get("body") or "").lstrip().startswith("{"):
                    result.finding(
                        "Source map is publicly readable on %s" % host,
                        "likely", map_url,
                        "%s returned a JSON source map (%d bytes)"
                        % (map_url, len(map_obs.get("body") or "")),
                        "curl -s %s" % map_url,
                    )
    result.note("JavaScript audit: %d file(s) fetched" % len(scripts))


def _check_api_diff(result, host):
    base, _root = _base(result, host)
    found_spec = False
    for path in SPEC_PATHS:
        if not result.budget.left():
            break
        obs = _get(result, base + path)
        if not obs or obs.get("status") != 200:
            continue
        body = obs.get("body") or ""
        content_type = (obs.get("headers") or {}).get("content-type") or ""
        if "json" not in content_type.lower() and not body.lstrip().startswith("{"):
            continue
        try:
            spec = json.loads(body)
        except ValueError:
            continue
        if not isinstance(spec, dict) or not (
                "openapi" in spec or "swagger" in spec or "paths" in spec):
            continue
        found_spec = True
        paths = list((spec.get("paths") or {}).keys())
        result.finding(
            "API specification exposed on %s" % host, "dig",
            base + path,
            "%s documents %d path(s), e.g. %s"
            % (path, len(paths), ", ".join(paths[:6]) or "none"),
            "curl -s %s | jq '.paths | keys'" % (base + path),
        )
        for api_path in paths[:40]:
            result.asset("url", base + api_path, "openapi:%s" % path)
        break
    if not found_spec:
        result.note("no OpenAPI/Swagger document answered at the common paths")

    introspection = json.dumps({
        "query": "query{__schema{types{name}}}"
    }).encode("utf-8")
    obs = _get(result, base + "/graphql", data=introspection)
    body = (obs or {}).get("body") or ""
    if obs and obs.get("status") == 200 and '"__schema"' in body:
        result.finding(
            "GraphQL introspection is enabled on %s" % host, "dig",
            base + "/graphql",
            "POST /graphql with an introspection query returned a schema",
            "curl -s -X POST %s/graphql -H 'Content-Type: application/json' "
            "-d '{\"query\":\"{__schema{types{name}}}\"}'" % base,
        )
    elif obs and obs.get("status") == 200 and '"__typename"' in body:
        result.note("GraphQL endpoint answered an anonymous __typename query")


def _check_takeover(result, host):
    dns_host = scope_guard.host_of(host) or host
    cnames = cname_candidates(dns_host)
    if cnames:
        result.note("CNAME chain: %s" % ", ".join(cnames[:6]))
    else:
        result.note("no CNAME records found for %s" % dns_host)

    base, root = _base(result, host)
    body = (root or {}).get("body") or ""
    for cname in cnames[:6]:
        service, marker = takeover_match(cname, body)
        if service and root:
            result.finding(
                "Subdomain takeover: %s points at an unclaimed %s name"
                % (host, service), "confirmed", root.get("url") or base,
                "CNAME %s -> %s; the HTTP response contains %r"
                % (dns_host, cname, marker),
                "dig +short CNAME %s; curl -sI %s" % (dns_host, base),
            )
            return
        if service and not _resolves(cname):
            result.finding(
                "Subdomain takeover: %s has a dangling %s CNAME"
                % (host, service), "likely", base,
                "CNAME %s -> %s does not resolve and matches an unclaimed "
                "%s pattern" % (dns_host, cname, service),
                "dig +short CNAME %s; dig +short %s" % (dns_host, cname),
            )
            return
    if cnames:
        result.note("CNAME target(s) resolve or are not a known claimable service")


# --- public entry point ----------------------------------------------------

def run(category, host, task_desc=None):
    """Run the real checks for one category. Never raises.

    Returns findings/assets/notes/requests. Findings have demo=False. An
    unknown or manual category returns notes only — the worker still finishes
    honestly instead of inventing output.
    """
    result = Result(category, host, task_desc)
    if not host:
        result.note("no target host supplied; nothing to check")
        return result.as_dict()

    allowed, reason = scope_guard.check(host)
    if not allowed:
        result.note("BLOCKED BY SCOPE: " + reason)
        return result.as_dict()
    if reason:
        result.note(reason)

    check = {
        "recon": _check_recon,
        "info_disclosure": _check_info_disclosure,
        "csrf_cors": _check_csrf_cors,
        "redirect": _check_redirect,
        "xss": _check_xss,
        "js_audit": _check_js_audit,
        "api_diff": _check_api_diff,
        "subdomain_takeover": _check_takeover,
    }.get(category)

    if check is None:
        note = MANUAL.get(category)
        if note:
            result.note("manual category — " + note)
        else:
            result.note("no automated check for category %r" % (category,))
        return result.as_dict()

    try:
        check(result, host)
    except Exception as exc:              # one check must never kill a hunt
        result.note("check aborted: %s: %s" % (type(exc).__name__, exc))
    return result.as_dict()
