#!/usr/bin/env python3
"""surface.py — what is this target made of, and which bug classes fit it?

Before a hunt spends an hour on payloads, it is worth two seconds asking what
the target actually is. A WordPress site and a GraphQL-only API fail in very
different ways, and the dashboard should say so instead of running all eighteen
categories against everything.

This module does exactly three things:

  1. make a small number of ordinary GET requests to the target (root page,
     robots.txt, sitemap.xml, a few well-known exposure paths),
  2. read the responses for technology and configuration signals,
  3. map those signals onto the dashboard's task categories, with a confidence
     and the evidence that produced it.

It is not a scanner. Every request goes through scope_guard, redirects are
checked before they are followed, nothing is brute-forced, and the request list
is returned so the user can see exactly what was touched. The analysis half
(`analyze`) is pure and is unit-tested by selftest.py without any network.
"""

import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

import common
import scope_guard

USER_AGENT = "hunt-dashboard-profiler/1.0 (in-scope surface check)"
PROBE_ORIGIN = "https://probe.invalid"
TIMEOUT = 6
MAX_BODY = 200_000
MAX_SECONDS = 25

# Paths that are cheap to ask for and tell you a lot when they answer. All are
# plain GETs of public URLs; a 404 is the normal, boring outcome.
PROBES = [
    ("robots",        "/robots.txt"),
    ("sitemap",       "/sitemap.xml"),
    ("git_head",      "/.git/HEAD"),
    ("dotenv",        "/.env"),
    ("server_status", "/server-status"),
    ("actuator_env",  "/actuator/env"),
    ("graphql",       "/graphql?query=%7B__typename%7D"),
    ("security_txt",  "/.well-known/security.txt"),
]

# --- signal -> task category map -------------------------------------------
# Weight is per signal: 3 = strong, 2 = meaningful, 1 = weak hint. A category's
# confidence is the sum of the weights of everything pointing at it.
HIGH, MED, LOW = 3, 2, 1

SIGNALS = {
    "wordpress": {
        "label": "WordPress",
        "cats": [("xss", HIGH), ("info_disclosure", HIGH), ("injection", MED),
                 ("file_upload", MED), ("auth_session", MED)],
    },
    "drupal": {
        "label": "Drupal",
        "cats": [("injection", MED), ("file_upload", MED),
                 ("access_control", MED), ("info_disclosure", MED)],
    },
    "joomla": {
        "label": "Joomla",
        "cats": [("injection", MED), ("xss", MED), ("access_control", MED)],
    },
    "magento": {
        "label": "Magento",
        "cats": [("injection", MED), ("business_logic", MED), ("access_control", MED)],
    },
    "shopify": {
        "label": "Shopify",
        "cats": [("api_diff", MED), ("business_logic", LOW)],
    },
    "php": {
        "label": "PHP",
        "cats": [("injection", HIGH), ("file_upload", MED),
                 ("deserialization", MED), ("info_disclosure", MED)],
    },
    "aspnet": {
        "label": "ASP.NET",
        "cats": [("deserialization", HIGH), ("injection", MED),
                 ("auth_session", MED), ("info_disclosure", MED)],
    },
    "java": {
        "label": "Java",
        "cats": [("deserialization", HIGH), ("injection", MED),
                 ("access_control", MED), ("info_disclosure", MED)],
    },
    "spring": {
        "label": "Spring Boot",
        "cats": [("deserialization", HIGH), ("info_disclosure", HIGH),
                 ("injection", MED), ("access_control", MED)],
    },
    "express": {
        "label": "Express/Node",
        "cats": [("deserialization", HIGH), ("xss", MED),
                 ("ssrf", MED), ("access_control", MED)],
    },
    "nextjs": {
        "label": "Next.js",
        "cats": [("js_audit", HIGH), ("api_diff", MED), ("ssrf", LOW)],
    },
    "nuxt": {"label": "Nuxt", "cats": [("js_audit", HIGH), ("api_diff", LOW)]},
    "react": {"label": "React", "cats": [("js_audit", MED)]},
    "angular": {"label": "Angular", "cats": [("js_audit", MED), ("xss", LOW)]},
    "vue": {"label": "Vue", "cats": [("js_audit", MED)]},
    "jquery": {"label": "jQuery", "cats": [("xss", LOW)]},
    "django": {
        "label": "Django",
        "cats": [("csrf_cors", MED), ("injection", MED), ("info_disclosure", MED)],
    },
    "rails": {
        "label": "Ruby on Rails",
        "cats": [("deserialization", MED), ("injection", MED), ("access_control", MED)],
    },
    "laravel": {
        "label": "Laravel",
        "cats": [("injection", MED), ("deserialization", MED), ("info_disclosure", MED)],
    },
    "api_json": {
        "label": "JSON API",
        "cats": [("api_diff", HIGH), ("access_control", HIGH),
                 ("jwt_crypto", MED), ("rate_limiting", MED), ("injection", LOW)],
    },
    "graphql": {
        "label": "GraphQL",
        "cats": [("api_diff", HIGH), ("access_control", HIGH),
                 ("injection", MED), ("info_disclosure", MED)],
    },
    "openapi": {
        "label": "OpenAPI/Swagger",
        "cats": [("api_diff", HIGH), ("access_control", MED), ("injection", MED)],
    },
    "jwt": {
        "label": "JWT in use",
        "cats": [("jwt_crypto", HIGH), ("auth_session", HIGH), ("access_control", MED)],
    },
    "login": {
        "label": "login form",
        "cats": [("auth_session", HIGH), ("access_control", MED),
                 ("csrf_cors", MED), ("rate_limiting", HIGH)],
    },
    "upload": {
        "label": "file upload form",
        "cats": [("file_upload", HIGH), ("injection", LOW)],
    },
    "redirect_param": {"label": "redirect parameter", "cats": [("redirect", HIGH)]},
    "ssrf_param": {"label": "URL-fetch parameter", "cats": [("ssrf", HIGH)]},
    "object_param": {
        "label": "object-id parameter",
        "cats": [("access_control", HIGH), ("business_logic", LOW)],
    },
    "search_param": {
        "label": "search/query parameter",
        "cats": [("injection", MED), ("xss", MED)],
    },
    "csrf_missing": {"label": "POST form without CSRF token", "cats": [("csrf_cors", HIGH)]},
    "cors_reflect": {"label": "CORS reflects arbitrary origin", "cats": [("csrf_cors", HIGH)]},
    "cors_wildcard": {"label": "CORS wildcard", "cats": [("csrf_cors", MED)]},
    "clickjacking": {"label": "no frame protection", "cats": [("csrf_cors", HIGH)]},
    "no_csp": {"label": "no Content-Security-Policy", "cats": [("xss", MED)]},
    "directory_listing": {"label": "directory listing", "cats": [("info_disclosure", HIGH)]},
    "exposed_git": {"label": "exposed .git", "cats": [("info_disclosure", HIGH)]},
    "exposed_env": {"label": "exposed .env", "cats": [("info_disclosure", HIGH)]},
    "actuator": {
        "label": "open Spring actuator",
        "cats": [("info_disclosure", HIGH), ("access_control", MED)],
    },
    "server_status": {"label": "server-status exposed", "cats": [("info_disclosure", MED)]},
    "stack_trace": {
        "label": "verbose error output",
        "cats": [("info_disclosure", HIGH), ("injection", MED)],
    },
    "waf": {"label": "WAF/CDN in front", "cats": [("http_smuggling", LOW)]},
    "sourcemap": {"label": "source maps shipped", "cats": [("js_audit", HIGH)]},
    "cookie_no_httponly": {
        "label": "cookie without HttpOnly",
        "cats": [("xss", MED), ("auth_session", MED)],
    },
    "cookie_no_secure": {"label": "cookie without Secure", "cats": [("auth_session", LOW)]},
    "robots_admin": {
        "label": "robots.txt points at admin paths",
        "cats": [("access_control", MED), ("info_disclosure", MED)],
    },
    "robots_api": {"label": "robots.txt points at API paths", "cats": [("api_diff", MED)]},
    "upload_path": {"label": "upload path advertised", "cats": [("file_upload", MED)]},
}

TECH_PATTERNS = [
    # (signal, regex, technology name, source kind)
    ("wordpress", r"wp-content|wp-includes|/wp-json|wp-emoji", "WordPress", "body"),
    ("drupal", r"Drupal\.settings|/sites/default/files|X-Drupal-Cache", "Drupal", "body"),
    ("joomla", r"Joomla!|/media/jui/|/components/com_", "Joomla", "body"),
    ("magento", r"Mage\.Cookies|/skin/frontend/|/static/version\d+/frontend", "Magento", "body"),
    ("shopify", r"cdn\.shopify\.com|Shopify\.theme", "Shopify", "body"),
    ("nextjs", r"__NEXT_DATA__|/_next/static/|x-nextjs-cache", "Next.js", "body"),
    ("nuxt", r"__NUXT__|/_nuxt/", "Nuxt", "body"),
    ("angular", r'ng-version="|ng-app=|<app-root', "Angular", "body"),
    ("react", r"data-reactroot|react-dom\.production|__REACT_DEVTOOLS", "React", "body"),
    ("vue", r"data-v-[0-9a-f]{6,}|vue(\.runtime)?\.min\.js", "Vue", "body"),
    ("django", r"csrfmiddlewaretoken", "Django", "body"),
    ("rails", r"authenticity_token|_rails", "Ruby on Rails", "body"),
    ("laravel", r"laravel_session|XSRF-TOKEN", "Laravel", "cookie"),
    ("aspnet", r"__VIEWSTATE|__EVENTVALIDATION|ASP\.NET", "ASP.NET", "body"),
    ("java", r"javax\.faces|JSF|Whitelabel Error Page|X-Application-Context", "Java", "body"),
    ("spring", r"Whitelabel Error Page|/actuator/|spring-boot", "Spring Boot", "body"),
    ("php", r"PHPSESSID|X-Powered-By:\s*PHP", "PHP", "header"),
    ("express", r"X-Powered-By:\s*Express", "Express/Node", "header"),
    ("openapi", r"swagger-ui|Swagger UI|openapi\.json|/v3/api-docs", "OpenAPI/Swagger", "body"),
    ("graphql", r"/graphql|graphql-", "GraphQL", "body"),
    ("jquery", r"jquery(?:-[\d.]+)?(?:\.min)?\.js", "jQuery", "body"),
]

GENERATOR_RE = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.I)
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
VERSION_RE = re.compile(r"([A-Za-z][A-Za-z0-9 ._-]{1,30})[/ ]v?([0-9]+(?:\.[0-9]+)+)")
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
HREF_RE = re.compile(r'(?:href|src|action)=["\']([^"\']+)["\']', re.I)
INPUT_RE = re.compile(r"<input[^>]*>", re.I)
FORM_RE = re.compile(r"<form[^>]*>", re.I)
LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)
DISALLOW_RE = re.compile(r"^\s*(?:Disallow|Allow)\s*:\s*(\S+)", re.I | re.M)

REDIRECT_PARAMS = {
    "url", "uri", "next", "redirect", "redirect_uri", "redirect_url", "return",
    "returnurl", "return_url", "dest", "destination", "continue", "to", "target",
    "rurl", "redir", "out", "view", "link", "forward", "goto",
}
SSRF_PARAMS = {
    "url", "uri", "src", "source", "image", "img", "file", "path", "page",
    "fetch", "proxy", "callback", "webhook", "host", "domain", "dest", "feed",
    "avatar", "thumbnail", "load", "site", "target", "u",
}
OBJECT_PARAMS = {
    "id", "uid", "user_id", "userid", "account", "account_id", "order", "order_id",
    "item", "item_id", "doc", "doc_id", "file_id", "pid", "mid", "cid", "aid",
    "invoice", "basket", "profile", "tenant", "org", "group",
}
SEARCH_PARAMS = {
    "q", "s", "search", "query", "keyword", "keywords", "term", "filter",
    "name", "email", "username", "user", "comment", "message",
}


# --- fetching --------------------------------------------------------------

class _ScopedRedirect(urllib.request.HTTPRedirectHandler):
    """Follow redirects only while they stay in scope."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        allowed, reason = scope_guard.check(newurl)
        if not allowed:
            raise urllib.error.HTTPError(
                newurl, code, "redirect blocked by scope: %s" % reason, headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Leave 3xx responses alone so the caller can inspect Location."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _request(url, follow=True, data=None, extra_headers=None):
    """One request. HTTP error statuses are returned as a response, not raised.

    `follow=False` + a 3xx response is how checks.py reads redirect targets
    without ever fetching the (possibly out-of-scope) destination.
    `extra_headers` lets a check override the probe Origin (e.g. `null`).
    """
    started = time.time()
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/json,text/plain;q=0.8,*/*;q=0.5",
        "Accept-Encoding": "identity",
        "Origin": PROBE_ORIGIN,
    }
    headers.update(extra_headers or {})
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers)
    opener = urllib.request.build_opener(
        _ScopedRedirect() if follow else _NoRedirect())
    try:
        with opener.open(req, timeout=TIMEOUT) as resp:
            body = resp.read(MAX_BODY).decode("utf-8", "replace")
            return {
                "url": resp.geturl(),
                "status": int(resp.status),
                "headers": {k.lower(): v for k, v in resp.headers.items()},
                "cookies": resp.headers.get_all("Set-Cookie") or [],
                "body": body,
                "error": None,
                "ms": int((time.time() - started) * 1000),
            }
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(MAX_BODY).decode("utf-8", "replace")
        except Exception:
            body = ""
        headers = {k.lower(): v for k, v in (exc.headers.items() if exc.headers else [])}
        return {
            "url": getattr(exc, "url", url),
            "status": int(exc.code),
            "headers": headers,
            "cookies": (exc.headers.get_all("Set-Cookie") or []) if exc.headers else [],
            "body": body,
            "error": None,
            "ms": int((time.time() - started) * 1000),
        }
    except (urllib.error.URLError, ssl.SSLError, OSError, ValueError) as exc:
        reason = getattr(exc, "reason", exc)
        return {
            "url": url, "status": None, "headers": {}, "cookies": [],
            "body": "", "error": "%s: %s" % (type(exc).__name__, reason),
            "ms": int((time.time() - started) * 1000),
        }


def _origin(url):
    parts = urllib.parse.urlsplit(url)
    return "%s://%s" % (parts.scheme, parts.netloc)


def fetch_surface(target):
    """Make the probe requests and return a raw observation dict."""
    started = time.time()
    raw = (target or "").strip()
    if "://" in raw:
        candidates = [raw]
    else:
        candidates = ["https://" + raw, "http://" + raw]

    root = None
    attempts = []
    for candidate in candidates:
        obs = _request(candidate)
        attempts.append({"url": candidate, "status": obs["status"], "error": obs["error"]})
        if obs["status"] is not None:
            root = obs
            break
        if time.time() - started > MAX_SECONDS:
            break

    observation = {
        "target": target,
        "base_url": _origin(root["url"]) if root else candidates[0],
        "root": root,
        "attempts": attempts,
        "probes": {},
        "requests": list(attempts),
        "notes": [],
    }
    if root is None:
        observation["notes"].append("target did not answer over http or https")
        return observation

    if len(attempts) > 1 and attempts[0]["url"].startswith("https://") \
            and root["url"].startswith("http://"):
        observation["notes"].append("https failed; profiled over plain http")

    base = observation["base_url"]
    for name, path in PROBES:
        if time.time() - started > MAX_SECONDS:
            observation["notes"].append("request budget reached; some probes were skipped")
            break
        obs = _request(base + path)
        observation["probes"][name] = obs
        observation["requests"].append(
            {"url": obs["url"], "status": obs["status"], "error": obs["error"]})
    return observation


# --- analysis --------------------------------------------------------------

def _add_tech(techs, name, version, source, confidence="high"):
    key = name.lower()
    for tech in techs:
        if tech["name"].lower() == key:
            if version and not tech.get("version"):
                tech["version"] = version
            return
    techs.append({"name": name, "version": version or None,
                  "source": source, "confidence": confidence})


def _ver(text):
    m = VERSION_RE.search(text or "")
    return m.group(2) if m else None


def _cookie_names(cookies):
    names = []
    for raw in cookies or []:
        first = raw.split(";", 1)[0]
        if "=" in first:
            names.append(first.split("=", 1)[0].strip())
    return names


def _interesting_robots(entries):
    admin = ("admin", "manage", "internal", "private", "backup", "config",
             "staging", "dev", "test", "debug", "old", "secret")
    api = ("api", "graphql", "rest", "v1", "v2", "swagger")
    found_admin = [e for e in entries if any(w in e.lower() for w in admin)]
    found_api = [e for e in entries if any(w in e.lower() for w in api)]
    return found_admin[:10], found_api[:10]


def analyze(observation):
    """Turn raw responses into technologies, exposures and likely categories."""
    root = observation.get("root")
    result = {
        "ok": bool(root and root.get("status") is not None),
        "error": None,
        "target": observation.get("target"),
        "base_url": observation.get("base_url"),
        "final_url": root.get("url") if root else None,
        "status": root.get("status") if root else None,
        "title": None,
        "server": None,
        "technologies": [],
        "headers": {},
        "security": {},
        "exposures": [],
        "robots": {"found": False, "entries": [], "interesting": []},
        "params": {"redirect": [], "ssrf": [], "object": [], "search": []},
        "signals": [],
        "categories": [],
        "notes": list(observation.get("notes") or []),
        "requests": observation.get("requests") or [],
        "checked_at": common.now_iso(),
    }
    if root is None:
        result["error"] = "no HTTP response from the target"
        return result
    if root.get("error"):
        result["error"] = root["error"]
        return result

    headers = root.get("headers") or {}
    body = root.get("body") or ""
    lower_body = body.lower()
    result["headers"] = {
        k: headers.get(k) for k in
        ("server", "x-powered-by", "content-type", "x-generator",
         "x-aspnet-version", "via", "cf-ray", "x-cache", "location")
        if headers.get(k)
    }
    result["server"] = headers.get("server")
    result["status"] = root.get("status")

    m = TITLE_RE.search(body)
    if m:
        result["title"] = re.sub(r"\s+", " ", m.group(1)).strip()[:200]

    techs = result["technologies"]
    signals = []

    def signal(kind, detail):
        if not any(s["id"] == kind for s in signals):
            signals.append({"id": kind, "detail": detail})

    # Server / framework headers.
    server = (headers.get("server") or "").lower()
    for word, name in (("nginx", "nginx"), ("apache", "Apache"), ("iis", "IIS"),
                       ("litespeed", "LiteSpeed"), ("caddy", "Caddy"),
                       ("openresty", "OpenResty"), ("gunicorn", "Gunicorn"),
                       ("uvicorn", "Uvicorn"), ("kestrel", "Kestrel")):
        if word in server:
            _add_tech(techs, name, _ver(headers.get("server", "")), "header")
    powered = headers.get("x-powered-by") or ""
    for word, name in (("php", "PHP"), ("express", "Express/Node"),
                       ("asp.net", "ASP.NET"), ("servlet", "Java"),
                       ("next.js", "Next.js")):
        if word in powered.lower():
            _add_tech(techs, name, _ver(powered), "header")
            signal({"php": "php", "express": "express", "asp.net": "aspnet",
                    "servlet": "java", "next.js": "nextjs"}[word],
                   "X-Powered-By: %s" % powered)
    if headers.get("x-aspnet-version") or headers.get("x-aspnetmvc-version"):
        _add_tech(techs, "ASP.NET", headers.get("x-aspnet-version"), "header")
        signal("aspnet", "ASP.NET version header present")
    if headers.get("x-generator"):
        _add_tech(techs, headers["x-generator"].split()[0], _ver(headers["x-generator"]), "header")
    if headers.get("x-drupal-cache") or headers.get("x-drupal-dynamic-cache"):
        _add_tech(techs, "Drupal", None, "header")
        signal("drupal", "Drupal cache header present")
    if headers.get("x-shopify-stage"):
        _add_tech(techs, "Shopify", None, "header")
        signal("shopify", "Shopify stage header present")
    if "cloudflare" in server or headers.get("cf-ray"):
        _add_tech(techs, "Cloudflare", None, "header")
        signal("waf", "Cloudflare edge in front of the origin")
    if headers.get("x-sucuri-id"):
        _add_tech(techs, "Sucuri", None, "header")
        signal("waf", "Sucuri edge in front of the origin")
    if headers.get("x-akamai-transformed") or "akamai" in server:
        _add_tech(techs, "Akamai", None, "header")
        signal("waf", "Akamai edge in front of the origin")
    if "cloudfront" in (headers.get("x-cache") or "").lower() or \
            "cloudfront" in (headers.get("via") or "").lower():
        _add_tech(techs, "CloudFront", None, "header")
        signal("waf", "CloudFront CDN in front of the origin")

    # Cookies.
    cookies = root.get("cookies") or []
    cookie_names = _cookie_names(cookies)
    cookie_lookup = {n.lower(): n for n in cookie_names}
    if "phpsessid" in cookie_lookup:
        _add_tech(techs, "PHP", None, "cookie")
        signal("php", "PHPSESSID cookie")
    if "jsessionid" in cookie_lookup:
        _add_tech(techs, "Java", None, "cookie")
        signal("java", "JSESSIONID cookie")
    if "asp.net_sessionid" in cookie_lookup or any(
            n.lower().startswith(".aspnetcore.") for n in cookie_names):
        _add_tech(techs, "ASP.NET", None, "cookie")
        signal("aspnet", "ASP.NET session cookie")
    if "laravel_session" in cookie_lookup:
        _add_tech(techs, "Laravel", None, "cookie")
        signal("laravel", "laravel_session cookie")
    if "csrftoken" in cookie_lookup:
        _add_tech(techs, "Django", None, "cookie")
        signal("django", "csrftoken cookie")
    if "connect.sid" in cookie_lookup:
        _add_tech(techs, "Express/Node", None, "cookie")
        signal("express", "connect.sid cookie")
    if "_session_id" in cookie_lookup or any(
            n.lower().startswith("_rails") for n in cookie_names):
        _add_tech(techs, "Ruby on Rails", None, "cookie")
        signal("rails", "Rails session cookie")

    # Body fingerprints.
    for kind, pattern, name, source in TECH_PATTERNS:
        haystack = body if source != "header" else "\n".join(
            "%s: %s" % (k, v) for k, v in headers.items())
        if re.search(pattern, haystack, re.I):
            _add_tech(techs, name, None, source)
            if kind in SIGNALS:
                signal(kind, "%s fingerprint in %s" % (name, source))

    # Generator meta gives a version more reliably than a regex on the body.
    gen = GENERATOR_RE.search(body)
    if gen:
        value = gen.group(1).strip()
        for key, name in (("wordpress", "WordPress"), ("drupal", "Drupal"),
                          ("joomla", "Joomla"), ("typo3", "TYPO3")):
            if key in value.lower():
                _add_tech(techs, name, _ver(value), "meta generator")
                signal(key if key != "typo3" else "php", value[:80])

    # JSON API / GraphQL.
    content_type = (headers.get("content-type") or "").lower()
    stripped = body.lstrip()
    if "application/json" in content_type or stripped[:1] in ("{", "["):
        if "text/html" not in content_type:
            _add_tech(techs, "JSON API", None, "response")
            signal("api_json", "response is JSON, not HTML")
    graphql_probe = (observation.get("probes") or {}).get("graphql") or {}
    if graphql_probe.get("status") == 200 and '"__typename"' in (graphql_probe.get("body") or ""):
        _add_tech(techs, "GraphQL", None, "probe")
        signal("graphql", "/graphql answered a typename query")

    # Auth, uploads, CSRF.
    if re.search(r'type=["\']?password', body, re.I) or "name=\"password" in lower_body:
        signal("login", "password field on the landing page")
    if re.search(r'type=["\']?file', body, re.I) or "multipart/form-data" in lower_body:
        signal("upload", "file input / multipart form")
    post_forms = [f for f in FORM_RE.findall(body) if re.search(r'method=["\']?post', f, re.I)]
    if post_forms and not re.search(r"csrf|authenticity_token|__requestverificationtoken", lower_body):
        signal("csrf_missing", "POST form without a visible CSRF token")
    if JWT_RE.search(body) or any(JWT_RE.search(c) for c in cookies):
        _add_tech(techs, "JWT", None, "cookie/body")
        signal("jwt", "JWT-shaped token in a cookie or the page")

    # Parameters advertised by links and forms.
    params = result["params"]
    seen = set()
    for raw_link in HREF_RE.findall(body)[:400]:
        link = raw_link.replace("&amp;", "&")
        try:
            query = urllib.parse.urlsplit(link).query
        except ValueError:
            continue
        for key in urllib.parse.parse_qs(query):
            key_l = key.lower()
            if key_l in seen:
                continue
            seen.add(key_l)
            if key_l in REDIRECT_PARAMS and key_l not in params["redirect"]:
                params["redirect"].append(key_l)
            if key_l in SSRF_PARAMS and key_l not in params["ssrf"]:
                params["ssrf"].append(key_l)
            if key_l in OBJECT_PARAMS and key_l not in params["object"]:
                params["object"].append(key_l)
            if key_l in SEARCH_PARAMS and key_l not in params["search"]:
                params["search"].append(key_l)
    for input_tag in INPUT_RE.findall(body)[:200]:
        m = re.search(r'name=["\']([^"\']+)', input_tag, re.I)
        if not m:
            continue
        key_l = m.group(1).lower()
        if key_l in OBJECT_PARAMS and key_l not in params["object"]:
            params["object"].append(key_l)
        if key_l in SEARCH_PARAMS and key_l not in params["search"]:
            params["search"].append(key_l)
    if params["redirect"]:
        signal("redirect_param", "links use %s" % ", ".join(params["redirect"][:5]))
    if params["ssrf"]:
        signal("ssrf_param", "links use %s" % ", ".join(params["ssrf"][:5]))
    if params["object"]:
        signal("object_param", "links/forms use %s" % ", ".join(params["object"][:5]))
    if params["search"]:
        signal("search_param", "links/forms use %s" % ", ".join(params["search"][:5]))

    # Security headers and CORS.
    security = {}
    csp = headers.get("content-security-policy") or ""
    security["csp"] = bool(csp)
    security["hsts"] = bool(headers.get("strict-transport-security"))
    security["x_frame_options"] = bool(headers.get("x-frame-options")) or \
        "frame-ancestors" in csp.lower()
    security["x_content_type_options"] = "nosniff" in (
        headers.get("x-content-type-options") or "").lower()
    security["referrer_policy"] = bool(headers.get("referrer-policy"))
    security["permissions_policy"] = bool(headers.get("permissions-policy"))
    acao = (headers.get("access-control-allow-origin") or "").strip()
    acac = (headers.get("access-control-allow-credentials") or "").strip().lower()
    if acao in ("*",) and acac == "true":
        security["cors"] = "wildcard-with-credentials"
    elif acao in ("*",):
        security["cors"] = "wildcard"
    elif acao and acao.lower() == PROBE_ORIGIN:
        security["cors"] = "reflected"
    elif acao:
        security["cors"] = "fixed-origin"
    else:
        security["cors"] = "none"
    security["cookies_missing_httponly"] = sorted(
        {_cookie_names([c])[0] for c in cookies
         if "httponly" not in c.lower() and _cookie_names([c])})
    security["cookies_missing_secure"] = sorted(
        {_cookie_names([c])[0] for c in cookies
         if "secure" not in c.split(";", 1)[-1].lower() and _cookie_names([c])})
    result["security"] = security

    if security["cors"] == "reflected":
        signal("cors_reflect", "Access-Control-Allow-Origin reflected %s" % PROBE_ORIGIN)
    elif security["cors"] in ("wildcard", "wildcard-with-credentials"):
        signal("cors_wildcard", "Access-Control-Allow-Origin: *")
    if not security["x_frame_options"]:
        signal("clickjacking", "no X-Frame-Options and no CSP frame-ancestors")
    if not security["csp"]:
        signal("no_csp", "no Content-Security-Policy")
    if security["cookies_missing_httponly"]:
        signal("cookie_no_httponly", "cookies: %s"
               % ", ".join(security["cookies_missing_httponly"][:5]))
    if security["cookies_missing_secure"]:
        signal("cookie_no_secure", "cookies: %s"
               % ", ".join(security["cookies_missing_secure"][:5]))
    if not security["hsts"]:
        result["notes"].append("no HSTS header (only meaningful over https)")

    # Exposures.
    probes = observation.get("probes") or {}
    exposures = result["exposures"]

    def exposure(path, status, note, severity):
        exposures.append({"path": path, "status": status,
                          "note": note, "severity": severity})

    robots = probes.get("robots") or {}
    robots_body = robots.get("body") or ""
    if robots.get("status") == 200 and robots_body.strip():
        entries = [e for e in DISALLOW_RE.findall(robots_body) if e != "/"]
        admin, api = _interesting_robots(entries)
        result["robots"] = {"found": True, "entries": entries[:40],
                            "interesting": admin + api}
        exposure("/robots.txt", 200, "%d rules, %d interesting"
                 % (len(entries), len(admin) + len(api)), "info")
        if admin:
            signal("robots_admin", "robots.txt: %s" % ", ".join(admin[:5]))
        if api:
            signal("robots_api", "robots.txt: %s" % ", ".join(api[:5]))
        if any("upload" in e.lower() for e in entries):
            signal("upload_path", "robots.txt advertises an upload path")
    elif robots:
        exposure("/robots.txt", robots.get("status"), "not present", "info")

    sitemap = probes.get("sitemap") or {}
    if sitemap.get("status") == 200 and "<loc>" in (sitemap.get("body") or ""):
        count = len(LOC_RE.findall(sitemap.get("body") or ""))
        exposure("/sitemap.xml", 200, "%d URLs" % count, "info")

    git_probe = probes.get("git_head") or {}
    if git_probe.get("status") == 200 and re.search(
            r"refs?/|^ref:", (git_probe.get("body") or ""), re.M | re.I):
        exposure("/.git/HEAD", 200, "git metadata is readable", "high")
        signal("exposed_git", "/.git/HEAD is readable")

    env_probe = probes.get("dotenv") or {}
    env_body = env_probe.get("body") or ""
    if env_probe.get("status") == 200 and re.search(
            r"(APP_KEY|DB_PASSWORD|SECRET_KEY|AWS_SECRET)", env_body):
        exposure("/.env", 200, "environment file is readable", "high")
        signal("exposed_env", "/.env is readable")

    status_probe = probes.get("server_status") or {}
    if status_probe.get("status") == 200 and "apache server status" in (
            status_probe.get("body") or "").lower():
        exposure("/server-status", 200, "Apache status page", "medium")
        signal("server_status", "/server-status is open")

    actuator = probes.get("actuator_env") or {}
    act_body = actuator.get("body") or ""
    if actuator.get("status") == 200 and (
            '"propertySources"' in act_body or '"activeProfiles"' in act_body):
        exposure("/actuator/env", 200, "Spring environment exposed", "high")
        signal("actuator", "/actuator/env is open")

    security_txt = probes.get("security_txt") or {}
    if security_txt.get("status") == 200 and "contact:" in (
            security_txt.get("body") or "").lower():
        result["notes"].append("security.txt published (mature disclosure process)")

    # Error output / directory listing / source maps.
    if re.search(r"Stack trace|Traceback \(most recent call last\)|"
                 r"Fatal error:|SQLSTATE|You have an error in your SQL syntax|"
                 r"at org\.springframework|java\.lang\.[A-Za-z]+Exception",
                 body, re.I):
        signal("stack_trace", "verbose error text in the landing page")
    if re.search(r"<title>\s*Index of /|Directory listing for", body, re.I):
        signal("directory_listing", "directory listing on the landing page")
    if re.search(r"\.js\.map\b|sourceMappingURL=", body, re.I):
        signal("sourcemap", "source map reference in the page")

    result["signals"] = signals
    result["categories"] = _categories(signals)
    if not result["technologies"]:
        result["notes"].append("no clear framework fingerprint; treat it as custom")
    return result


def _categories(signals):
    scores = {}
    for signal in signals:
        spec = SIGNALS.get(signal["id"])
        if not spec:
            continue
        for category, weight in spec["cats"]:
            entry = scores.setdefault(category, {"score": 0, "reasons": []})
            entry["score"] += weight
            # The signal detail often repeats the label ("no Content-Security-
            # Policy"). Showing "label (detail)" then reads as a stutter, so
            # only add the parenthetical when it carries extra information.
            if signal["detail"] and signal["detail"].lower() != spec["label"].lower():
                entry["reasons"].append("%s (%s)" % (spec["label"], signal["detail"]))
            else:
                entry["reasons"].append(spec["label"])
    out = []
    for category, entry in scores.items():
        if entry["score"] >= 6:
            confidence = "high"
        elif entry["score"] >= 3:
            confidence = "medium"
        else:
            confidence = "low"
        out.append({
            "category": category,
            "confidence": confidence,
            "score": entry["score"],
            "reason": "; ".join(_dedupe(entry["reasons"])[:4]),
        })
    out.sort(key=lambda c: (-c["score"], c["category"]))
    return out


def _dedupe(items):
    seen, out = set(), []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


# --- public entry point ----------------------------------------------------

def profile_target(target, allow_unlisted=False):
    """Scope-check, fetch and analyse one target. Never raises.

    allow_unlisted is used by the dashboard's live plan/profile calls when
    lenient scope is on: a target that is not listed but is also not explicitly
    out of scope may be profiled, without writing scope. It is only honoured
    when the caller proved same-origin intent with X-Hunt-Request; an
    out-of-scope entry still blocks.
    """
    allowed, reason = scope_guard.check(target)
    if not allowed and allow_unlisted:
        if scope_guard.missing_from_scope(target):
            allowed, reason = True, None
    if not allowed:
        return {
            "ok": False,
            "error": "BLOCKED BY SCOPE: " + reason,
            "target": target,
            "categories": [],
            "technologies": [],
            "checked_at": common.now_iso(),
        }
    if common.DEMO_MODE:
        # Demo mode exists to exercise the pipeline without a network. Hitting
        # a real host here would defeat that promise (and surprise the operator
        # who set HUNT_DEMO_MODE=1 precisely to avoid traffic).
        return {
            "ok": False,
            "error": "demo mode: live target checks are disabled; the hunt will "
                     "use the selected/all categories without a profile",
            "target": target,
            "demo": True,
            "categories": [],
            "technologies": [],
            "checked_at": common.now_iso(),
        }
    try:
        observation = fetch_surface(target)
        result = analyze(observation)
    except Exception as exc:              # a profiler must never break a hunt
        return {
            "ok": False,
            "error": "%s: %s" % (type(exc).__name__, exc),
            "target": target,
            "categories": [],
            "technologies": [],
            "checked_at": common.now_iso(),
        }
    if reason:                            # no in-scope list configured
        result["notes"].append(reason)
    result["suggested_categories"] = [c["category"] for c in result["categories"]]
    return result
