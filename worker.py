#!/usr/bin/env python3
"""worker.py — one agent process.

    python worker.py <name> <model> <task_id> <task_description> \
        [--target example.com] [--run 20260101T120000Z] \
        [--category xss] [--role worker] [--tools dalfox,gf]

Writes a heartbeat to state/<name>.json every few steps (the dashboard reads
those), and appends findings + discovered assets to state/runs/<run_id>/.

HUNT_DEMO_MODE=1 keeps the old simulation (useful for exercising the pipeline
with no network). With HUNT_DEMO_MODE=0 the worker calls checks.run(), which
makes a bounded number of real, scope-checked requests and only emits findings
whose evidence is in the response. Categories that need credentials or a
destructive payload return a manual-testing note instead of fiction.

Either way the scaffolding is the same:

  * scope is checked with scope_guard.assert_allowed() before anything runs,
    and every discovered asset is filtered through it
  * findings carry host / url / param / payload / evidence / command plus a
    dedupe key, so they can be reproduced and de-duplicated
  * discovered assets go in their own stream, so two runs can be diffed
"""

import argparse
import os
import random
import sys
import time
import urllib.parse

import checks
import common
import logs
import scope_guard
import toolbox

DEMO_MODE = common.DEMO_MODE  # flip it in common.py, not here

# --- what a demo finding looks like, per task category ----------------------
# Real runs will not use this table at all: it exists so the whole pipeline
# (schema, dedupe, diffing, dashboard) can be exercised with no tools and no
# API keys. Every row is fiction and is flagged demo=true in the output.
FINDINGS = {
    "recon": {
        "title": "Directory listing exposed on {path} of {host}",
        "path": "/backup/", "param": None, "payload": None, "severity": "likely",
        "evidence": "Index of /backup/ returned 200 with a file listing, no auth",
        "command": "ffuf -u https://{host}/FUZZ -w common.txt",
    },
    "js_audit": {
        "title": "Internal API host leaked in bundled JS on {host}",
        "path": "/static/app.bundle.js", "param": None, "payload": None, "severity": "dig",
        "evidence": "sourceMappingURL + api.internal.{host} present in the bundle",
        "command": "curl -s https://{host}/static/app.bundle.js | linkfinder",
    },
    "auth_session": {
        "title": "Password reset token is not invalidated after use on {host}",
        "path": "/account/reset", "param": "token", "payload": None, "severity": "likely",
        "evidence": "same reset link accepted twice, second request changed the password",
        "command": "manual: POST /account/reset twice with one token",
    },
    "access_control": {
        "title": "IDOR: invoice of another account readable via {param} on {host}",
        "path": "/api/v1/invoices/1002", "param": "id", "payload": "1002", "severity": "confirmed",
        "evidence": "account A (id 1001) fetched id 1002 and received account B's invoice PDF",
        "command": "curl -H 'Authorization: Bearer <A>' https://{host}/api/v1/invoices/1002",
    },
    "injection": {
        "title": "Error-based SQLi in {param} on {host}",
        "path": "/api/v1/products", "param": "category", "payload": "1' AND 1=CAST(1 AS int)--",
        "severity": "likely",
        "evidence": "500 + 'syntax error at or near' in the response body",
        "command": "sqlmap -u 'https://{host}/api/v1/products?category=1' --batch --level 2",
    },
    "xss": {
        "title": "Reflected XSS in {param} on {host}{path}",
        "path": "/search", "param": "q",
        "payload": '"><img src=x onerror=alert(document.domain)>',
        "severity": "confirmed",
        "evidence": "payload returned unencoded inside <title> of the 200 response",
        "command": "dalfox url 'https://{host}/search?q=test'",
    },
    "ssrf": {
        "title": "SSRF via {param} on {host} reaches cloud metadata",
        "path": "/api/v1/import", "param": "source_url",
        "payload": "http://169.254.169.254/latest/meta-data/iam/",
        "severity": "confirmed",
        "evidence": "response contained the instance role name from IMDSv1",
        "command": "curl -X POST https://{host}/api/v1/import -d 'source_url=http://169.254.169.254/'",
    },
    "csrf_cors": {
        "title": "CORS reflects arbitrary Origin with credentials on {host}",
        "path": "/api/v1/me", "param": None, "payload": None, "severity": "likely",
        "evidence": "Access-Control-Allow-Origin echoed evil.test + Allow-Credentials: true",
        "command": "curl -H 'Origin: https://evil.test' -I https://{host}/api/v1/me",
    },
    "redirect": {
        "title": "Open redirect via {param} on {host}{path}",
        "path": "/login", "param": "next",
        "payload": "//evil.test", "severity": "likely",
        "evidence": "302 Location: https://evil.test after following the link",
        "command": "curl -sI 'https://{host}/login?next=//evil.test'",
    },
    "api_diff": {
        "title": "Undocumented admin endpoint on {host}",
        "path": "/api/internal/users/export", "param": None, "payload": None, "severity": "dig",
        "evidence": "route exists and returns data, absent from the OpenAPI spec",
        "command": "curl -s https://{host}/openapi.json | jq; curl -s https://{host}/api/internal/users/export",
    },
    "deserialization": {
        "title": "Prototype pollution via {param} on {host}",
        "path": "/api/v1/settings", "param": "__proto__[isAdmin]",
        "payload": "true", "severity": "dig",
        "evidence": "subsequent /api/v1/me returns isAdmin: true for the same session",
        "command": "curl -X PATCH https://{host}/api/v1/settings -d '__proto__[isAdmin]=true'",
    },
    "jwt_crypto": {
        "title": "JWT accepts alg=none on {host}",
        "path": "/api/v1/me", "param": None, "payload": None, "severity": "confirmed",
        "evidence": "token with alg:none and no signature accepted, returns 200",
        "command": "jwt_tool <token> -X a",
    },
    "file_upload": {
        "title": "Upload filter bypassed with a double extension on {host}",
        "path": "/api/v1/avatar", "param": "file", "payload": "shell.php.jpg",
        "severity": "likely",
        "evidence": "file stored as .php and served from /uploads/ as text/html",
        "command": "curl -F 'file=@shell.php.jpg' https://{host}/api/v1/avatar",
    },
    "rate_limiting": {
        "title": "No rate limit on {param} endpoint on {host}",
        "path": "/auth/login", "param": None, "payload": None, "severity": "likely",
        "evidence": "200 consecutive failed logins, no 429, no lockout",
        "command": "ffuf -u https://{host}/auth/login -X POST -d 'u=admin&p=FUZZ' -w pw.txt",
    },
    "info_disclosure": {
        "title": "Stack trace + framework version leaked on {host}",
        "path": "/api/v1/debug", "param": None, "payload": None, "severity": "dig",
        "evidence": "500 body contains a full traceback and the exact dependency versions",
        "command": "curl -s https://{host}/api/v1/debug",
    },
    "business_logic": {
        "title": "Coupon can be applied twice on {host}",
        "path": "/api/v1/cart/coupon", "param": "code", "payload": "WELCOME10",
        "severity": "likely",
        "evidence": "two sequential POSTs both returned 200 and stacked the discount",
        "command": "curl -X POST https://{host}/api/v1/cart/coupon -d 'code=WELCOME10' (x2)",
    },
    "http_smuggling": {
        "title": "CL.TE desync between proxy and origin on {host}",
        "path": "/", "param": None, "payload": "Transfer-Encoding: chunked",
        "severity": "dig",
        "evidence": "smuggled prefix altered the next request's response",
        "command": "python3 smuggling.py https://{host}",
    },
    "subdomain_takeover": {
        "title": "Dangling CNAME to an unclaimed bucket on {host}",
        "path": "/", "param": None, "payload": None, "severity": "likely",
        "evidence": "CNAME -> <bucket>.s3.amazonaws.com returns NoSuchBucket",
        "command": "dig CNAME {host} +short; curl -sI https://{host}",
    },
}

# Demo asset discovery. The last entry is deliberately outside a typical
# in-scope list, so the scope gate has something real to reject.
ASSET_POOL = [
    ("subdomain", "dev.{target}"),
    ("subdomain", "staging.{target}"),
    ("subdomain", "legacy-api.{target}"),
    ("url", "https://dev.{target}/api/v1/"),
    ("url", "https://staging.{target}/admin"),
    ("subdomain", "cdn.third-party-saas.net"),
]


def log_line(name, text):
    os.makedirs(common.LOG_DIR, exist_ok=True)
    path = os.path.join(common.LOG_DIR, name + ".log")
    with open(path, "a", encoding="utf-8") as f:
        f.write("[%s] %s\n" % (common.now_iso(), text))
    try:
        if os.path.getsize(path) > 5 * 1024 * 1024:
            logs.trim(name)
    except OSError:
        pass


def write_heartbeat(name, model, status, task_id, task_desc, findings_count,
                    note="", run_id=None, role="worker", category=None,
                    tools=None):
    data = {
        "name": name,
        "model": model,
        "role": role,
        "status": status,               # LIVE | ON_TASK | BLOCKED
        "task_id": task_id,
        "task_desc": task_desc,
        "category": category,
        "run_id": run_id,
        "findings_count": findings_count,
        "tools": tools or [],
        "last_report_ts": common.now_iso(),
        "note": note,
    }
    try:
        common.atomic_write_json(os.path.join(common.STATE_DIR, name + ".json"), data)
    except OSError as exc:
        # A heartbeat is not worth dying over.
        log_line(name, "heartbeat write failed: %s" % exc)


def resolve_tools(tool_ids):
    """Turn the ids dispatch sent us into {id, bin, installed, ...} records.

    Unknown ids are kept with known=False so the log says so instead of
    silently dropping whatever the user picked.
    """
    resolved = []
    for tool_id in tool_ids or []:
        tool = toolbox.get(tool_id)
        if not tool:
            resolved.append({"id": tool_id, "bin": None, "purpose": None,
                             "known": False, "installed": False,
                             "version": None})
            continue
        status = toolbox.detect(tool_id)
        resolved.append({
            "id": tool_id,
            "bin": tool["bin"],
            "purpose": tool["purpose"],
            "known": True,
            "installed": status["installed"],
            "version": status["version"],
        })
    return resolved


def request_host(target, host):
    """Hostname plus an explicit port, for the checks' HTTP requests.

    scope_guard.host_of() deliberately returns only the hostname (scope is
    about a host, not a port), but a target the user typed as
    `example.com:8080` should be contacted on 8080, not 443.
    """
    raw = (target or "").strip()
    if not raw:
        return host
    candidate = raw if "://" in raw else "//" + raw
    try:
        parts = urllib.parse.urlsplit(candidate)
        port = parts.port
    except ValueError:
        return host
    return host + (":%d" % port if port else "")


def describe_tools(resolved):
    if not resolved:
        return "manual testing — no CLI tool required for this category"
    parts = []
    for tool in resolved:
        if not tool["known"]:
            parts.append("%s(unknown tool id)" % tool["id"])
        elif tool["installed"]:
            parts.append("%s(installed, not executed here)" % tool["bin"])
        else:
            parts.append("%s(NEED INSTALL)" % tool["bin"])
    return ", ".join(parts)


def append_finding(name, run_id, finding):
    finding["run_id"] = run_id
    finding["agent"] = name
    finding["ts"] = common.now_iso()
    finding["dedupe_key"] = common.finding_dedupe_key(finding)
    common.append_jsonl(common.findings_path(run_id), finding)
    return finding["dedupe_key"]


def append_asset(name, run_id, kind, value, source):
    common.append_jsonl(common.assets_path(run_id), {
        "ts": common.now_iso(),
        "run_id": run_id,
        "agent": name,
        "kind": kind,
        "value": value,
        "source": source,
    })


def demo_finding(category, host, task_desc):
    tpl = FINDINGS.get(category)
    if tpl is None:
        return None
    path = tpl["path"] if tpl.get("path") else "/"
    url = "https://%s%s" % (host, path)
    if tpl.get("param") and tpl.get("payload"):
        url += "?%s=%s" % (tpl["param"], tpl["payload"])
    return {
        "title": tpl["title"].format(host=host, path=path, param=tpl.get("param") or ""),
        "severity": tpl["severity"],
        "category": category,
        "host": host,
        "url": url,
        "param": tpl.get("param"),
        "payload": tpl.get("payload"),
        "evidence": tpl["evidence"].replace("{host}", host),
        "command": tpl["command"].replace("{host}", host),
        "task_desc": task_desc,
        "demo": DEMO_MODE,
    }


def run_worker(name, model, task_id, task_desc, target=None, run_id=None,
               category=None, role="worker", tool_ids=None):
    run_id = run_id or common.current_run_id()
    if not run_id:
        log_line(name, "no run id — run dispatch.py instead of calling a worker directly")
        return 1

    log_line(name, "START %s [%s] %s" % (task_id, category or "-", task_desc))
    write_heartbeat(name, model, "ON_TASK", task_id, task_desc, 0,
                    note="starting", run_id=run_id, role=role, category=category)

    if common.stop_requested():
        note = "emergency stop is set — worker did not start any work"
        log_line(name, "STOPPED: " + note)
        write_heartbeat(name, model, "BLOCKED", task_id, task_desc, 0,
                        note=note, run_id=run_id, role=role, category=category)
        return 4

    # ---- toolchain: what this task was told to use, and what is actually here
    resolved_tools = resolve_tools(tool_ids)
    log_line(name, "tools selected: " + describe_tools(resolved_tools))
    log_line(name, "execution: built-in bounded checks in checks.py; catalog "
                   "tools are for the manual follow-up, and are never claimed "
                   "as executed")
    for tool in resolved_tools:
        if tool["known"] and not tool["installed"]:
            log_line(name, "NEED INSTALL %s — %s"
                     % (tool["id"], toolbox.get(tool["id"])["install"]))

    # With simulation off, a task whose tools are all absent must not pretend
    # to have scanned anything. Refuse it loudly instead.
    if not DEMO_MODE and resolved_tools and not any(t["installed"] for t in resolved_tools):
        note = "no installed tool for this task: " + ", ".join(
            t["bin"] or t["id"] for t in resolved_tools)
        log_line(name, "BLOCKED: " + note)
        write_heartbeat(name, model, "BLOCKED", task_id, task_desc, 0,
                        note=note, run_id=run_id, role=role, category=category,
                        tools=resolved_tools)
        return 3

    # ---- scope gate: nothing below runs against an unapproved host --------
    host = None
    if target:
        try:
            host = scope_guard.assert_allowed(target)
        except scope_guard.ScopeError as exc:
            log_line(name, "BLOCKED by scope: %s" % exc)
            write_heartbeat(name, model, "BLOCKED", task_id, task_desc, 0,
                            note="blocked by scope: %s" % exc,
                            run_id=run_id, role=role, category=category,
                            tools=resolved_tools)
            return 2
    # ----------------------------------------------------------------------

    findings = 0
    seen = set()

    if DEMO_MODE:
        # ---------------- SIMULATE WORK (HUNT_DEMO_MODE=1) ----------------
        steps = random.randint(3, 6)
        for i in range(steps):
            if common.stop_requested():
                log_line(name, "STOPPED by operator at step %d/%d" % (i + 1, steps))
                write_heartbeat(name, model, "BLOCKED", task_id, task_desc,
                                findings, note="stopped by operator",
                                run_id=run_id, role=role, category=category,
                                tools=resolved_tools)
                return 4
            time.sleep(random.uniform(2, 5))

            # Assets first: this is what the run-to-run diff is built from.
            if category in (None, "recon", "js_audit", "api_diff", "subdomain_takeover"):
                kind, template = random.choice(ASSET_POOL)
                value = template.format(target=host or "example.com")
                try:
                    scope_guard.assert_allowed(value)
                except scope_guard.ScopeError as exc:
                    log_line(name, "skipped asset (out of scope): %s" % exc)
                else:
                    append_asset(name, run_id, kind, value, source=category or "recon")
                    log_line(name, "asset: %s (%s)" % (value, kind))

            write_heartbeat(name, model, "LIVE", task_id, task_desc, findings,
                            note="step %d/%d" % (i + 1, steps),
                            run_id=run_id, role=role, category=category,
                            tools=resolved_tools)
            log_line(name, "step %d/%d complete" % (i + 1, steps))

            if host and random.random() < 0.35:
                finding = demo_finding(category, host, task_desc)
                if finding:
                    key = common.finding_dedupe_key(finding)
                    if key in seen:
                        log_line(name, "duplicate finding, not counted: %s" % finding["title"])
                    else:
                        seen.add(key)
                        append_finding(name, run_id, finding)
                        findings += 1
                        log_line(name, "FINDING (%s): %s"
                                 % (finding["severity"], finding["title"]))
        # ------------------------------------------------------------------
    else:
        # ---------------- REAL, BOUNDED CHECKS (HUNT_DEMO_MODE=0) ----------
        write_heartbeat(name, model, "ON_TASK", task_id, task_desc, findings,
                        note="running real %s checks" % (category or "manual"),
                        run_id=run_id, role=role, category=category,
                        tools=resolved_tools)
        if common.stop_requested():
            log_line(name, "STOPPED before checks — no request sent")
            write_heartbeat(name, model, "BLOCKED", task_id, task_desc, findings,
                            note="stopped by operator before running checks",
                            run_id=run_id, role=role, category=category,
                            tools=resolved_tools)
            return 4
        result = checks.run(category, request_host(target, host), task_desc)
        for note in result.get("notes") or []:
            log_line(name, "note: " + note)

        for asset in result.get("assets") or []:
            value = (asset.get("value") or "").strip()
            if not value:
                continue
            try:
                scope_guard.assert_allowed(value)
            except scope_guard.ScopeError as exc:
                log_line(name, "skipped asset (out of scope): %s" % exc)
                continue
            kind = asset.get("kind") or "url"
            append_asset(name, run_id, kind, value,
                         source=asset.get("source") or category or "check")
            log_line(name, "asset: %s (%s)" % (value, kind))

        for finding in result.get("findings") or []:
            key = common.finding_dedupe_key(finding)
            if key in seen:
                log_line(name, "duplicate finding, not counted: %s" % finding["title"])
                continue
            seen.add(key)
            append_finding(name, run_id, finding)
            findings += 1
            log_line(name, "FINDING (%s): %s"
                     % (finding["severity"], finding["title"]))

        for request in result.get("requests") or []:
            if request.get("error"):
                log_line(name, "request failed: %s — %s"
                         % (request.get("url"), request.get("error")))

        write_heartbeat(name, model, "LIVE", task_id, task_desc, findings,
                        note="real checks complete: %d finding(s), %d asset(s)"
                             % (findings, len(result.get("assets") or [])),
                        run_id=run_id, role=role, category=category,
                        tools=resolved_tools)
        # ------------------------------------------------------------------

    write_heartbeat(name, model, "LIVE", task_id, task_desc, findings,
                    note="task complete, awaiting next dispatch",
                    run_id=run_id, role=role, category=category,
                    tools=resolved_tools)
    log_line(name, "DONE %s: %d findings" % (task_id, findings))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="one hunt agent process")
    parser.add_argument("name")
    parser.add_argument("model")
    parser.add_argument("task_id")
    parser.add_argument("task_desc", nargs="+")
    parser.add_argument("--target", default=None)
    parser.add_argument("--run", dest="run_id", default=None)
    parser.add_argument("--category", default=None)
    parser.add_argument("--role", default="worker")
    parser.add_argument("--tools", default="",
                        help="comma-separated tool ids chosen on the Tools tab")
    args = parser.parse_args(argv)

    name = common.safe_agent_name(args.name)
    if not name:
        print("invalid agent name: %r" % args.name, file=sys.stderr)
        return 1
    if args.run_id:
        try:
            common.safe_run_id(args.run_id)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 1

    tool_ids = [t.strip() for t in (args.tools or "").split(",") if t.strip()]

    return run_worker(
        name, args.model, args.task_id, " ".join(args.task_desc),
        target=args.target, run_id=args.run_id,
        category=args.category, role=args.role, tool_ids=tool_ids,
    )


if __name__ == "__main__":
    sys.exit(main())
