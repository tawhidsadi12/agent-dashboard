#!/usr/bin/env python3
"""selftest.py — dependency-free checks for the parts that are easy to get
wrong: scope matching, run diffing, and the tool catalog. No Flask, no network,
no state touched outside a temp directory.

    python selftest.py

Exits non-zero if anything fails. Run this after editing scope_guard.py,
common.py or toolbox.py — it is faster than starting a hunt and noticing later.
"""

import os
import shutil
import sys
import tempfile

import checks
import common
import dispatch
import logs
import methods
import planning
import scope_guard
import surface
import toolbox
import worker

failures = []


def check(label, condition):
    print(("ok   " if condition else "FAIL ") + label)
    if not condition:
        failures.append(label)


def scope(in_scope, out_scope=None):
    return {"in_scope": in_scope, "out_scope": out_scope or []}


# --- scope matching --------------------------------------------------------
S = scope(["example.com"], ["payments.example.com"])
check("apex is in scope", scope_guard.check("example.com", S)[0])
check("subdomain inherits scope", scope_guard.check("dev.example.com", S)[0])
check("url form is understood", scope_guard.check("https://dev.example.com:8443/a?b=1", S)[0])
check("lookalike domain is blocked", not scope_guard.check("evilexample.com", S)[0])
check("out-of-scope beats in-scope", not scope_guard.check("payments.example.com", S)[0])
check("unlisted domain is blocked", not scope_guard.check("other.test", S)[0])
check("wildcard entry works", scope_guard.check("a.example.com", scope(["*.example.com"]))[0])
check("cidr entry works", scope_guard.check("10.1.2.3", scope(["10.0.0.0/8"]))[0])
check("ip outside cidr is blocked", not scope_guard.check("11.1.2.3", scope(["10.0.0.0/8"]))[0])
check("empty scope is fail-closed", not scope_guard.check("anything.test", scope([]))[0])
check("empty scope can be allowed explicitly for offline previews",
      scope_guard.check("anything.test", scope([]), allow_empty=True)[0])
check("junk target is rejected", not scope_guard.check("", S)[0])

check("empty scope adopts the submitted target",
      scope_guard.adopt_if_empty("https://www.example.com/x?y=1", scope([])) == "www.example.com")
check("an existing in-scope list is never replaced",
      scope_guard.adopt_if_empty("other.test", S) is None)
check("an out-of-scope host is not adopted",
      scope_guard.adopt_if_empty("payments.example.com",
                                 scope([], ["payments.example.com"])) is None)
check("a host that is already in scope is not adopted twice",
      scope_guard.adopt_if_empty("example.com", S) is None)
check("junk is never adopted", scope_guard.adopt_if_empty("", scope([])) is None)
check("a new target is missing from scope",
      scope_guard.missing_from_scope("new.test", S) == "new.test")
check("a listed target is not missing",
      scope_guard.missing_from_scope("example.com", S) is None)
check("an excluded target is never missing",
      scope_guard.missing_from_scope("payments.example.com", S) is None)

try:
    scope_guard.assert_allowed("payments.example.com", S)
    check("assert_allowed raises on out-of-scope", False)
except scope_guard.ScopeError:
    check("assert_allowed raises on out-of-scope", True)

# --- authorization gate ----------------------------------------------------
# The gate is a setting, not a fixed rule. Exercise both states without
# touching the real data directory.
settings_dir = tempfile.mkdtemp(prefix="hunt-settings-")
old_settings_path, old_auth_env = common.SETTINGS_PATH, common.AUTH_ENV
common.SETTINGS_PATH = os.path.join(settings_dir, "settings.json")
common.AUTH_ENV = None
check("authorization is optional by default", common.auth_required() is False)
check("the authorization gate is not pinned by default",
      common.auth_required_locked() is False)
common.save_auth_required(True)
check("the authorization gate can be enabled", common.auth_required() is True)
common.AUTH_ENV = "0"
check("HUNT_REQUIRE_AUTH=0 pins the gate off", common.auth_required() is False)
common.AUTH_ENV = "1"
check("HUNT_REQUIRE_AUTH=1 pins the gate on", common.auth_required() is True)
check("a pinned gate reports as locked", common.auth_required_locked() is True)
common.SETTINGS_PATH, common.AUTH_ENV = old_settings_path, old_auth_env
shutil.rmtree(settings_dir, ignore_errors=True)

# --- scope mode ------------------------------------------------------------
# Lenient by default: an unlisted target is added at hunt start. Strict mode
# makes the list authoritative. Both are settings with an env pin.
settings_dir = tempfile.mkdtemp(prefix="hunt-settings-")
old_settings_path, old_auth_env = common.SETTINGS_PATH, common.AUTH_ENV
old_scope_env = common.SCOPE_ENV
common.SETTINGS_PATH = os.path.join(settings_dir, "settings.json")
common.AUTH_ENV = None
common.SCOPE_ENV = None
check("scope is lenient by default", common.strict_scope() is False)
check("the scope mode is not pinned by default",
      common.strict_scope_locked() is False)
common.save_strict_scope(True)
check("scope can be made strict", common.strict_scope() is True)
common.save_auth_required(True)
check("settings merge instead of overwriting each other",
      common.strict_scope() is True and common.auth_required() is True)
common.SCOPE_ENV = "0"
check("HUNT_STRICT_SCOPE=0 pins lenient", common.strict_scope() is False)
common.SCOPE_ENV = "1"
check("HUNT_STRICT_SCOPE=1 pins strict", common.strict_scope() is True)
check("a pinned scope mode reports as locked", common.strict_scope_locked() is True)
common.SETTINGS_PATH, common.AUTH_ENV = old_settings_path, old_auth_env
common.SCOPE_ENV = old_scope_env
shutil.rmtree(settings_dir, ignore_errors=True)

# --- run history, dedupe, diff --------------------------------------------
tmp = tempfile.mkdtemp(prefix="hunt-selftest-")
original_runs_dir = common.RUNS_DIR
common.RUNS_DIR = tmp
try:
    run_a, run_b = "20260101T000000Z", "20260102T000000Z"
    for rid in (run_a, run_b):
        os.makedirs(os.path.join(tmp, rid))

    # a.example.com was already known; new.example.com appeared in run B
    common.append_jsonl(common.assets_path(run_a), {"value": "a.example.com", "kind": "subdomain"})
    common.append_jsonl(common.assets_path(run_b), {"value": "a.example.com", "kind": "subdomain"})
    common.append_jsonl(common.assets_path(run_b), {"value": "new.example.com", "kind": "subdomain"})

    diff = common.diff_runs(run_a, run_b)
    check("diff reports only the new asset",
          [a["value"] for a in diff["assets"]["added"]] == ["new.example.com"])
    check("diff does not call a stable asset removed", diff["assets"]["removed"] == [])
    check("diff counts both assets", diff["assets"]["total"] == 2)

    finding = {"host": "a.example.com", "url": "https://a.example.com/x",
               "param": "q", "title": "Reflected XSS", "severity": "confirmed"}
    common.append_jsonl(common.findings_path(run_b), finding)
    common.append_jsonl(common.findings_path(run_b), dict(finding))
    deduped = common.dedupe_findings(common.read_jsonl(common.findings_path(run_b)))
    check("dedupe collapses a repeated finding", len(deduped) == 1)
    check("dedupe remembers it was seen twice", deduped[0]["dup_count"] == 2)
    check("dedupe key is stable for the same finding",
          common.finding_dedupe_key(finding) == deduped[0]["dedupe_key"])
    check("dedupe ignores per-request marker values",
          common.finding_dedupe_key(
              {"host": "a.example.com", "url": "https://a.example.com/s?q=marker-a",
               "param": "q", "title": "Raw HTML reflection"}) ==
          common.finding_dedupe_key(
              {"host": "a.example.com", "url": "https://a.example.com/s?q=marker-b",
               "param": "q", "title": "Raw HTML reflection"}))
    check("dedupe keeps different sinks apart",
          common.finding_dedupe_key(
              {"host": "a.example.com", "url": "https://a.example.com/s?q=1",
               "param": "q", "title": "Reflection"}) !=
          common.finding_dedupe_key(
              {"host": "a.example.com", "url": "https://a.example.com/s?next=1",
               "param": "next", "title": "Reflection"}))

    # a run with no predecessor diffs against nothing
    first = common.diff_runs(None, run_a)
    check("first run reports all assets as new", len(first["assets"]["added"]) == 1)
finally:
    common.RUNS_DIR = original_runs_dir
    shutil.rmtree(tmp, ignore_errors=True)

# --- path safety ----------------------------------------------------------
check("agent name cannot escape state/", common.safe_agent_name("../../evil") is None)
check("normal agent name is accepted", common.safe_agent_name("worker-glm") == "worker-glm")

# --- tool catalog ---------------------------------------------------------
check("tool ids are unique", len(toolbox.TOOLS) == len(toolbox._RAW))
check("every tool belongs to a known stage",
      all(t["purpose"] in toolbox.PURPOSE_IDS for t in toolbox.TOOLS.values()))
check("every tool points at a github repo",
      all(t["repo"].startswith("https://github.com/") and t["slug"] for t in toolbox.TOOLS.values()))
check("every stage has at least one tool",
      all(toolbox.tools_in(pid) for pid in toolbox.PURPOSE_IDS))
check("every stage has exactly one default",
      all(sum(1 for t in toolbox.tools_in(pid) if t["default"]) == 1
          for pid in toolbox.PURPOSE_IDS))
check("alternatives never include the tool itself",
      all(tid not in toolbox.alternatives(tid) for tid in toolbox.TOOLS))
check("alternatives cover the rest of the stage",
      all(len(toolbox.alternatives(tid)) == len(toolbox.tools_in(toolbox.TOOLS[tid]["purpose"])) - 1
          for tid in toolbox.TOOLS))
check("every tool has an install command",
      all(t["install"].strip() for t in toolbox.TOOLS.values()))

# The catalog is only useful if the image actually bakes in each stage default.
def _installer_text():
    tools_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools")
    parts = []
    for name in sorted(os.listdir(tools_dir)):
        if name.endswith(".sh"):
            with open(os.path.join(tools_dir, name), encoding="utf-8") as fh:
                parts.append(fh.read())
    return "\n".join(parts)

_checkout_installers = _installer_text().lower()
check("every stage default is named by an installer script",
      all(toolbox.default_for(pid).lower() in _checkout_installers
          for pid in toolbox.PURPOSE_IDS))
check("checkout hints only reference catalogued tools",
      all(tid in toolbox.TOOLS for tid in toolbox.CHECK_DIRS))
check("every dashboard category has a tool plan",
      all(c in toolbox.CATEGORY_NEEDS for c in dispatch.TASK_CATEGORIES))
check("tool plans only reference known stages",
      all(pid in toolbox.PURPOSE_IDS
          for needs in toolbox.CATEGORY_NEEDS.values() for pid in needs))
check("an unknown category needs no tools", toolbox.tools_for_category("nope") == [])

# --- dispatch scheduling ---------------------------------------------------
check("a round covers every queued task",
      sum(len(w) for w in dispatch.split_waves(list(range(5)), 3)) == 5)
check("a wave never exceeds the worker count",
      all(len(w) <= 3 for w in dispatch.split_waves(list(range(5)), 3)))
check("split_waves preserves order",
      dispatch.split_waves([1, 2, 3, 4], 2) == [[1, 2], [3, 4]])
check("split_waves is safe when no workers are configured",
      dispatch.split_waves([1, 2], 0) == [[1], [2]])

# --- target surface profiler ----------------------------------------------
# analyze() is pure: feed it a synthetic observation, no network involved.

def observation(body="", headers=None, cookies=None, probes=None):
    return {
        "target": "example.com",
        "base_url": "https://example.com",
        "root": {"url": "https://example.com/", "status": 200,
                 "headers": headers or {}, "cookies": cookies or [],
                 "body": body, "error": None},
        "probes": probes or {},
        "requests": [],
        "notes": [],
    }

check("every profiler signal maps to real task categories",
      all(cat in dispatch.TASK_CATEGORIES
          for spec in surface.SIGNALS.values() for cat, _ in spec["cats"]))
check("every body pattern names a known signal",
      all(kind in surface.SIGNALS for kind, _, _, _ in surface.TECH_PATTERNS))

wp = surface.analyze(observation(
    body='<html><head><title>Demo</title>'
         '<meta name="generator" content="WordPress 6.5">'
         '<script src="/wp-includes/js/jquery/jquery.min.js"></script></head>'
         '<body><a href="/go?url=https://x.test&amp;id=42&amp;q=hi">go</a>'
         '<form method="post"><input name="user">'
         '<input type="password" name="pass"></form></body></html>',
    headers={"server": "nginx/1.24.0", "x-powered-by": "PHP/8.2.1"},
    cookies=["PHPSESSID=abc"],
    probes={"git_head": {"url": "https://example.com/.git/HEAD", "status": 200,
                         "headers": {}, "cookies": [], "error": None,
                         "body": "ref: refs/heads/main"}},
))
wp_cats = {c["category"] for c in wp["categories"]}
check("profiler recognises nginx/PHP/WordPress",
      {"nginx", "PHP", "WordPress"} <= {t["name"] for t in wp["technologies"]})
check("profiler maps WordPress to XSS/injection work",
      {"xss", "injection", "info_disclosure"} <= wp_cats)
check("profiler maps a login form to auth/rate-limit work",
      {"auth_session", "rate_limiting"} <= wp_cats)
check("profiler maps url/id/q parameters to SSRF/IDOR/injection",
      {"ssrf", "access_control", "redirect"} <= wp_cats)
check("profiler reports an exposed .git as high severity",
      any(e["path"] == "/.git/HEAD" and e["severity"] == "high"
          for e in wp["exposures"]))
check("profiler category confidence is high/medium/low",
      all(c["confidence"] in ("high", "medium", "low") for c in wp["categories"]))

api = surface.analyze(observation(
    body='{"token":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop"}',
    headers={"content-type": "application/json",
             "access-control-allow-origin": surface.PROBE_ORIGIN,
             "access-control-allow-credentials": "true"},
))
api_cats = {c["category"] for c in api["categories"]}
check("profiler sees a JSON API", "api_json" in {s["id"] for s in api["signals"]})
check("profiler sees a JWT", "jwt" in {s["id"] for s in api["signals"]})
check("profiler flags reflected CORS",
      api["security"]["cors"] == "reflected" and "csrf_cors" in api_cats)
check("profiler maps a JSON API to api_diff/IDOR",
      {"api_diff", "access_control"} <= api_cats)

down = surface.analyze({"target": "example.com", "base_url": "https://example.com",
                        "root": None, "probes": {}, "requests": [], "notes": []})
check("profiler reports a dead target instead of raising", down["ok"] is False)
check("profiler suggests at most one category per name",
      len({c["category"] for c in wp["categories"]}) == len(wp["categories"]))
check("profiler reasons do not repeat the label",
      all("no Content-Security-Policy (no Content-Security-Policy)" not in c["reason"]
          for c in wp["categories"]))

# --- real checks (pure helpers; no network) --------------------------------
check("every automated check maps to a real task category",
      all(c in dispatch.TASK_CATEGORIES for c in
          ("recon", "info_disclosure", "csrf_cors", "redirect", "xss",
           "js_audit", "api_diff", "subdomain_takeover")))
check("every manual category has an explanation",
      all(c in checks.MANUAL for c in dispatch.TASK_CATEGORIES
          if c not in ("recon", "info_disclosure", "csrf_cors", "redirect",
                       "xss", "js_audit", "api_diff", "subdomain_takeover")))

js = checks.scan_js_text(
    'fetch("/api/v1/users?active=1");'
    'var k = "AKIAABCDEFGHIJKLMNOP";'
    'var img = "/static/logo.png";')
check("JS scan finds API endpoints", "/api/v1/users?active=1" in js["endpoints"])
check("JS scan ignores static assets", "/static/logo.png" not in js["endpoints"])
check("JS scan finds an AWS key", any(s["kind"] == "AWS access key" for s in js["secrets"]))
check("JS scan redacts the credential",
      js["secrets"] and "AKIAABCDEFGHIJKLMNOP" not in js["secrets"][0]["value"])

check("redirect detector accepts a protocol-relative escape",
      checks.redirect_location("//example.invalid/login"))
check("redirect detector accepts an absolute escape",
      checks.redirect_location("https://example.invalid/login"))
check("redirect detector ignores a same-site path",
      not checks.redirect_location("/dashboard"))
check("redirect detector ignores the same host",
      not checks.redirect_location("https://example.com/dashboard"))
check("raw redirect parameter keeps the double slash readable",
      checks._with_raw_param("https://x.test/go", "url", "//example.invalid/")
      == "https://x.test/go?url=//example.invalid/")

service, marker = checks.takeover_match(
    "old-bucket.s3.amazonaws.com",
    "<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist")
check("takeover fingerprint matches an unclaimed S3 bucket",
      service == "Amazon S3" and marker == "NoSuchBucket")
check("takeover fingerprint ignores a normal S3 response",
      checks.takeover_match("assets.s3.amazonaws.com", "<html>ok</html>") == (None, None))

manual = checks.run("auth_session", "example.com")
check("a manual category returns notes, not findings",
      manual["findings"] == [] and manual["notes"])
check("a manual category makes no requests", manual["requests"] == [])
check("the checks entry point never needs a host",
      checks.run("recon", None)["findings"] == [])
check("the request host keeps an explicit port",
      worker.request_host("example.com:8080", "example.com") == "example.com:8080")
check("the request host ignores scheme and path",
      worker.request_host("https://app.example.com/x?y=1", "app.example.com")
      == "app.example.com")

# selection round-trip, isolated from the real tools.json
tmp_tools = tempfile.mkdtemp(prefix="hunt-tools-")
original_selection_path = toolbox.SELECTION_PATH
toolbox.SELECTION_PATH = os.path.join(tmp_tools, "tools.json")
try:
    stage_id = toolbox.PURPOSE_IDS[0]
    pick = toolbox.tools_in(stage_id)[-1]["id"]
    saved = toolbox.save_selection({stage_id: pick})
    check("selection round-trips through tools.json", saved.get(stage_id) == pick)
    check("saved selection is read back", toolbox.selected_for(stage_id) == pick)
    check("untouched stages fall back to their default",
          toolbox.selected_for("xss") == toolbox.default_for("xss"))

    try:
        toolbox.save_selection({"xss": "nuclei"})
        check("selection rejects a tool from another stage", False)
    except ValueError:
        check("selection rejects a tool from another stage", True)

    try:
        toolbox.save_selection({"not_a_stage": "ffuf"})
        check("selection rejects an unknown stage", False)
    except ValueError:
        check("selection rejects an unknown stage", True)

    check("tools_for_category follows the saved selection",
          toolbox.tools_for_category("xss") == [toolbox.selected_for("xss")])
finally:
    toolbox.SELECTION_PATH = original_selection_path
    shutil.rmtree(tmp_tools, ignore_errors=True)

# detection-dependent views, with the probe replaced so this stays offline
original_detect = toolbox.detect
original_is_installed = toolbox.is_installed
original_load_selection = toolbox.load_selection
toolbox.detect = lambda tool_id, refresh=False: {
    "installed": True, "version": "selftest", "path": "/bin/%s" % tool_id}
toolbox.is_installed = lambda tool_id: True
toolbox.load_selection = lambda: {}
try:
    stages = toolbox.purpose_view()
    check("purpose_view returns every stage", len(stages) == len(toolbox.PURPOSE_IDS))
    check("every stage has a selected tool", all(s["selected"] for s in stages))
    check("the selected tool is flagged inside its stage",
          all(any(t["id"] == s["selected"] and t["selected"] for t in s["tools"])
              for s in stages))
    check("stages list the categories that need them",
          all(isinstance(s["needed_by"], list) for s in stages))

    full = toolbox.summary(stages=stages)
    check("summary counts the whole catalog", full["catalogued"] == len(toolbox.TOOLS))
    check("summary reports nothing missing when all probes succeed",
          full["installed"] == full["selected_total"] and full["missing"] == [])

    toolbox.is_installed = lambda tool_id: tool_id == "ffuf"
    missing = toolbox.missing_for_categories(["xss"])
    check("missing tools are reported for a category",
          [m["id"] for m in missing] == [toolbox.default_for("xss")])
    check("a missing tool carries its install command",
          all(m["install"] and m["repo"] for m in missing))
finally:
    toolbox.detect = original_detect
    toolbox.is_installed = original_is_installed
    toolbox.load_selection = original_load_selection

# a git-checkout tool counts as present when its clone exists
original_which = toolbox.shutil.which
original_isdir = toolbox.os.path.isdir
toolbox.shutil.which = lambda name: None
toolbox.os.path.isdir = lambda path: path.replace("\\", "/").endswith("SecLists")
try:
    check("a checkout-based tool is detected from its directory",
          toolbox._probe(toolbox.get("seclists"))["installed"])
    check("a tool with no binary and no checkout is missing",
          not toolbox._probe(toolbox.get("ffuf"))["installed"])
finally:
    toolbox.shutil.which = original_which
    toolbox.os.path.isdir = original_isdir

# --- methodology playbooks -------------------------------------------------
check("every hunting category has a playbook",
      set(methods.METHODS) == set(dispatch.TASK_CATEGORIES))
check("playbooks are structurally complete", methods.validate() == [])
check("every playbook explains what evidence is needed",
      all(m.get("evidence") for m in methods.METHODS.values()))
check("every playbook names at least one pitfall",
      all(m.get("pitfalls") for m in methods.METHODS.values()))
check("the automated set matches checks.run()",
      set(methods.AUTOMATED) == {"recon", "info_disclosure", "csrf_cors",
                                 "redirect", "xss", "js_audit", "api_diff",
                                 "subdomain_takeover"})
check("commands are grouped by step",
      all(set(c) == {"step", "command"} for c in methods.commands_for("recon")))

# --- ranked hunt plan ------------------------------------------------------
plan = planning.build_plan("example.com")
check("a plan without a profile still has steps", bool(plan["steps"]))
check("plan steps only use real categories",
      all(s["category"] in dispatch.TASK_CATEGORIES for s in plan["steps"]))
check("plan is sorted by descending score",
      all(plan["steps"][i]["score"] >= plan["steps"][i + 1]["score"]
          for i in range(len(plan["steps"]) - 1)))
check("plan starts with recon when nothing is known",
      plan["steps"][0]["category"] == "recon")
check("plan marks the eight scripted categories as automated",
      set(plan["automated"]) <= set(methods.AUTOMATED))
check("plan marks manual categories as manual",
      all(not s["automated"] for s in plan["steps"]
          if s["category"] not in methods.AUTOMATED))

xp = {"ok": True, "categories": [
    {"category": "xss", "confidence": "high", "reason": "reflected search box"}],
    "params": {"search": ["q"]}, "forms": ["/search"], "cookies": ["sid"]}
xplan = planning.build_plan("example.com", xp)
check("a high-confidence profile outranks the baseline",
      xplan["steps"][0]["category"] == "xss")
check("the plan keeps the evidence for its ranking",
      "reflected search box" in xplan["steps"][0]["reason"])

nsp = {"ok": True, "categories": [
    {"category": "xss", "confidence": "low", "reason": "no Content-Security-Policy"}],
    "security": {"csp": False}}
nsplan = planning.build_plan("example.com", nsp)
xss_step = [s for s in nsplan["steps"] if s["category"] == "xss"][0]
check("the plan states a missing CSP once",
      xss_step["reason"].lower().count("csp") +
      xss_step["reason"].lower().count("content-security-policy") == 1)

# --- log management --------------------------------------------------------
tmp_logs = tempfile.mkdtemp(prefix="hunt-logs-")
old_log_dir, old_audit_path = common.LOG_DIR, logs.AUDIT_PATH
common.LOG_DIR = tmp_logs
logs.AUDIT_PATH = os.path.join(tmp_logs, "audit", "audit.jsonl")
try:
    with open(os.path.join(tmp_logs, "worker-a.log"), "w", encoding="utf-8") as f:
        f.write("one\ntwo\nthree\n")
    with open(os.path.join(tmp_logs, "worker-b.log"), "w", encoding="utf-8") as f:
        f.write("four\n")

    listed = logs.list_logs()
    check("log listing finds both files", len(listed) == 2)
    check("log listing reports line counts",
          sorted(x["lines"] for x in listed) == [1, 3])

    data = logs.read_log("worker-a", tail=2)
    check("log reading is tail-bounded", data["lines"] == ["two", "three"])
    check("log reading reports the total", data["total"] == 3)

    try:
        logs.delete_log("../../evil")
        check("log deletion rejects traversal", False)
    except ValueError:
        check("log deletion rejects traversal", True)

    gone = logs.delete_log("worker-b")
    check("log deletion removes one file", gone["deleted"] and not os.path.exists(
        os.path.join(tmp_logs, "worker-b.log")))
    check("log deletion is audited",
          any(a["action"] == "log.delete" for a in logs.audit_tail()))

    try:
        logs.clear_logs("yes")
        check("clear-all requires the exact confirmation", False)
    except ValueError:
        check("clear-all requires the exact confirmation", True)

    cleared = logs.clear_logs("CLEAR")
    check("clear-all removes every log", cleared["cleared"] == 1)
    check("clear-all is audited",
          any(a["action"] == "log.clear" for a in logs.audit_tail()))
finally:
    common.LOG_DIR = old_log_dir
    logs.AUDIT_PATH = old_audit_path
    shutil.rmtree(tmp_logs, ignore_errors=True)

# --- authorization and emergency stop -------------------------------------
tmp_ctl = tempfile.mkdtemp(prefix="hunt-ctl-")
old_auth_path, old_stop_path = common.AUTH_PATH, common.STOP_PATH
common.AUTH_PATH = os.path.join(tmp_ctl, "authorization.json")
common.STOP_PATH = os.path.join(tmp_ctl, "STOP")
try:
    check("authorization starts unconfirmed",
          common.load_authorization()["confirmed"] is False)
    common.save_authorization({"program": "Acme program", "reference": "H1-1234",
                               "confirmed": True})
    check("authorization round-trips",
          common.load_authorization()["reference"] == "H1-1234")

    check("stop starts clear", common.stop_requested() is False)
    common.request_stop("selftest")
    check("stop latches", common.stop_requested() is True)
    check("stop records a reason", common.load_stop()["reason"] == "selftest")
    common.clear_stop()
    check("stop can be cleared", common.stop_requested() is False)
finally:
    common.AUTH_PATH = old_auth_path
    common.STOP_PATH = old_stop_path
    shutil.rmtree(tmp_ctl, ignore_errors=True)

print()
if failures:
    print("%d check(s) failed" % len(failures))
    sys.exit(1)
print("all checks passed")
