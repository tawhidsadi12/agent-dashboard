#!/usr/bin/env python3
"""common.py — the state layout and small IO helpers every process shares.

dispatch.py (the lead), worker.py (one agent) and server.py (the dashboard) all
have to agree on where things live and what shape they are. That agreement
used to be copy-pasted; now it is one module.

Layout under state/:

    state/<agent>.json            live heartbeat, one per agent (top level)
    state/current_run.json        pointer to the newest run
    state/runs/<run_id>/meta.json       target, rounds, categories, timing
    state/runs/<run_id>/findings.jsonl  one finding per line, append-only
    state/runs/<run_id>/assets.jsonl    hostnames/URLs discovered, for diffing

Runs are NEVER deleted by starting a new hunt — that is what makes diffing
possible (a host that appeared since last run is the interesting one). Only
the newest MAX_RUNS are kept, so the folder does not grow forever.
"""

import hashlib
import json
import os
import re
import shutil
import time
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

ROOT = os.path.dirname(os.path.abspath(__file__))

# Everything that changes at runtime lives under DATA_DIR. Locally that is the
# project folder (same layout as before); in Docker it is a mounted volume, so
# history survives `docker compose down` and the code stays read-only.
DATA_DIR = os.environ.get("HUNT_DATA_DIR") or ROOT

STATE_DIR = os.path.join(DATA_DIR, "state")
RUNS_DIR = os.path.join(STATE_DIR, "runs")
LOG_DIR = os.path.join(DATA_DIR, "logs")
SCOPE_PATH = os.path.join(DATA_DIR, "scope.json")
AUTH_PATH = os.path.join(DATA_DIR, "authorization.json")
SETTINGS_PATH = os.path.join(DATA_DIR, "settings.json")
AGENTS_PATH = os.path.join(DATA_DIR, "agents.json")
CURRENT_RUN_PATH = os.path.join(STATE_DIR, "current_run.json")
STOP_PATH = os.path.join(STATE_DIR, "STOP")

# An explicit HUNT_REQUIRE_AUTH pins the authorization gate for deployments; when
# it is unset, the Scope panel toggle decides. The default is optional: scope is
# always enforced, but the written-authorization record is not.
AUTH_ENV = os.environ.get("HUNT_REQUIRE_AUTH")
# HUNT_STRICT_SCOPE pins whether a target must already be listed before a hunt.
# Off by default: a new target is added to the in-scope list automatically, while
# out-of-scope entries stay hard blocks.
SCOPE_ENV = os.environ.get("HUNT_STRICT_SCOPE")

MAX_RUNS = 20
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$")

# One switch for the whole system. Real mode (the default) makes each worker
# run bounded, scope-checked checks and record `demo: false`. Set
# HUNT_DEMO_MODE=1 to restore the old simulation, which is tagged demo: true
# on the run and on every finding so the dashboard can mark it.
DEMO_MODE = os.environ.get("HUNT_DEMO_MODE", "0").strip().lower() in (
    "1", "true", "yes", "on")


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def ensure_dirs():
    os.makedirs(STATE_DIR, exist_ok=True)
    os.makedirs(RUNS_DIR, exist_ok=True)
    os.makedirs(LOG_DIR, exist_ok=True)


# --- names -----------------------------------------------------------------
# Agent names become file names (state/<name>.json, logs/<name>.log) and run
# ids become directory names. Anything that could climb out of state/ with
# ".." is rejected here instead of being handed to os.path.join.

def safe_name(value, label="name"):
    value = (value or "").strip()
    if not NAME_RE.match(value) or value in (".", ".."):
        raise ValueError(
            "%s must be 1-40 chars of letters, digits, dot, underscore or dash" % label
        )
    return value


def safe_agent_name(value):
    """Like safe_name but returns None instead of raising (used in validation)."""
    try:
        return safe_name(value, "agent name")
    except ValueError:
        return None


def safe_run_id(value):
    return safe_name(value, "run id")


# --- files -----------------------------------------------------------------

def atomic_write_json(path, data, retries=8):
    """Write to <path>.tmp, then os.replace().

    Windows refuses the replace while the dashboard happens to have the file
    open, so retry briefly rather than letting one worker die on a race it can
    simply lose. Callers that write every few seconds always recover.
    """
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    tmp = path + ".tmp"
    payload = json.dumps(data, indent=2)
    last_err = None
    for attempt in range(max(1, retries)):
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(payload)
            os.replace(tmp, path)
            return True
        except OSError as exc:  # PermissionError on Windows = reader has it open
            last_err = exc
            time.sleep(0.05 * (attempt + 1))
    try:
        if os.path.exists(tmp):
            os.remove(tmp)
    except OSError:
        pass
    if last_err is not None:
        raise last_err
    raise OSError("could not write %s" % path)


def read_json(path, default=None):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def append_jsonl(path, entry):
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def read_jsonl(path):
    out = []
    if not os.path.isfile(path):
        return out
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue  # torn last line while another process appends
    except OSError:
        pass
    return out


# --- scope -----------------------------------------------------------------

def load_scope():
    data = read_json(SCOPE_PATH, {}) or {}
    return {
        "in_scope": [s for s in data.get("in_scope", []) if isinstance(s, str)],
        "out_scope": [s for s in data.get("out_scope", []) if isinstance(s, str)],
    }


def save_scope(in_scope, out_scope):
    atomic_write_json(SCOPE_PATH, {"in_scope": in_scope, "out_scope": out_scope})


# --- authorization ---------------------------------------------------------
# A scope list says "what"; this record says "who said we may". The record is
# always stored, but it is only *required* when the operator turns the gate on
# in the Scope panel (settings.json) or pins HUNT_REQUIRE_AUTH. Stored separately
# so a scope edit cannot silently erase the authorization trail.

def load_authorization():
    data = read_json(AUTH_PATH, {}) or {}
    return {
        "program": data.get("program") or "",
        "program_url": data.get("program_url") or "",
        "authorized_by": data.get("authorized_by") or "",
        "reference": data.get("reference") or "",
        "window_start": data.get("window_start") or "",
        "window_end": data.get("window_end") or "",
        "rate_limit": data.get("rate_limit") or "",
        "notes": data.get("notes") or "",
        "confirmed": bool(data.get("confirmed")),
        "updated": data.get("updated") or "",
    }


def save_authorization(record):
    payload = dict(record or {})
    payload["confirmed"] = bool(payload.get("confirmed"))
    payload["updated"] = now_iso()
    atomic_write_json(AUTH_PATH, payload)
    return load_authorization()


def _env_auth_required():
    """The value pinned by HUNT_REQUIRE_AUTH, or None when the env is silent."""
    if AUTH_ENV is None:
        return None
    value = AUTH_ENV.strip().lower()
    if value in ("", "default"):
        return None
    return value not in ("0", "false", "no", "off")


def auth_required_locked():
    """True when HUNT_REQUIRE_AUTH pins the gate and the UI cannot change it."""
    return _env_auth_required() is not None


def load_settings():
    data = read_json(SETTINGS_PATH, {}) or {}
    return data if isinstance(data, dict) else {}


def save_settings(updates):
    """Merge settings so independent toggles never erase each other."""
    data = load_settings()
    data.update(updates or {})
    atomic_write_json(SETTINGS_PATH, data)
    return data


def auth_required():
    """Whether a confirmed authorization record is mandatory before a hunt.

    Off by default: the operator can hunt with only a target. The Scope panel
    toggle (settings.json) turns the gate on, and HUNT_REQUIRE_AUTH pins it for
    a deployment.
    """
    pinned = _env_auth_required()
    if pinned is not None:
        return pinned
    return bool(load_settings().get("require_auth", False))


def save_auth_required(value):
    save_settings({"require_auth": bool(value)})
    return auth_required()


def _env_strict_scope():
    """The value pinned by HUNT_STRICT_SCOPE, or None when the env is silent."""
    if SCOPE_ENV is None:
        return None
    value = SCOPE_ENV.strip().lower()
    if value in ("", "default"):
        return None
    return value not in ("0", "false", "no", "off")


def strict_scope_locked():
    """True when HUNT_STRICT_SCOPE pins the scope mode."""
    return _env_strict_scope() is not None


def strict_scope():
    """Whether a target must already be in the in-scope list.

    Off by default. In lenient mode a new target is appended to the list and
    audited; an out-of-scope entry always blocks, and GET endpoints never write
    scope. Turn the Scope-panel checkbox on to require a pre-listed target, or
    pin it with HUNT_STRICT_SCOPE=1.
    """
    pinned = _env_strict_scope()
    if pinned is not None:
        return pinned
    return bool(load_settings().get("strict_scope", False))


def save_strict_scope(value):
    save_settings({"strict_scope": bool(value)})
    return strict_scope()


# --- emergency stop --------------------------------------------------------
# A file, not an in-memory flag: every worker is a separate process and has to
# see it. The server creates it, dispatch polls it between rounds, and worker
# checks it before its first request.

def request_stop(reason="operator requested stop"):
    atomic_write_json(STOP_PATH, {"requested": now_iso(), "reason": reason})
    return load_stop()


def clear_stop():
    try:
        if os.path.isfile(STOP_PATH):
            os.remove(STOP_PATH)
    except OSError:
        pass


def load_stop():
    data = read_json(STOP_PATH, {}) or {}
    return {"requested": bool(data.get("requested")), "at": data.get("requested"),
            "reason": data.get("reason") or ""}


def stop_requested():
    return load_stop()["requested"]


# --- runs ------------------------------------------------------------------

def new_run_id():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def unique_run_id():
    """Two hunts inside the same second must not share a folder."""
    base = new_run_id()
    candidate = base
    n = 2
    while os.path.isdir(os.path.join(RUNS_DIR, candidate)):
        candidate = "%s-%d" % (base, n)
        n += 1
    return candidate


def run_dir(run_id):
    return os.path.join(RUNS_DIR, safe_run_id(run_id))


def meta_path(run_id):
    return os.path.join(run_dir(run_id), "meta.json")


def findings_path(run_id):
    return os.path.join(run_dir(run_id), "findings.jsonl")


def assets_path(run_id):
    return os.path.join(run_dir(run_id), "assets.jsonl")


def list_runs():
    """Oldest first. Run ids are UTC timestamps, so they sort lexicographically."""
    if not os.path.isdir(RUNS_DIR):
        return []
    ids = [
        d for d in os.listdir(RUNS_DIR)
        if NAME_RE.match(d) and os.path.isdir(os.path.join(RUNS_DIR, d))
    ]
    return sorted(ids)


def current_run_id():
    data = read_json(CURRENT_RUN_PATH, {}) or {}
    rid = data.get("run_id")
    if not rid:
        return None
    try:
        return safe_run_id(rid)
    except ValueError:
        return None


def set_current_run_id(run_id):
    atomic_write_json(CURRENT_RUN_PATH, {
        "run_id": safe_run_id(run_id),
        "updated": now_iso(),
    })


def prune_runs(keep=MAX_RUNS):
    if keep <= 0:
        return
    ids = list_runs()
    for rid in ids[:-keep]:
        shutil.rmtree(os.path.join(RUNS_DIR, rid), ignore_errors=True)


# --- findings --------------------------------------------------------------

def _stable_url(url):
    """Drop query values and the fragment, keep path and parameter names.

    A reflected-XSS check embeds a unique marker in the payload, so the raw URL
    differs on every run even when it is the same reflection at the same sink.
    Keying on the raw URL turned one finding into six. Parameter *names* are
    kept so `?id=` and `?next=` remain different sinks.
    """
    if not url:
        return ""
    try:
        parts = urlsplit(url)
    except ValueError:
        return url.lower()
    keys = urlencode([(k, "") for k, _ in parse_qsl(parts.query, keep_blank_values=True)])
    return urlunsplit((parts.scheme, parts.netloc, parts.path, keys, "")).lower()


def finding_dedupe_key(finding):
    """Two agents finding the same thing is normal; the same finding counted
    twice in the header is not. Key on where it is + what it is."""
    parts = [
        (finding.get("host") or "").lower(),
        _stable_url(finding.get("url")),
        (finding.get("param") or "").lower(),
        re.sub(r"\s+", " ", (finding.get("title") or "").strip().lower()),
    ]
    return hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()[:16]


def dedupe_findings(findings):
    """Collapse repeats within one run, keeping the first sighting and a
    dup_count. The jsonl itself stays append-only for audit."""
    seen = {}
    for f in findings:
        key = f.get("dedupe_key") or finding_dedupe_key(f)
        if key in seen:
            seen[key]["dup_count"] = seen[key].get("dup_count", 1) + 1
            continue
        item = dict(f)
        item["dedupe_key"] = key
        item["dup_count"] = 1
        seen[key] = item
    return list(seen.values())


def run_summary(run_id):
    rid = safe_run_id(run_id)
    meta = read_json(meta_path(rid), {}) or {}
    findings = dedupe_findings(read_jsonl(findings_path(rid)))
    assets = read_jsonl(assets_path(rid))
    return {
        "run_id": rid,
        "target": meta.get("target"),
        "rounds": meta.get("rounds"),
        "categories": meta.get("categories") or [],
        "started": meta.get("started"),
        "finished": meta.get("finished"),
        "running": bool(meta.get("running")),
        "demo": bool(meta.get("demo", True)),
        "profile": meta.get("profile") or None,
        "findings": len(findings),
        "assets": len({(a.get("value") or "").lower() for a in assets if a.get("value")}),
    }


def diff_runs(base_run, run):
    """What is new and what vanished between two runs.

    This is the Phase-5 primitive: a subdomain or endpoint that did not exist
    in the previous run has almost certainly not been tested by anyone, so it
    is the best place to spend the next hour.
    """
    cur = safe_run_id(run)
    base = safe_run_id(base_run) if base_run else None

    def asset_map(rid):
        out = {}
        if not rid:
            return out
        for a in read_jsonl(assets_path(rid)):
            value = (a.get("value") or "").strip()
            if value:
                out.setdefault(value.lower(), a)
        return out

    def finding_map(rid):
        if not rid:
            return {}
        return {
            f.get("dedupe_key") or finding_dedupe_key(f): f
            for f in dedupe_findings(read_jsonl(findings_path(rid)))
        }

    base_assets, cur_assets = asset_map(base), asset_map(cur)
    base_findings, cur_findings = finding_map(base), finding_map(cur)

    added_assets = [cur_assets[k] for k in sorted(cur_assets) if k not in base_assets]
    gone_assets = [base_assets[k] for k in sorted(base_assets) if k not in cur_assets]
    new_findings = [cur_findings[k] for k in cur_findings if k not in base_findings]
    gone_findings = [base_findings[k] for k in base_findings if k not in cur_findings]
    new_findings.sort(key=lambda f: f.get("ts", ""), reverse=True)

    return {
        "base_run": base,
        "run": cur,
        "assets": {"added": added_assets, "removed": gone_assets, "total": len(cur_assets)},
        "findings": {"added": new_findings, "removed": gone_findings, "total": len(cur_findings)},
    }
