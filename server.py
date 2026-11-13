#!/usr/bin/env python3
"""server.py — serves the dashboard UI and the API that reads state/.

    python server.py     ->  http://127.0.0.1:8777

Findings and assets are read from the current run folder (state/runs/<id>/),
so a new hunt never erases the previous one. Scope is enforced here on the
submitted target, and again inside every worker before a tool touches a host
(scope_guard.assert_allowed) — this check is the convenience, that one is the
gate.
"""

import os
import sys
import threading
from datetime import datetime, timezone
from urllib.parse import urlsplit

from flask import Flask, jsonify, request, send_from_directory

import common
import logs
import methods
import planning
import scope_guard
import surface
import toolbox

ROOT = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(ROOT, "static")

app = Flask(__name__, static_folder=STATIC_DIR)

hunt_lock = threading.Lock()
hunt_running = {"value": False, "target": None, "run_id": None, "error": None}

MAX_ROUNDS = 20

# A browser cannot send a custom header cross-origin without a successful CORS
# preflight, and this app never grants one. Requiring it on every write is a
# CSRF gate that costs the dashboard one line and blocks form/text-plain posts.
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _csrf_enabled():
    return os.environ.get("HUNT_CSRF_PROTECT", "1").strip().lower() not in (
        "0", "false", "no", "off")


def _same_origin():
    origin = request.headers.get("Origin") or ""
    if not origin:
        return True                      # curl / CLI, not a browser form
    try:
        return urlsplit(origin).netloc == request.host
    except ValueError:
        return False


@app.before_request
def _guard_writes():
    if request.method not in UNSAFE_METHODS or not _csrf_enabled():
        return None
    if request.headers.get("X-Hunt-Request") != "1":
        return jsonify({
            "ok": False,
            "error": "missing X-Hunt-Request header — write requests must come "
                     "from the dashboard, not a cross-site form",
        }), 403
    if not _same_origin():
        return jsonify({"ok": False, "error": "cross-origin write blocked"}), 403
    return None


def _require_authorization():
    """Return an error response only when the authorization gate is enabled.

    The gate is optional by default: scope is always fail-closed, while the
    written-record check can be switched on in the Scope panel. An explicit
    HUNT_REQUIRE_AUTH pins it for a deployment.
    """
    if not common.auth_required():
        return None
    auth = common.load_authorization()
    if auth.get("confirmed"):
        return None
    return jsonify({
        "ok": False,
        "error": "this installation requires a confirmed written authorization "
                 "record before a hunt. Fill in the Scope panel, or turn off "
                 "'Block hunts until this record is confirmed'.",
        "requires_authorization": True,
    }), 409



def _dispatch():
    sys.path.insert(0, ROOT)
    import dispatch
    return dispatch


def age_seconds(iso_ts):
    try:
        ts = datetime.fromisoformat(iso_ts)
        return (datetime.now(timezone.utc) - ts).total_seconds()
    except Exception:
        return None


def derive_live_status(raw_status, age):
    """LIVE = pulse <90s old, yellow = on task but silent, grey = idle."""
    if raw_status == "BLOCKED" and age is not None and age < 180:
        return "blocked"
    if age is None:
        return "grey"
    if age < 90:
        return "ontask" if raw_status == "ON_TASK" else "live"
    if age < 180:
        return "yellow"
    return "grey"


def load_agents_state():
    agents = []
    if not os.path.isdir(common.STATE_DIR):
        return agents
    for fname in sorted(os.listdir(common.STATE_DIR)):
        if not fname.endswith(".json") or fname == "current_run.json":
            continue
        data = common.read_json(os.path.join(common.STATE_DIR, fname))
        if not isinstance(data, dict) or not data.get("name"):
            continue
        age = age_seconds(data.get("last_report_ts", ""))
        data["age_seconds"] = round(age) if age is not None else None
        data["live_status"] = derive_live_status(data.get("status"), age)
        agents.append(data)
    return agents


def current_findings():
    run_id = common.current_run_id()
    if not run_id:
        return [], None
    findings = common.dedupe_findings(common.read_jsonl(common.findings_path(run_id)))
    findings.sort(key=lambda f: f.get("ts", ""), reverse=True)
    return findings, run_id


@app.route("/")
def index():
    return send_from_directory(STATIC_DIR, "dashboard.html")


@app.route("/api/state")
def api_state():
    findings, run_id = current_findings()

    counts = {"confirmed": 0, "likely": 0, "dig": 0, "chain": 0, "lead": 0}
    for f in findings:
        sev = f.get("severity", "")
        if sev in counts:
            counts[sev] += 1

    run = None
    if run_id:
        try:
            run = common.run_summary(run_id)
        except ValueError:
            run = None

    auth = common.load_authorization()
    return jsonify({
        "updated": common.now_iso(),
        "demo_mode": common.DEMO_MODE,
        "run": run,
        "agents": load_agents_state(),
        "findings": findings,
        "counts": counts,
        "stop": common.load_stop(),
        "authorization": {
            "confirmed": bool(auth.get("confirmed")),
            "program": auth.get("program") or "",
        },
        "auth_required": common.auth_required(),
        "auth_required_locked": common.auth_required_locked(),
        "strict_scope": common.strict_scope(),
        "strict_scope_locked": common.strict_scope_locked(),
        "scope_configured": bool(common.load_scope().get("in_scope")),
    })


@app.route("/api/runs")
def api_runs():
    ids = common.list_runs()
    try:
        current = common.current_run_id()
    except ValueError:
        current = None
    runs = []
    for rid in reversed(ids):            # newest first
        try:
            runs.append(common.run_summary(rid))
        except ValueError:
            continue
    return jsonify({"runs": runs, "current": current})


@app.route("/api/diff")
def api_diff():
    """Diff the selected run (default: current) against the one before it."""
    run_id = request.args.get("run") or common.current_run_id()
    if not run_id:
        return jsonify({"ok": False, "error": "no runs yet — start a hunt first"}), 404
    try:
        rid = common.safe_run_id(run_id)
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400

    ids = common.list_runs()
    if rid not in ids:
        return jsonify({"ok": False, "error": "unknown run %r" % rid}), 404

    index = ids.index(rid)
    previous = ids[index - 1] if index > 0 else None
    result = common.diff_runs(previous, rid)
    result["ok"] = True
    result["is_first_run"] = previous is None
    return jsonify(result)


@app.route("/api/scope", methods=["GET"])
def api_scope_get():
    scope = common.load_scope()
    scope["parsed"] = {
        "in_scope": scope_guard.describe_entries(scope["in_scope"]),
        "out_scope": scope_guard.describe_entries(scope["out_scope"]),
    }
    return jsonify(scope)


@app.route("/api/scope", methods=["POST"])
def api_scope_post():
    body = request.get_json(force=True, silent=True) or {}
    in_scope = [s.strip() for s in body.get("in_scope", []) if isinstance(s, str) and s.strip()]
    out_scope = [s.strip() for s in body.get("out_scope", []) if isinstance(s, str) and s.strip()]
    common.save_scope(in_scope, out_scope)
    logs.audit("scope.update", {"in_scope": in_scope, "out_scope": out_scope})

    unparsed = []
    for entry in in_scope + out_scope:
        kind, _ = scope_guard.parse_entry(entry)
        if kind is None:
            unparsed.append(entry)
    return jsonify({"ok": True, "in_scope": in_scope, "out_scope": out_scope,
                    "unparsed": unparsed})


@app.route("/api/authorization", methods=["GET"])
def api_authorization_get():
    return jsonify({"ok": True, "authorization": common.load_authorization(),
                    "required": common.auth_required(),
                    "locked": common.auth_required_locked()})


@app.route("/api/authorization", methods=["POST"])
def api_authorization_post():
    body = request.get_json(force=True, silent=True) or {}
    record = {
        "program": (body.get("program") or "").strip()[:200],
        "program_url": (body.get("program_url") or "").strip()[:500],
        "authorized_by": (body.get("authorized_by") or "").strip()[:200],
        "reference": (body.get("reference") or "").strip()[:200],
        "window_start": (body.get("window_start") or "").strip()[:40],
        "window_end": (body.get("window_end") or "").strip()[:40],
        "rate_limit": (body.get("rate_limit") or "").strip()[:120],
        "notes": (body.get("notes") or "").strip()[:2000],
        "confirmed": bool(body.get("confirmed")),
    }
    if record["confirmed"] and not record["program"]:
        return jsonify({"ok": False,
                        "error": "program name is required when confirming"}), 400
    saved = common.save_authorization(record)
    logs.audit("authorization.update",
               {"program": saved["program"], "confirmed": saved["confirmed"]})
    return jsonify({"ok": True, "authorization": saved})


@app.route("/api/settings", methods=["GET"])
def api_settings_get():
    return jsonify({
        "ok": True,
        "require_auth": common.auth_required(),
        "locked": common.auth_required_locked(),
        "strict_scope": common.strict_scope(),
        "strict_scope_locked": common.strict_scope_locked(),
    })


@app.route("/api/settings", methods=["POST"])
def api_settings_post():
    body = request.get_json(force=True, silent=True) or {}
    changes = {}
    if "require_auth" in body:
        if common.auth_required_locked():
            return jsonify({
                "ok": False,
                "error": "HUNT_REQUIRE_AUTH pins this setting for this installation",
            }), 409
        if not isinstance(body["require_auth"], bool):
            return jsonify({"ok": False, "error": "require_auth must be true or false"}), 400
        changes["require_auth"] = body["require_auth"]
    if "strict_scope" in body:
        if common.strict_scope_locked():
            return jsonify({
                "ok": False,
                "error": "HUNT_STRICT_SCOPE pins this setting for this installation",
            }), 409
        if not isinstance(body["strict_scope"], bool):
            return jsonify({"ok": False, "error": "strict_scope must be true or false"}), 400
        changes["strict_scope"] = body["strict_scope"]
    if not changes:
        return jsonify({
            "ok": False,
            "error": "provide require_auth or strict_scope (true/false)",
        }), 400
    common.save_settings(changes)
    logs.audit("settings.update", changes)
    return jsonify({
        "ok": True,
        "require_auth": common.auth_required(),
        "strict_scope": common.strict_scope(),
        "locked": common.auth_required_locked(),
        "strict_scope_locked": common.strict_scope_locked(),
    })


# --- emergency stop --------------------------------------------------------
# POST  /api/stop   set the stop flag (workers and dispatch check it)
# DELETE /api/stop  clear it so the next hunt can start
@app.route("/api/stop", methods=["POST"])
def api_stop_post():
    reason = ((request.get_json(force=True, silent=True) or {}).get("reason")
              or "operator pressed stop")
    state = common.request_stop(reason[:300])
    logs.audit("hunt.stop", {"reason": state["reason"]})
    return jsonify({"ok": True, "stopped": state,
                    "message": "stop requested; running workers will exit at "
                               "their next checkpoint"})


@app.route("/api/stop", methods=["DELETE"])
def api_stop_delete():
    common.clear_stop()
    logs.audit("hunt.stop.clear", {})
    return jsonify({"ok": True, "stopped": common.load_stop()})


# --- log management --------------------------------------------------------
@app.route("/api/logs", methods=["GET"])
def api_logs_list():
    return jsonify({"ok": True, "logs": logs.list_logs(),
                    "audit": logs.audit_tail(30)})


@app.route("/api/logs/<name>", methods=["GET"])
def api_log_read(name):
    try:
        tail = int(request.args.get("tail") or 400)
    except ValueError:
        tail = 400
    try:
        return jsonify({"ok": True, **logs.read_log(name, tail=tail)})
    except FileNotFoundError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 404
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.route("/api/logs/<name>", methods=["DELETE"])
def api_log_delete(name):
    try:
        return jsonify({"ok": True, **logs.delete_log(name)})
    except FileNotFoundError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 404
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    except OSError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@app.route("/api/logs/clear", methods=["POST"])
def api_logs_clear():
    body = request.get_json(force=True, silent=True) or {}
    try:
        result = logs.clear_logs(body.get("confirm"))
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    return jsonify({"ok": True, **result})



@app.route("/api/categories")
def api_categories():
    return jsonify({"categories": _dispatch().ALL_CATEGORIES,
                    "methods": methods.all_methods()})


@app.route("/api/methods")
def api_methods():
    """All playbooks, or one when ?category= is given."""
    category = (request.args.get("category") or "").strip()
    if category:
        playbook = methods.get(category)
        if not playbook:
            return jsonify({"ok": False, "error": "unknown category %r" % category}), 404
        return jsonify({
            "ok": True,
            "id": category,
            "automated": category in methods.AUTOMATED,
            "playbook": playbook,
            "commands": methods.commands_for(category),
        })
    return jsonify({"ok": True, "methods": methods.all_methods(),
                    "count": len(methods.METHODS)})


@app.route("/api/plan")
def api_plan():
    """Ranked hunt plan for a target, optionally after a live surface check."""
    target = (request.args.get("target") or "").strip()
    if not target:
        return jsonify({"ok": False, "error": "target is required"}), 400
    if not scope_guard.host_of(target):
        return jsonify({"ok": False, "error": "could not read a hostname out of %r"
                                               % target}), 400

    profile = None
    if request.args.get("profile") in ("1", "true", "yes"):
        auth_error = _require_authorization()
        if auth_error:
            return auth_error
        profile = surface.profile_target(target,
                                         allow_unlisted=_lenient_live_allowed())
        if profile.get("error"):
            # A scope refusal is a 403. An unreachable host is an upstream
            # failure (502), not an authorization problem.
            blocked = str(profile["error"]).startswith("BLOCKED BY SCOPE")
            return jsonify({"ok": False, "error": profile["error"],
                            "profile": profile}), (403 if blocked else 502)

    plan = planning.build_plan(target, profile)
    plan["profile"] = profile
    return jsonify(plan)


# --- target surface check --------------------------------------------------
# GET /api/profile?target=example.com
# Ordinary GETs only, in scope, redirects checked before they are followed.
@app.route("/api/profile")
def api_profile():
    auth_error = _require_authorization()
    if auth_error:
        return auth_error
    target = (request.args.get("target") or "").strip()
    if not target:
        return jsonify({"ok": False, "error": "target is required"}), 400
    if not scope_guard.host_of(target):
        return jsonify({"ok": False,
                        "error": "could not read a hostname out of %r" % target}), 400
    result = surface.profile_target(target,
                                    allow_unlisted=_lenient_live_allowed())
    return jsonify(result), (200 if result.get("ok") else 502)


# --- tool registry ---------------------------------------------------------
# GET  /api/tools            catalog grouped by stage + what is on PATH
# GET  /api/tools?refresh=1  same, ignoring the 60s detection cache
# POST /api/tools            {"selected": {"<stage>": "<tool id>"}}
@app.route("/api/tools", methods=["GET"])
def api_tools_get():
    refresh = request.args.get("refresh") in ("1", "true", "yes")
    stages = toolbox.purpose_view(refresh=refresh)
    return jsonify({
        "ok": True,
        "demo_mode": common.DEMO_MODE,
        "selected": toolbox.load_selection(),
        "stages": stages,
        "summary": toolbox.summary(stages=stages),
    })


@app.route("/api/tools", methods=["POST"])
def api_tools_post():
    body = request.get_json(force=True, silent=True) or {}
    selected = body.get("selected")
    if not isinstance(selected, dict) or not selected:
        return jsonify({
            "ok": False,
            "error": "selected must be an object like {\"xss\": \"dalfox\"}",
        }), 400
    try:
        toolbox.save_selection(selected)
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400

    stages = toolbox.purpose_view()
    return jsonify({
        "ok": True,
        "demo_mode": common.DEMO_MODE,
        "selected": toolbox.load_selection(),
        "stages": stages,
        "summary": toolbox.summary(stages=stages),
    })


@app.route("/api/agents", methods=["GET"])
def api_agents_get():
    agents = _dispatch().load_agents()
    masked = []
    for a in agents:
        m = dict(a)
        m["api_key_set"] = bool(m.get("api_key"))
        m["api_key"] = ""          # never echo the key back to the browser
        masked.append(m)
    return jsonify({"agents": masked})


@app.route("/api/agents", methods=["POST"])
def api_agents_post():
    dispatch = _dispatch()
    body = request.get_json(force=True, silent=True) or {}
    existing = {a["name"]: a for a in dispatch.load_agents()}

    cleaned, seen = [], set()
    for a in body.get("agents", []):
        if not isinstance(a, dict):
            continue
        raw_name = (a.get("name") or "").strip()
        name = common.safe_agent_name(raw_name)
        if not name:
            return jsonify({
                "ok": False,
                "error": "invalid agent name %r — use letters, digits, dot, "
                         "underscore or dash (max 40 chars)" % raw_name,
            }), 400
        model = (a.get("model") or "").strip()
        if not model:
            return jsonify({"ok": False, "error": "agent %r has no model" % name}), 400
        if name in seen:
            return jsonify({"ok": False, "error": "duplicate agent name %r" % name}), 400
        seen.add(name)

        api_key = a.get("api_key", "")
        if not api_key and name in existing:
            api_key = existing[name].get("api_key", "")   # blank = keep saved key
        cleaned.append({
            "name": name,
            "role": a.get("role") if a.get("role") in ("lead", "worker") else "worker",
            "model": model,
            "api_key": api_key,
        })

    if not cleaned:
        return jsonify({"ok": False, "error": "at least one agent is required"}), 400

    dispatch.save_agents(cleaned)
    return jsonify({"ok": True, "count": len(cleaned)})


def _lenient_live_allowed():
    """True when a live GET may profile a not-yet-listed target.

    Lenient scope plus the dashboard's X-Hunt-Request header. A cross-site
    image/link cannot set that header, so this does not open a CSRF path to
    arbitrary profiling; out-of-scope entries still block inside the profiler.
    """
    return (not common.strict_scope()
            and request.headers.get("X-Hunt-Request") == "1")


def _admit_target_as_scope(target):
    """Persist the submitted target when scope is lenient.

    Lenient mode (default) makes the in-scope list a record, not a gate: a
    target that is not listed is appended and audited. Strict mode keeps the
    list authoritative. Both modes refuse a host that matches an out-of-scope
    entry, and both only run on POST /api/start (never on a GET, so a cross-site
    request cannot cause traffic or write scope). Returns the added host, or
    None.
    """
    if common.strict_scope():
        return None
    scope = common.load_scope()
    host = scope_guard.missing_from_scope(target, scope)
    if not host:
        return None
    common.save_scope(scope["in_scope"] + [host], scope["out_scope"])
    logs.audit("scope.auto_add", {
        "host": host,
        "reason": "lenient scope: target was not listed",
    })
    return host


@app.route("/api/start", methods=["POST"])
def api_start():
    dispatch = _dispatch()
    with hunt_lock:
        if hunt_running["value"]:
            return jsonify({
                "ok": False,
                "error": "a hunt is already running on %s" % hunt_running["target"],
            }), 409

        body = request.get_json(force=True, silent=True) or {}
        target = (body.get("target") or "").strip()
        if not target:
            return jsonify({"ok": False, "error": "target is required"}), 400
        if not scope_guard.host_of(target):
            return jsonify({"ok": False, "error": "could not read a hostname out of %r" % target}), 400

        try:
            rounds = int(body.get("rounds") or 3)
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "rounds must be a number"}), 400
        if not 1 <= rounds <= MAX_ROUNDS:
            return jsonify({"ok": False, "error": "rounds must be 1-%d" % MAX_ROUNDS}), 400

        auth_error = _require_authorization()
        if auth_error:
            return auth_error

        if common.stop_requested():
            return jsonify({
                "ok": False,
                "error": "emergency stop is latched. Clear it with the Resume "
                         "button (DELETE /api/stop) before starting a new hunt.",
                "stop_latched": True,
            }), 409

        scope_seeded = _admit_target_as_scope(target)
        allowed, reason = scope_guard.check(target)
        if not allowed:
            return jsonify({"ok": False, "error": "BLOCKED BY SCOPE: " + reason}), 403
        if scope_seeded:
            reason = ("scope is lenient, so %s was added to the in-scope list. "
                      "Turn on strict scope in the Scope panel to require a "
                      "pre-listed target." % scope_seeded)

        # Look at the web surface before choosing what to test. Ordinary GETs
        # only, in scope; see surface.py. If the caller did not pick
        # categories, the likely bug classes found here decide what runs.
        requested_categories = body.get("categories")
        if requested_categories is not None:
            if not isinstance(requested_categories, list):
                return jsonify({"ok": False, "error": "categories must be a list"}), 400
            categories = [c for c in requested_categories if c in dispatch.TASK_CATEGORIES]
            if not categories:
                return jsonify({
                    "ok": False,
                    "error": "none of the selected categories are valid",
                }), 400
            categories_source = "user"
        else:
            categories = None
            categories_source = None

        profile_result = None
        if body.get("profile", True) and not common.DEMO_MODE:
            profile_result = surface.profile_target(target)

        if categories is None:
            # Auto mode: use the same ranked plan the Plan button shows, but
            # only the categories that have bounded checks. Manual categories
            # need a person; running them with no checks would just add noise.
            auto_plan = planning.build_plan(target, profile_result)
            suggested = [c for c in auto_plan.get("automated", [])
                         if c in dispatch.TASK_CATEGORIES]
            if suggested:
                categories = suggested
                categories_source = "plan"
            else:
                categories = list(dispatch.TASK_CATEGORIES.keys())
                categories_source = "all"

        # Preflight the toolchain for exactly the categories being run. In demo
        # mode a missing tool is only reported (the work is simulated anyway);
        # with DEMO_MODE off it is a hard stop, because a hunt that silently
        # pretends to scan is worse than a hunt that refuses to start.
        missing_tools = toolbox.missing_for_categories(categories)
        if missing_tools and not common.DEMO_MODE:
            names = ", ".join(t["name"] for t in missing_tools)
            return jsonify({
                "ok": False,
                "error": "this hunt needs %d tool(s) that are not installed: %s. "
                         "Pick an installed alternative on the Tools tab, or run the "
                         "install command shown there." % (len(missing_tools), names),
                "tools_missing": missing_tools,
            }), 409

        tools_warning = None
        if missing_tools:
            tools_warning = ("%d tool(s) for these categories are not installed (demo "
                             "mode: results are simulated): %s"
                             % (len(missing_tools),
                                ", ".join(t["name"] for t in missing_tools)))

        hunt_running["value"] = True
        hunt_running["target"] = target
        hunt_running["error"] = None
        hunt_running["run_id"] = None

    logs.audit("hunt.start", {
        "target": target,
        "rounds": rounds,
        "categories": categories,
        "source": categories_source,
    })

    def _run():
        try:
            dispatch.run_hunt(target, rounds, categories=categories,
                              fresh_state=True, profile_result=profile_result)
        except Exception as exc:          # never leave the button stuck
            print("[server] hunt failed: %s" % exc)
            with hunt_lock:
                hunt_running["error"] = "%s" % exc
        finally:
            with hunt_lock:
                hunt_running["value"] = False
                hunt_running["target"] = None
                hunt_running["run_id"] = None

    threading.Thread(target=_run, daemon=True).start()
    return jsonify({
        "ok": True,
        "target": target,
        "rounds": rounds,
        "categories": categories,
        "categories_source": categories_source,
        "profile": profile_result,
        "scope_seeded": scope_seeded,
        "warning": reason,
        "tools_missing": missing_tools,
        "tools_warning": tools_warning,
    })


@app.route("/api/status")
def api_status():
    with hunt_lock:
        state = dict(hunt_running)
    state["run_id"] = common.current_run_id()
    state["stop"] = common.load_stop()
    return jsonify(state)


@app.route("/api/activity")
def api_activity():
    """Tails recent lines from every agent's log file for the Activity tab."""
    lines = []
    if os.path.isdir(common.LOG_DIR):
        for fname in sorted(os.listdir(common.LOG_DIR)):
            if not fname.endswith(".log"):
                continue
            agent = fname[:-4]
            try:
                with open(os.path.join(common.LOG_DIR, fname), encoding="utf-8",
                          errors="replace") as f:
                    tail = f.readlines()[-20:]
            except OSError:
                continue
            for line in tail:
                lines.append("[%s] %s" % (agent, line.strip()))
    return jsonify({"lines": lines[-100:]})


if __name__ == "__main__":
    common.ensure_dirs()
    host = os.environ.get("HUNT_HOST", "127.0.0.1")
    try:
        port = int(os.environ.get("HUNT_PORT", "8777"))
    except ValueError:
        port = 8777
    print("Dashboard running at http://%s:%d" % (host, port))
    print("data dir: %s" % common.DATA_DIR)
    app.run(host=host, port=port, debug=False)
