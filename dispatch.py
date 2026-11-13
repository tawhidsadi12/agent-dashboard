#!/usr/bin/env python3
"""dispatch.py — the lead: spawn every worker AT ONCE (parallel, not
sequential), assign tasks, and keep dispatching rounds until done.

    python dispatch.py <target> [rounds] [category1,category2,...]

Each worker is a separate background process (subprocess.Popen, non-blocking).
Each writes only its own heartbeat file, so there is no shared-file race.

Every hunt becomes its own run folder under state/runs/<run_id>/. Runs are
never overwritten, which is what makes diffing possible: see the Runs tab.

Agents with role "lead" are not sent into the task pool — they are the
orchestrator's identity. This process does the orchestration, and reports
through that agent's card and a single closing summary finding.
"""

import os
import random
import subprocess
import sys
import time

import common
import scope_guard
import toolbox

ROOT = os.path.dirname(os.path.abspath(__file__))
PYTHON = sys.executable
AGENTS_PATH = common.AGENTS_PATH

# --- Default team, used only if agents.json doesn't exist yet ----------------
DEFAULT_WORKERS = [
    {"name": "lead-glm",        "role": "lead",   "model": "opencode/glm-5.3-flash-free",      "api_key": ""},
    {"name": "worker-deepseek", "role": "worker", "model": "opencode/deepseek-v4.1-flash-free", "api_key": ""},
    {"name": "worker-glm",      "role": "worker", "model": "opencode/glm-5.3-flash-free",      "api_key": ""},
    {"name": "worker-mimo",     "role": "worker", "model": "opencode/mimo-v2.6-flash-free",    "api_key": ""},
]


# --- Task templates, grouped by category. Pick which categories run per hunt. -
# Broadly follows OWASP Top 10 / common bug-bounty vuln classes. Add your own
# category by adding a key here with a list of {target}-templated strings —
# it shows up in the dashboard automatically via /api/categories.
TASK_CATEGORIES = {
    "recon": [
        "subdomain enumeration on {target}",
        "port + service discovery on {target}",
        "tech stack fingerprinting on {target}",
        "cloud asset / S3-bucket discovery for {target}",
    ],
    "js_audit": [
        "JS asset content audit on {target} — root shape vs bounded common-name probes",
        "endpoint + secret extraction from bundled JS on {target}",
        "sourcemap exposure check on {target}",
    ],
    "auth_session": [
        "auth bypass probing on {target} session endpoints",
        "WS persistence lane on {target}: 15-min all-pairs long-hold + re-challenge check",
        "session fixation / token reuse check on {target}",
        "password reset flow abuse on {target}",
        "MFA / OTP bypass probing on {target}",
    ],
    "access_control": [
        "IDOR sweep across object-id parameters on {target}",
        "BOLA (broken object level auth) sweep on {target} API endpoints",
        "privilege escalation probing between roles on {target}",
        "mass assignment check on {target} write endpoints",
    ],
    "injection": [
        "SQL injection probing on {target} input params",
        "command injection probing on {target} file/exec-adjacent params",
        "NoSQL injection probing on {target} query params",
        "SSTI (server-side template injection) probing on {target}",
        "XXE probing on {target} XML-accepting endpoints",
    ],
    "xss": [
        "reflected XSS sweep on {target} input params",
        "stored XSS sweep on {target} user-generated content fields",
        "DOM XSS sweep on {target} client-side sinks",
    ],
    "ssrf": [
        "SSRF probing on {target} URL-fetching params",
        "SSRF via webhook/callback URLs on {target}",
    ],
    "csrf_cors": [
        "CSRF token validation check on {target} state-changing endpoints",
        "CORS misconfiguration probing on {target}",
        "clickjacking / missing frame-protection check on {target}",
    ],
    "redirect": [
        "open redirect sweep on {target} known redirect params",
    ],
    "api_diff": [
        "apidocs spec-completeness diff vs route inventory on {target}",
        "GraphQL introspection + over-fetching check on {target}",
        "undocumented/shadow API endpoint discovery on {target}",
    ],
    "deserialization": [
        "insecure deserialization probing on {target}",
        "prototype pollution probing on {target} JS-handling endpoints",
    ],
    "jwt_crypto": [
        "JWT algorithm confusion / alg=none check on {target}",
        "weak crypto / predictable token check on {target}",
    ],
    "file_upload": [
        "file upload validation bypass on {target}",
        "path traversal / LFI probing on {target} file-serving endpoints",
    ],
    "rate_limiting": [
        "rate limit / brute-force protection check on {target} auth endpoints",
        "resource exhaustion / DoS-adjacent probing on {target}",
    ],
    "info_disclosure": [
        "verbose error / stack trace leak check on {target}",
        "debug endpoint / admin panel exposure check on {target}",
        "git/.env/config file exposure check on {target}",
    ],
    "business_logic": [
        "race condition probing on {target} payment/state endpoints",
        "business logic abuse (price/quantity manipulation) check on {target}",
        "workflow step-skipping probing on {target}",
    ],
    "http_smuggling": [
        "HTTP request smuggling probing on {target}",
        "cache poisoning probing on {target}",
    ],
    "subdomain_takeover": [
        "dangling DNS / subdomain takeover check on {target}",
    ],
}

ALL_CATEGORIES = list(TASK_CATEGORIES.keys())


def load_agents():
    """Reads agents.json (written by the Setup AI panel). Falls back to
    DEFAULT_WORKERS and writes the file if it doesn't exist yet."""
    if not os.path.isfile(AGENTS_PATH):
        save_agents(DEFAULT_WORKERS)
        return [dict(a) for a in DEFAULT_WORKERS]
    data = common.read_json(AGENTS_PATH, {}) or {}
    agents = data.get("agents", [])
    if not agents:
        return [dict(a) for a in DEFAULT_WORKERS]

    cleaned, seen = [], set()
    for a in agents:
        name = common.safe_agent_name(a.get("name"))
        model = (a.get("model") or "").strip()
        if not name or not model or name in seen:
            print("[dispatch] skipping invalid/duplicate agent entry: %r" % (a.get("name"),))
            continue
        seen.add(name)
        role = a.get("role") if a.get("role") in ("lead", "worker") else "worker"
        cleaned.append({
            "name": name,
            "role": role,
            "model": model,
            "api_key": a.get("api_key", ""),
        })
    return cleaned or [dict(a) for a in DEFAULT_WORKERS]


def save_agents(agents):
    common.atomic_write_json(AGENTS_PATH, {"agents": agents})


def split_roles(agents):
    leads = [a for a in agents if a.get("role") == "lead"]
    workers = [a for a in agents if a.get("role") != "lead"]
    if not workers:
        # A team of only leads still has to produce something.
        workers, leads = leads, []
    return leads, workers


def build_task_pool(categories):
    """Flatten selected categories into one pool of (category, template)."""
    cats = [c for c in (categories or ALL_CATEGORIES) if c in TASK_CATEGORIES]
    pool = []
    for category in cats:
        for template in TASK_CATEGORIES[category]:
            pool.append((category, template))
    if not pool:
        pool = [("recon", t) for t in TASK_CATEGORIES["recon"]]
    return pool


def plan_tools(categories):
    """{category: [selected tool ids]} — the toolchain this hunt will ask for."""
    plan = {}
    for category in (categories or ALL_CATEGORIES):
        if category in TASK_CATEGORIES:
            plan[category] = toolbox.tools_for_category(category)
    return plan


def report_missing_tools(categories):
    """Say loudly which selected tools are not installed, and how to fix it."""
    missing = toolbox.missing_for_categories(categories or ALL_CATEGORIES)
    if not missing:
        print("[dispatch] toolchain: every selected tool is installed\n")
        return
    print("[dispatch] WARNING: %d selected tool(s) are not installed:" % len(missing))
    for tool in missing:
        print("[dispatch]   - %s (%s)" % (tool["name"], tool["purpose"]))
        print("[dispatch]       install: %s" % tool["install"])
    if common.DEMO_MODE:
        print("[dispatch] demo mode is on, so the hunt still runs — results are simulated.")
    else:
        print("[dispatch] workers will refuse tasks whose tools are missing.")
    print()


def clear_live_state():
    """Wipe heartbeats and legacy findings. state/runs/ is history and stays."""
    common.ensure_dirs()
    for fname in os.listdir(common.STATE_DIR):
        path = os.path.join(common.STATE_DIR, fname)
        if not os.path.isfile(path):
            continue
        if fname.endswith(".json") or fname.endswith(".jsonl") or fname.endswith(".tmp"):
            try:
                os.remove(path)
            except OSError as exc:
                print("[dispatch] could not clear %s: %s" % (fname, exc))


def prepare_run(target, rounds, categories, agents, tool_plan=None, profile=None):
    clear_live_state()
    run_id = common.unique_run_id()
    os.makedirs(common.run_dir(run_id), exist_ok=True)
    common.atomic_write_json(common.meta_path(run_id), {
        "run_id": run_id,
        "target": target,
        "rounds": rounds,
        "categories": categories or ALL_CATEGORIES,
        "agents": [a["name"] for a in agents],
        "tools": tool_plan or {},
        "profile": profile or None,
        "started": common.now_iso(),
        "finished": None,
        "running": True,
        "demo": common.DEMO_MODE,
    })
    common.set_current_run_id(run_id)
    common.prune_runs()
    return run_id


def write_lead_state(lead, run_id, target, round_num, rounds, dispatched,
                     findings, note):
    """The lead is this process, not a task-taker. Keep its card honest."""
    common.atomic_write_json(os.path.join(common.STATE_DIR, lead["name"] + ".json"), {
        "name": lead["name"],
        "model": lead.get("model", ""),
        "role": "lead",
        "status": "LIVE",
        "task_id": "lead-r%d" % round_num,
        "task_desc": "orchestrating round %d/%d on %s — %d agents dispatched"
                     % (round_num, rounds, target, dispatched),
        "category": None,
        "run_id": run_id,
        "findings_count": findings,
        "last_report_ts": common.now_iso(),
        "note": note,
    })


def round_asset_count(run_id):
    return len({
        (a.get("value") or "").lower()
        for a in common.read_jsonl(common.assets_path(run_id))
        if a.get("value")
    })


def split_waves(items, size):
    """Split one round's task list into parallel waves.

    Every task appears exactly once: a 3-agent team asked to cover 4 categories
    runs 3 tasks, then 1, instead of silently dropping the fourth.
    """
    size = max(1, int(size or 1))
    items = list(items)
    return [items[i:i + size] for i in range(0, len(items), size)]


def spawn_wave(run_id, round_num, target, tasks, workers, offset=0):
    """Launch one task per worker for this wave, in parallel.

    A round covers the whole task pool, not just the first `len(workers)`
    entries: a 3-agent team with 4 selected categories used to silently skip
    one of them. The pool is split into waves of at most one task per worker,
    and each wave is genuinely parallel.
    """
    procs = []
    for i, worker in enumerate(workers):
        if i >= len(tasks):
            break
        category, template = tasks[i]
        task_id = "task-%d-%d" % (round_num, offset + i + 1)
        task_desc = template.format(target=target)
        tool_ids = toolbox.tools_for_category(category)
        print("[dispatch] round %d: %s -> %s: %s" % (round_num, worker["name"], task_id, task_desc))
        print("[dispatch]   tools: %s" % (", ".join(tool_ids) or "manual testing"))

        cmd = [
            PYTHON, os.path.join(ROOT, "worker.py"),
            worker["name"], worker["model"], task_id, task_desc,
            "--target", target,
            "--run", run_id,
            "--category", category,
            "--role", "worker",
        ]
        if tool_ids:
            cmd += ["--tools", ",".join(tool_ids)]
        env = os.environ.copy()
        if worker.get("api_key"):
            # Generic pass-through; OpenCode / your provider SDK reads whichever
            # env var it expects (OPENAI_API_KEY, ANTHROPIC_API_KEY, etc).
            env["AGENT_API_KEY"] = worker["api_key"]
        procs.append(subprocess.Popen(cmd, env=env, cwd=ROOT))
    return procs


def wait_for_wave(procs):
    """Wait in small slices so an emergency stop is noticed mid-task.

    Returns True when a stop was requested; the remaining processes in the
    wave are terminated so nothing keeps talking to the target.
    """
    stopped = False
    for p in procs:
        waited = 0.0
        while p.poll() is None:
            if common.stop_requested():
                stopped = True
                p.terminate()
                break
            time.sleep(0.25)
            waited += 0.25
            if waited > 900:
                print("[dispatch] worker exceeded 900s — terminating")
                p.terminate()
                break
    if stopped:
        for p in procs:
            if p.poll() is None:
                p.terminate()
    return stopped


def heartbeat_count():
    if not os.path.isdir(common.STATE_DIR):
        return 0
    return len([f for f in os.listdir(common.STATE_DIR) if f.endswith(".json")
                and f != "current_run.json"])


def warn_if_nothing_ran():
    """The classic silent failure: sys.executable is the Windows Store stub,
    Popen succeeds, nothing runs, and the hunt 'completes' instantly."""
    if heartbeat_count() == 0:
        print("\n[dispatch] WARNING: no agent ever wrote a heartbeat.")
        print("[dispatch]   interpreter: %s" % PYTHON)
        print("[dispatch]   That is usually the Microsoft Store python stub rather "
              "than a real Python.")
        print("[dispatch]   Run 'python -c \"import sys; print(sys.executable)\"' and "
              "make sure it is not under WindowsApps.\n")


def run_hunt(target, rounds, categories=None, fresh_state=True, profile_result=None):
    agents = load_agents()
    leads, workers = split_roles(agents)
    if not workers:
        raise ValueError("no worker agents configured — add at least one agent "
                         "with role 'worker' in Setup AI before starting a hunt")
    tool_plan = plan_tools(categories)
    run_id = prepare_run(target, rounds, categories, agents,
                         tool_plan=tool_plan, profile=profile_result)
    pool = build_task_pool(categories)

    print("[dispatch] target: %s" % target)
    print("[dispatch] run: %s" % run_id)
    print("[dispatch] categories: %s" % ", ".join(categories or ALL_CATEGORIES))
    print("[dispatch] %d agents (%d lead), %d rounds"
          % (len(workers), len(leads), rounds))
    print("[dispatch] dashboard reads from: %s\n" % common.STATE_DIR)
    report_missing_tools(categories)

    # The surface profile is the first thing a lead would write down: what the
    # target is, and which bug classes are worth the first hour. It is stored
    # as a finding so it shows up in the feed, not only in meta.json.
    if profile_result and profile_result.get("ok"):
        top = [c for c in profile_result.get("categories", [])
               if c.get("confidence") in ("high", "medium")][:6]
        techs = ", ".join(
            t["name"] + (" " + t["version"] if t.get("version") else "")
            for t in profile_result.get("technologies", [])[:8]) or "no clear stack"
        common.append_jsonl(common.findings_path(run_id), {
            "ts": common.now_iso(),
            "run_id": run_id,
            "agent": (leads[0]["name"] if leads else "dispatch"),
            "role": "lead",
            "task_id": "surface-profile",
            "category": None,
            "severity": "lead",
            "title": "surface profile: %s — likely %s" % (
                techs, ", ".join(c["category"] for c in top) or "no strong signal"),
            "host": scope_guard.host_of(target),
            "url": profile_result.get("final_url") or profile_result.get("base_url"),
            "param": None,
            "payload": None,
            "evidence": "status %s; %s" % (
                profile_result.get("status"),
                "; ".join("%s (%s): %s" % (c["category"], c["confidence"], c["reason"])
                          for c in top) or "see the target-check panel"),
            "command": None,
            "demo": common.DEMO_MODE,
        })

    try:
        used = set()
        for r in range(1, rounds + 1):
            if common.stop_requested():
                print("[dispatch] STOP requested before round %d — stopping." % r)
                break

            # One round = one pass over the whole task pool. If the pool was
            # already covered in earlier rounds, start a fresh pass. Waves are
            # parallel; the next wave starts when the previous one finishes.
            remaining = [item for item in pool if item not in used]
            if not remaining:
                used.clear()
                remaining = list(pool)
            random.shuffle(remaining)
            queued = len(remaining)
            for lead in leads:
                write_lead_state(lead, run_id, target, r, rounds, len(workers),
                                 0, "%d task(s) queued for round %d" % (queued, r))

            stopped = False
            dispatched = 0
            for wave, batch in enumerate(split_waves(remaining, len(workers)), 1):
                for item in batch:
                    used.add(item)
                procs = spawn_wave(run_id, r, target, batch, workers,
                                   offset=dispatched)
                dispatched += len(batch)
                if wave > 1:
                    print("[dispatch] round %d: wave %d (%d task(s))"
                          % (r, wave, len(batch)))
                if wait_for_wave(procs):
                    stopped = True
                    break
            if stopped:
                print("[dispatch] STOP requested — terminating this round.")
                break

            if r == 1:
                warn_if_nothing_ran()

            findings = len(common.dedupe_findings(
                common.read_jsonl(common.findings_path(run_id))))
            for lead in leads:
                write_lead_state(lead, run_id, target, r, rounds, len(workers),
                                 findings,
                                 "round %d done: %d findings, %d assets"
                                 % (r, findings, round_asset_count(run_id)))
            print("[dispatch] round %d complete\n" % r)
            time.sleep(1)
    finally:
        meta = common.read_json(common.meta_path(run_id), {}) or {}
        meta.update({"finished": common.now_iso(), "running": False,
                     "stopped": bool(common.stop_requested())})
        common.atomic_write_json(common.meta_path(run_id), meta)

    findings = common.dedupe_findings(common.read_jsonl(common.findings_path(run_id)))
    assets = round_asset_count(run_id)
    for lead in leads:
        common.append_jsonl(common.findings_path(run_id), {
            "ts": common.now_iso(),
            "run_id": run_id,
            "agent": lead["name"],
            "role": "lead",
            "task_id": "summary",
            "category": None,
            "severity": "lead",
            "title": "run complete: %d unique findings, %d assets over %d rounds"
                     % (len(findings), assets, rounds),
            "host": None, "url": None, "param": None, "payload": None,
            "evidence": "round summaries above; see the Runs tab for the diff against the previous run",
            "command": None,
            "demo": common.DEMO_MODE,
        })
        write_lead_state(lead, run_id, target, rounds, rounds, len(workers),
                         len(findings), "hunt complete")

    print("[dispatch] all rounds complete — run %s" % run_id)


def main():
    if len(sys.argv) < 2:
        print("usage: python dispatch.py <target> [rounds] [categories-csv]")
        print('example: python dispatch.py "example.com" 3 recon,idor,ssrf')
        print("available categories: %s" % ", ".join(ALL_CATEGORIES))
        sys.exit(1)
    target = sys.argv[1]
    try:
        rounds = int(sys.argv[2]) if len(sys.argv) > 2 else 3
    except ValueError:
        print("rounds must be a number")
        sys.exit(1)
    categories = sys.argv[3].split(",") if len(sys.argv) > 3 else None

    if not 1 <= rounds <= 20:
        print("rounds must be between 1 and 20")
        sys.exit(1)
    unknown = [c for c in (categories or []) if c not in TASK_CATEGORIES]
    if unknown:
        print("unknown categories: %s" % ", ".join(unknown))
        print("available: %s" % ", ".join(ALL_CATEGORIES))
        sys.exit(1)

    run_hunt(target, rounds, categories)


if __name__ == "__main__":
    main()
