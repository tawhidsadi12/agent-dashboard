# Hunt Console — multi-agent bug bounty orchestrator

A local, evidence-first platform for **authorized** bug bounty work. A lead
process plans the hunt, several worker processes run in parallel, and every
finding must carry the request that produced it. The dashboard shows live
agents, a ranked plan, playbooks for all 18 categories, per-run diffs, logs with
an audit trail, and an emergency stop.

Two rules shape a hunt:

1. **Scope is lenient by default, out-of-scope is hard.** A target that is not
   listed is added to the in-scope list at hunt start (audited as
   `scope.auto_add`). Out-of-scope entries always block, and every request is
   re-checked inside the worker and for every discovered asset. Turn on
   “Only allow targets already in the in-scope list (strict)” to make the list
   authoritative; `HUNT_STRICT_SCOPE=1` pins it for a deployment.
2. **Written authorization is a record, and optionally a gate.** The Scope panel
   stores program, reference and confirmation in `authorization.json`. By
   default the record is optional; turn on
   “Block hunts until this record is confirmed” to return **409** without it.
   `HUNT_REQUIRE_AUTH=1` pins the gate for a deployment (and `=0` pins it off).

Everything runs against targets you are allowed to test. The tool catalog is
listed so a manual tester knows what to install; nothing in this project grants
permission to run it.

---

## Quick start

### One command, no Docker

```bash
python3 hunt.py example.com          # 3 rounds against a target you may test
python3 hunt.py example.com 5        # 5 rounds
python3 hunt.py example.com 3 xss,ssrf
python3 hunt.py --web                # dashboard on http://127.0.0.1:8777
python3 hunt.py --tools              # installed / missing catalog tools
```

The first run creates `.venv` and installs Flask, so a fresh clone needs nothing
else. The target is added to `scope.json` the same way the dashboard does it;
out-of-scope hosts and a required-but-missing authorization record still refuse
the run. `python3 hunt.py --install-tools` lays down the catalog on Linux (sudo,
slow, re-runnable) — without it, a worker whose stage tool is missing refuses
that task.

### Docker (recommended everywhere)

```bash
docker compose up -d --build
# open http://127.0.0.1:8777
```

The image contains the full toolchain. The build runs `selftest.py`, compiles
every module and imports the app, so a broken image cannot be produced
silently. Hunts started from the UI spawn worker processes inside the same
container.

```bash
docker compose logs -f dashboard        # server output
docker compose exec dashboard python selftest.py
docker compose exec dashboard python dispatch.py example.com 3
docker compose down                     # stop, keep history
docker compose down -v                  # stop and wipe history
```

The UI has **no authentication** and can spawn agents. The compose file
publishes it on `127.0.0.1` only — do not change that to `0.0.0.0`.

Runtime data lives in the `hunt-data` volume (`/data`): `state/`, `logs/`,
`scope.json`, `authorization.json`, `agents.json`, `tools.json`. To use a host
folder instead, comment out the named volume and use `- ./data:/data`; on Linux
create it with `mkdir -p data && sudo chown -R 1000:1000 data`.

### Native Python (3.10+)

Use a real Python, not the Microsoft Store stub:

```bash
python -c "import sys; print(sys.executable)"   # must NOT be under WindowsApps
pip install -r requirements.txt
python selftest.py
python server.py                                # http://127.0.0.1:8777
python dispatch.py example.com 3                # optional CLI hunt
```

Native mode gives you the dashboard and the built-in bounded checks. The
Go/release installers are POSIX shell scripts and expect Linux, macOS or WSL2;
on Windows, use Docker or WSL2 for the full toolchain.

---

## UI tour

| tab | what it is for |
|---|---|
| **Dashboard** | target form, scope + authorization panel, ranked plan, category chips, live agent cards |
| **Findings** | filterable table with severity, evidence, the reproducing command and duplicate counts |
| **Runs** | one folder per hunt, diffed against the previous run (new assets, new findings, gone) |
| **Activity & logs** | live tail, per-agent log viewer, delete one log, clear all logs with a typed confirmation, audit trail |
| **Playbooks** | step-by-step methodology, commands, evidence requirements and pitfalls for all 18 categories |
| **Tools** | 24 stages, one selected tool per stage, READY / NEED INSTALL, exact install command |
| **Setup AI** | agent name, role, model, optional API key |

The front end is split into `static/dashboard.html`, `static/app.css` and
`static/app.js`. The pre-redesign UI is preserved as
`static/dashboard.legacy.html`; the server does not serve it.

---

## Safety model

### Scope

In-scope entries allow a host and its subdomains; out-of-scope always wins:

| entry | matches |
|---|---|
| `example.com` | `example.com` and every subdomain |
| `*.example.com` | the same — the `*.` is stripped, apex included |
| `api.partner.com` | exactly that host |
| `10.0.0.0/8` | any address in the range |
| `https://app.x.com/a` | scheme, path and port ignored |

Checks happen at three layers:

1. `/api/start`, `/api/profile` and `/api/plan?profile=1` refuse an
   out-of-scope target before any request.
2. Every worker calls `scope_guard.assert_allowed()` before its task.
3. Every discovered asset (subdomain, URL, redirect target) is checked before
   it is stored or probed. A CNAME into a third-party SaaS is out of scope even
   when it matched your wildcard.

Lenient mode (the default) makes the in-scope list a record rather than a gate:
**Start hunt** sends a `POST /api/start`, where a target that is not listed is
appended (`scope.auto_add`). Existing entries are preserved. A host that matches
an out-of-scope entry is never added and is refused before any request.

Strict mode makes the list authoritative: an unlisted target returns **403**.
Toggle “Only allow targets already in the in-scope list (strict)” in the Scope
panel, or pin it with `HUNT_STRICT_SCOPE=1` (and `HUNT_STRICT_SCOPE=0` pins lenient).

**Check & plan** is a GET, and GETs never write scope. In lenient mode the
server may profile a not-yet-listed target, but only when the dashboard sends
`X-Hunt-Request: 1`; a cross-site image/link cannot set that header. Out-of-scope
entries block in every mode. `allow_empty=True` exists only for offline unit
tests; no HTTP surface uses it.

### Written authorization

The Scope panel records the program, URL, authorizer, reference, window and
rate limit, plus an explicit confirmation checkbox. This is a local record, not
proof by itself — it is the trail you need when someone asks why a request was
sent. Saving scope does not confirm authorization.

`GET/POST /api/authorization` manages the record. Whether it is *required* is a
separate switch in the same panel (“Block hunts until this record is
confirmed”), stored in `settings.json` via `POST /api/settings`:

| configuration | effect |
|---|---|
| toggle off (default) | hunts and live profiles run with only a non-empty scope; the record is informational |
| toggle on | a hunt or live profile request without `confirmed: true` returns **409** with `requires_authorization: true` |
| `HUNT_REQUIRE_AUTH=1` / `=0` | pins the gate on/off; the UI checkbox is disabled and shows why |

The scope list is never optional. Turning the gate off does not relax any
per-request scope check.

### Write protection

All POST/PUT/PATCH/DELETE requests require the `X-Hunt-Request: 1` header and a
same-origin `Origin` when one is sent. A cross-site HTML form cannot set that
header, so it cannot start a hunt or change scope. `HUNT_CSRF_PROTECT=0` is an
escape hatch for scripted demos only.

### Emergency stop

`POST /api/stop` writes `state/STOP`. Dispatch checks it between waves and
terminates running workers; each worker checks it before its first request and
between steps. `DELETE /api/stop` clears the latch. The run's `meta.json` gets
`"stopped": true`, and the stop/clear actions are audited.

### Demo mode

`HUNT_DEMO_MODE=1` simulates findings and **disables live profiling**, so a
demo cannot generate traffic by accident. Demo findings are tagged `DEMO` in
the UI and in `findings.jsonl`.

### Audit trail

Scope changes, authorization changes, hunt starts, stop/clear and log deletions
are appended to `state/audit/audit.jsonl` and shown in Activity. Log deletion
is audited *before* the file is removed.

---

## Playbooks and the ranked plan

`methods.py` contains one playbook per hunting category. Each has an objective,
why it matters, 4–6 concrete steps, command templates, recommended tools,
manual notes, evidence requirements, pitfalls, references and a severity hint.
`selftest.py` fails if a category exists without a playbook.

`planning.py` turns the surface profile into an ordered list:

- baseline categories worth a first pass on almost any web target;
- confidence from `surface.py` (high/medium/low);
- surface boosts for an observed form, upload field, GraphQL endpoint, JWT,
  API documentation, redirect/SSRF parameter, object ids or missing CSP;
- an explicit `scripted` or `manual` label per step, with the first two actions.

**Auto plan** profiles the target with ordinary GETs, ranks the categories, and
starts the hunt with the result. Clicking a category chip switches to manual
selection; **Use scripted categories** applies only the categories that have
bounded checks.

A round is one pass over the whole task pool. With three workers and four
selected categories, tasks run in parallel waves (3, then 1) rather than
silently dropping the fourth category.

---

## Automated checks vs manual categories

`checks.run()` automates eight categories because a script can prove the
result from an HTTP response:

| category | what it does | what a finding means |
|---|---|---|
| `recon` | DNS + `subfinder` (when installed) and HTTP fingerprinting | in-scope names become assets, not findings |
| `info_disclosure` | the ordinary GETs from the target check | readable `.git`/`.env`/actuator, directory listing, verbose error, source map |
| `csrf_cors` | CORS origins, frame protection, POST form token check | reflected/null origin with credentials; missing frame protection; no CSRF token |
| `redirect` | link-derived redirect parameters, `Location` read without following | a 3xx to the chosen marker host |
| `xss` | a unique reflected marker in link/input parameters | the marker comes back **unencoded** (`likely`; confirm execution in a browser) |
| `js_audit` | up to six same-origin script files | credential-shaped strings (redacted), a readable `.map`; endpoints become assets |
| `api_diff` | common OpenAPI paths + one GraphQL introspection POST | exposed spec, enabled introspection (`dig`, not a vulnerability by itself) |
| `subdomain_takeover` | CNAME lookup + unclaimed-service fingerprints | a CNAME into a service that says "NoSuchBucket"/"No such app" |

Everything else is manual by design: `auth_session`, `access_control`,
`injection`, `ssrf`, `deserialization`, `jwt_crypto`, `file_upload`,
`rate_limiting`, `business_logic`, `http_smuggling`, and the manual parts of
the categories above. They need a session, a second account, an out-of-band
listener or a payload that can damage a shared cache. The worker logs the
manual test and tool to use instead of inventing a finding.

Every request is scope-checked first, redirects are never followed off-scope,
and the request list is written to the agent log. Per category the budget is
40 seconds / 40 requests.

### Deduplication

`finding_dedupe_key` hashes host, path, parameter **names** and title. Query
*values* are dropped, so a per-request XSS marker cannot turn one reflection
into six findings; different paths and parameter names remain separate. The
JSONL stays append-only; the header counts unique findings and shows
`seen N×`.

---

## Tools

The **Tools** tab has **81 tools across 24 stages**, generated from
`toolbox.py`. Each stage selects one tool:

| column | meaning |
|---|---|
| **select** | the tool this stage uses; alternatives are one click away |
| **READY / NEED INSTALL** | whether the binary is on `PATH` right now |
| **github.com/…** | the upstream repository |
| **install command** | exactly what would add it (shown only while missing) |
| **needed by** | which task categories pull in this stage |

Selection is saved to `tools.json` and survives restarts. Detection is
`shutil.which` plus a short `--version` probe, cached for 60 seconds.
**Re-detect** forces a fresh probe. Nothing installs automatically.

The image bakes in every stage's default tool, including the cloud
(`cloudlist`), secret-scanning (`noseyparker`), GraphQL (`graphql-cop`) and
interception (`mitmproxy`) stages. Alternative tools are catalogued with their
install command but are not baked in; select one and the Tools tab tells you how
to add it. `caido` is a desktop application and intentionally not installed in
the container.

### How a hunt picks its tools

`toolbox.CATEGORY_NEEDS` maps each category to stages. An empty list means
manual testing — no binary exists for access control or business logic. At
hunt time:

1. `/api/start` preflights only the selected categories. In real mode a missing
   tool refuses the hunt (409) with the names and commands.
2. `dispatch.py` records the plan in `meta.json` and passes `--tools` to each
   worker.
3. `worker.py` logs `tool(installed, not executed here)` or `tool(NEED
   INSTALL)` and never claims a catalog tool ran when it did not. The built-in
   bounded checks are what actually execute.

### Installing tools

The Docker image has five installer groups:

| script | installs |
|---|---|
| `tools/install-apt-tools.sh` | apt runtime deps + `wpscan` |
| `tools/install-go-tools.sh` | Go tools, compiled in a builder stage |
| `tools/install-release-tools.sh` | GitHub release binaries (findomain, feroxbuster, cloudlist, noseyparker, …) |
| `tools/install-python-tools.sh` | pipx packages (arjun, sqlmap, ghauri, mitmproxy, …) |
| `tools/install-git-tools.sh` | checkout tools (XSStrike, jwt_tool, nikto, SecLists, …) and graphql-cop in its own venv |

Release binaries are found by following `releases/latest` and reading the
public `expanded_assets` page — not the rate-limited GitHub API. A failed
installer is reported and skipped; the Tools tab shows what actually landed.
`rengine` is a separate Docker Compose platform and is catalogued but not
installed.

---

## Setup AI

Each row is one agent:

- **name** — shown on the dashboard card;
- **role** — `lead` (orchestrator identity) or `worker` (takes tasks);
- **model** — the identifier your runtime expects;
- **api key** — optional, stored in `agents.json`, never echoed back.

Leads are never handed a scanning task. `dispatch.py` reports through the lead
card and writes one closing summary finding. If every agent is a lead, they run
as workers rather than doing nothing. At least one worker is required; the
server refuses a hunt otherwise.

The built-in checks are plain Python and need no model. If you wire an
OpenCode/LLM call for the manual categories, pass the task to it at the point
where `checks.run()` returns a manual note, and keep the heartbeat, scope check
and log streaming around it.

---

## Platform support

### Kali Linux (recommended)

- Docker Engine + Compose plugin are normally present:
  `docker compose up -d --build`, then `http://127.0.0.1:8777`.
- Native mode also works: `python3 server.py`, then install tools from the
  Tools tab. The installer scripts are POSIX shell and run on Kali directly.
- Do not publish the UI beyond loopback.

### Windows 11

- **Docker Desktop** is the supported path for the full toolchain.
- Native Windows runs the dashboard and the built-in checks if Python is a real
  install (python.org, not the Microsoft Store stub). `python -c "import sys;
  print(sys.executable)"` must not print a `WindowsApps` path.
- The Go/release installers are bash; use Docker or WSL2 for those.

### WSL2

- Install Docker Desktop with the WSL2 backend, or Docker Engine inside WSL2.
  Run `docker compose up -d --build` from the project inside WSL2.
- Native WSL2 also works for `python3 server.py` and the installer scripts.
- Keep the repository inside the Linux filesystem (`~/...`) for file-watch and
  performance sanity; the dashboard itself does not watch files.

### Verification without a real target

The repository's tests use a local mock only:

```bash
python selftest.py
# inside the container, after copying the E2E script:
# 44 checks: CSRF gate, lenient vs strict scope, dashboard-header-gated live
# profile, authorization gate on/off, playbooks, plan (including upstream-error
# vs scope refusal), logs, stop latch, wave coverage, XSS reflection + dedupe,
# auto-plan start, log deletion
```

The current build passes `selftest.py` and a 44-point containerized API test
against a reflective `127.0.0.1` mock. No external target was contacted.

---

## Architecture

```
agent-dashboard/
├── hunt.py          # one-command entry point: venv bootstrap, scope, hunt
├── server.py        # Flask app: UI + API, write gates, authorization, stop, logs
├── dispatch.py      # lead: plans rounds, runs parallel waves, checks stop
├── worker.py        # one agent: heartbeat, scope checks, findings, assets
├── common.py        # shared layout, atomic writes, dedupe, run diffing, stop/auth
├── scope_guard.py   # the single "is this host allowed?" decision
├── surface.py       # bounded target profile; pure analysis is unit-tested
├── checks.py        # eight bounded, evidence-based automated checks
├── methods.py       # 18 playbooks: steps, commands, evidence, pitfalls
├── planning.py      # ranked, explained hunt plan
├── logs.py          # bounded log reads, safe deletion, audit trail
├── toolbox.py       # 81-tool / 24-stage catalog, selection, PATH detection
├── selftest.py      # dependency-free checks for the pure logic
├── static/
│   ├── dashboard.html       # UI shell
│   ├── app.css              # design system
│   ├── app.js               # UI logic, CSRF header, dirty-field guard
│   └── dashboard.legacy.html
├── tools/           # five installer groups used at image build time
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

Runtime layout under `HUNT_DATA_DIR`:

```
state/<agent>.json          live heartbeat per agent
state/STOP                  emergency-stop latch
state/runs/<run_id>/        meta.json, findings.jsonl, assets.jsonl
state/audit/audit.jsonl     scope/auth/hunt/stop/log actions
logs/<agent>.log            worker log, trimmed at 5 MB
scope.json                  in/out-of-scope
authorization.json          written-authorization record
settings.json               whether the authorization record is required
agents.json                 team (never baked into the image)
tools.json                  selected tool per stage
```

The newest 20 runs are kept (`common.MAX_RUNS`); older run folders are pruned
so history does not grow without bound. Within a run, findings and assets are
append-only.

### Finding shape

```json
{"ts": "...", "agent": "worker-glm", "severity": "likely",
 "title": "Raw HTML reflection in q on app.example.com/search",
 "host": "app.example.com", "url": "https://app.example.com/search?q=...",
 "param": "q", "payload": "marker<svg/onload=alert(1)>",
 "evidence": "payload returned unencoded in a 200 response: ...",
 "command": "dalfox url 'https://app.example.com/search?q=test'",
 "category": "xss", "demo": false, "dedupe_key": "a1b2c3..."}
```

A finding you cannot reproduce is a finding you cannot report. Severity
`likely` means the response is evidence but browser execution was not proven;
`confirmed` is reserved for proof.

### Avoiding race conditions

Each worker writes only its own heartbeat file, using an atomic
write-to-temp-then-`os.replace`. Findings and assets are appended to the
current run's `.jsonl`. At more than ~10 concurrent workers, move those two
files to SQLite.

---

## Extending it

- **Add a category** — add a key to `TASK_CATEGORIES` and a playbook to
  `methods.py` (selftest fails until both exist). Add a check to `checks.py` and
  map it in `checks.run()` if it can be proven safely; otherwise leave it
  manual.
- **Add a tool** — one line in `toolbox._RAW` plus an installer line. `default:
  True` marks the stage default; add `BIN_OVERRIDES` when the binary name
  differs.
- **Coverage tracking** — write `coverage.jsonl` (host, endpoint, tool,
  timestamp) and surface "new asset that nobody has touched yet".
- **Scheduled runs / notifications** — `dispatch.py` is a CLI; cron can run it
  and `/api/diff` names what changed.
- **Verifier pass** — a second agent re-running the `command` of every
  `confirmed` finding before report writing.

## Limitations

- The UI has no authentication; keep it on loopback.
- Automated checks cover 8 of 18 categories; the rest are honest manual notes.
- `xss` proves unencoded reflection, not browser execution. Confirm in a
  browser before reporting.
- The catalog is installed for Linux containers; Windows-native installs of
  the Go/release tools are not automated.
- `naabu`-style raw-socket tools and `caido` need manual setup; the Tools tab
  shows the command or the reason.
- CTF mode is **not** implemented. This build is bug-bounty only; no CTF
  exploitation path or target transfer exists. Do not use bounty techniques
  against CTF infrastructure or the reverse.
