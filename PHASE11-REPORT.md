# Phase 11 — before/after report and modified-file ledger

Date: 2026-11-12
Scope: UI/UX, playbooks and plan, tool catalog, log management, Auto Mode,
round orchestration, deduplication, API semantics, documentation, installers.
Project: `F:\agent-dashboard` (not a git repository; no commits exist).

All tests were run against a local reflective mock (`127.0.0.1:8899`) inside a
disposable Docker container. No external target was contacted.

---

## 1. Verification evidence

| check | result |
|---|---|
| `selftest.py` (dependency-free logic suite) | **142/142 assertions pass** |
| Containerized API/E2E test | **44/44 pass** |
| Tool catalog probe | **81 tools · 24 stages · 24/24 selected defaults installed · 0 missing** |
| UI, desktop browser | Tools, Playbooks, Findings, Runs, Activity, logs and modal verified; **no console errors** |
| External traffic | none; mock only |
| Image build | build-time compile + `selftest.py` + app import pass |

The E2E run covers: CSRF gate, lenient scope (a plan GET without the dashboard
header stays blocked, start appends the target), strict scope blocking an
unlisted target, out-of-scope exclusions in both modes, the authorization record
and gate on/off, 18 playbooks, plan ranking, plan `502` vs `403`, log
listing/clear guard, stop latch and clear, hunt start, round completion, run
recording, agent logs, one-round coverage of every selected category, XSS
reflection on the mock, cross-template dedupe, Auto Mode using the ranked plan,
log read and log delete.

---

## 2. Before / after

Status scale: **PASS / PARTIAL / FAIL / MISSING / NEEDS REVIEW**.

| ID | Area | Before | After | Status |
|---|---|---|---|---|
| UIX-01 | Dashboard layout | One 48 KB `dashboard.html` with inline CSS/JS; cramped sections, no tabs | Split UI (`dashboard.html`, `app.css`, `app.js`) with Dashboard, Findings, Runs, Activity, Playbooks, Tools, Setup AI; old UI preserved as `dashboard.legacy.html` | PASS |
| UIX-02 | Form state | Slow boot responses could overwrite text the operator had already typed | Dirty-field guard marks typed/toggled fields and loaders skip them; saving clears the mark | PASS |
| UIX-03 | Plan presentation | Category scores without an order, scripted/manual distinction or reasons | Ranked steps with score, confidence, `SCRIPTED`/`MANUAL`, evidence reason, first two actions and apply buttons | PASS |
| UIX-04 | Plan reasons | Duplicated wording (`no Content-Security-Policy (no Content-Security-Policy)`), repeated CSP fact | Stutter removed in `surface.py`; `planning.py` no longer restates a missing CSP; selftest asserts it appears once | PASS |
| UIX-05 | Logs | Plain text tail; no deletion, no confirmation, no audit entry | Per-agent viewer, delete one, clear all behind a modal that requires typing `CLEAR`; every deletion audited before removal | PASS |
| PB-01 | Hunting methodology | Task templates only; no step-by-step operator guidance | 18 playbooks: objective, why, 4–6 steps, commands, tools, manual notes, evidence, pitfalls, references, severity hint; selftest fails if a category has no playbook | PASS |
| PLAN-01 | Planning | Category list from the profiler, unranked, no explanation | `planning.py` ranks profile + baseline + surface boosts, labels automated/manual, explains each step | PASS |
| PLAN-02 | Auto Mode | Started only high/medium profile categories, so a boosted low-confidence category (e.g. XSS with no CSP) was skipped | Auto start uses `build_plan(...).automated`, the same ranked scripted list the Plan button shows; UI says “ranked plan (scripted categories)” | PASS |
| ORCH-01 | Round coverage | With 3 workers and 4 selected categories, the fourth category was silently never dispatched | A round is one pass over the whole pool, executed in parallel waves (3 then 1); selftest covers split/order/worker bound | PASS |
| ORCH-02 | Worker guard | A team with no workers failed late or ambiguously | `run_hunt` raises a clear error; the server refuses the hunt; UI shows the message | PASS |
| DED-01 | Findings dedupe | Per-request XSS marker in the query string produced six near-identical findings | Dedupe key keeps host, path and parameter **names**, drops query values; two sinks stay separate, repeats show `seen 3×` | PASS |
| API-01 | Plan error semantics | An unreachable target returned `403`, implying an authorization failure | Scope refusal stays `403`; unreachable/upstream failure is `502` with the profile body | PASS |
| CAT-01 | Tool catalog | ~66 tools; 20 of 24 stage defaults installed; catalog and image disagreed | 81 tools across 24 stages; installer coverage for cloudlist, noseyparker, graphql-cop, mitmproxy; image probe reports 24/24 selected installed | PASS |
| INST-01 | Installer drift | Nothing detected a catalog default that no installer bakes in | Selftest asserts every stage default is named by an installer script; fixed stale testssl repo and nikto path | PASS |
| DOC-01 | Documentation | Partial README, no workflow or safety model | README rewritten: UI tour, safety model, playbooks/plan, 81-tool catalog, dedupe, installers, Kali/Windows/WSL2, verification, limitations | PASS |
| TEST-01 | Verification | Phase 8 suite covered pure logic only | 142 selftest assertions plus a 44-point containerized API test; build runs the suite before tagging an image | PASS |
| SEC-01 | Write protection | State-changing requests had no CSRF defense | `X-Hunt-Request: 1` plus same-origin `Origin`; escape hatch `HUNT_CSRF_PROTECT=0` | PASS |
| SEC-02 | Authorization | A hunt was blocked until a written authorization was confirmed; there was no way to make the gate optional | Authorization is a stored record; the Scope panel toggle can block hunts until it is confirmed (default off). `HUNT_REQUIRE_AUTH` pins the gate. A blocked request returns `409` | PASS |
| SEC-03 | Empty scope | An empty in-scope list could behave as “allow” | Lenient scope appends the submitted target at start (audited, see Amendment 3); strict mode and `allow_empty=False` remain fail-closed; out-of-scope always blocks | PASS |
| SEC-04 | Emergency stop | No way to stop a running hunt | `state/STOP` latch written by `POST /api/stop`, checked between waves and inside workers; run `meta.json` records `stopped`; stop/clear audited | PASS |
| DEMO-01 | Demo mode | Demo mode could still profile a live target | `HUNT_DEMO_MODE=1` disables live profiling and tags simulated findings `DEMO` | PASS |

---

## 3. Remaining issues (not regressions, deliberate or out of scope)

| ID | Module | Current behavior | Problem / impact | Severity | Fix / status |
|---|---|---|---|---|---|
| CTF-01 | (no module) | Bug-bounty mode only | CTF mode and CTF→bounty transfer are not implemented | P1 for product scope | **MISSING** — requires an explicit design that keeps the two modes isolated |
| AUTH-01 | `server.py` | No login; UI bound to `127.0.0.1` | Anyone with local access can start hunts; exposing it would be unsafe | P1 if published | **MISSING** — documented loopback-only; add auth/reverse proxy before any remote use |
| AI-01 | `worker.py` | Built-in checks are plain Python; manual categories log a note | No LLM runtime drives manual exploration or explains findings | P2 | **NEEDS REVIEW** — hook point documented in README; choice of provider is a user decision |
| COV-01 | `checks.py` | 8 of 18 categories run bounded checks | Remaining categories are honest manual notes, not automation | P2 (by design) | **PARTIAL** — adding safe checks requires per-category proof, not more payloads |
| XSS-01 | `checks.py` | Reports unencoded reflection as `likely` | Reflection is not proof of execution | P2 | **PARTIAL** — confirm in a browser; `confirmed` is reserved for proof |
| TOOL-01 | `toolbox.py` | One default baked per stage; alternatives catalogued | Selecting an alternative may need an install | P3 | **PARTIAL** — Tools tab shows the exact command; nothing installs automatically |
| WIN-01 | installers | Go/release/git installers are POSIX shell | Native Windows lacks the full toolchain | P3 | **PARTIAL** — Docker Desktop is the supported path; WSL2 also works |
| RAW-01 | `toolbox.py` | `naabu`/raw-socket tools need capabilities | May fail without `CAP_NET_RAW` or host tuning | P3 | **NEEDS REVIEW** — catalogued, not relied on by automated checks |
| SCALE-01 | `common.py` | Findings/assets append to JSONL | Above ~10 concurrent workers, append contention grows | P3 | **NEEDS REVIEW** — documented; move to SQLite at that scale |
| CTF-02 | `dispatch.py` | No CTF categories | Accidental cross-mode execution is impossible today | P2 | **MISSING** — keep isolated when implemented; do not share target state |

---

## 4. Modified-file ledger

Every file below was changed or created during this upgrade. Runtime folders
(`state/`, `logs/`, `data/`, `__pycache__/`) and user data
(`agents.json`, `scope.json`, `authorization.json`, `tools.json`) are excluded.

| File | Type | Change | Verified by |
|---|---|---|---|
| `server.py` | modified | Playbook/plan/authorization/stop/log APIs; CSRF + authorization gates; empty-scope target adoption on start (`scope.auto_add`); `502` vs `403`; Auto Mode ranked plan; audit events; scope/demo summary in `/api/state` | E2E 36 checks, UI |
| `dispatch.py` | modified | `split_waves` / `spawn_wave` / `wait_for_wave`; one round covers the whole pool; stop-aware waves; no-worker guard | selftest, E2E wave coverage |
| `worker.py` | modified | Stop checks before/during work; truthful tool logs; log trimming; no start under stop | E2E, log inspection |
| `common.py` | modified | `_stable_url` + dedupe key; authorization/stop helpers; authorization-gate setting; atomic writes; run pruning | selftest dedupe checks, E2E |
| `scope_guard.py` | modified | Lenient/strict scope; `missing_from_scope` and `adopt_if_empty` decision helpers; out-of-scope always wins; `allow_empty` reserved for offline tests | selftest, E2E |
| `checks.py` | modified | Eight bounded, evidence-based checks refined during the upgrade (XSS reflection evidence, category notes) | E2E XSS/dedupe |
| `surface.py` | modified | Profiler reason de-duplication; demo-mode guard; form/upload/JWT/GraphQL/API/redirect/SSRF signals | selftest, plan API |
| `methods.py` | new | 18 playbooks, `AUTOMATED` set, `validate()`, command helpers | selftest, UI Playbooks |
| `planning.py` | new | Ranked plan, surface boosts, scripted/manual labels, CSP reason suppression | selftest, plan API, UI |
| `logs.py` | new | Bounded list/read; path-safe delete; `CLEAR` confirmation; audit trail | selftest, E2E, UI modal |
| `toolbox.py` | modified | 81 tools / 24 stages; selection, PATH detection, summaries; cloud/GraphQL/secrets/intercept entries | tool probe 24/24, UI Tools |
| `static/dashboard.html` | new | UI shell and seven tabs | Browser |
| `static/app.css` | new | Design system, responsive layout, cards, chips, tables, modal | Browser |
| `static/app.js` | new | UI logic, CSRF header, dirty-field guard, plan/playbook/tools/logs rendering; scope seeding before a plan and post-start scope refresh | Browser, no console errors |
| `static/dashboard.legacy.html` | new | Pre-redesign UI preserved; not served | File inspection |
| `selftest.py` | modified | 142 assertions: scope, lenient/strict mode, target adoption, authorization gate, dedupe, profiler, plan, logs, stop, waves, installer drift | selftest 142/142 |
| `README.md` | modified | Rewritten: UI, safety model, playbooks/plan, tools, installers, platform support, limitations | Review |
| `Dockerfile` | modified | Build-time compile + selftest + import; copies `tools/` for the drift check | Image build |
| `docker-compose.yml` | modified | Loopback-only publish, `/data` volume, demo-mode documentation | Review |
| `tools/install-apt-tools.sh` | modified | Runtime dependencies + `wpscan` | Image build |
| `tools/install-go-tools.sh` | modified | Cloudlist moved out (needs newer Go); comment explains why | Image build |
| `tools/install-release-tools.sh` | modified | Cloudlist and noseyparker release binaries validated end-to-end | Image build, tool probe |
| `tools/install-python-tools.sh` | modified | `mitmproxy` via pipx; graphql-cop moved to the git installer | Image build |
| `tools/install-git-tools.sh` | modified | graphql-cop clone + dedicated venv wrapper; testssl repo moved to `testssl/testssl.sh`; corrected nikto path | Image build, tool probe |

---

## 5. Rollback notes

- The previous UI remains at `static/dashboard.legacy.html`; the server does not
  serve it. Restoring it means pointing `/` back at that filename.
- No database migration was introduced. Runtime data is plain JSON/JSONL under
  `HUNT_DATA_DIR`; removing a run folder or the whole data directory is safe
  outside a running hunt.
- The image is additive: no host tool installation was performed by this work.

---

## Amendment — authorization gate made optional

Requested after the Phase 11 report: the “no written authorization on record”
block should be optional.

| ID | Change | Status |
|---|---|---|
| SEC-02a | The gate is **off by default**: a hunt needs a non-empty in-scope list but not a confirmed authorization record | PASS |
| SEC-02b | New Scope-panel checkbox “Block hunts until this record is confirmed” (persisted in `settings.json`) turns the `409` gate on | PASS |
| SEC-02c | `HUNT_REQUIRE_AUTH=1` / `=0` pins the gate for a deployment; the checkbox is then disabled and the UI says why | PASS |
| SEC-02d | The header chip distinguishes `authorization on file`, `authorization required`, and `authorization optional` | PASS |

Scope enforcement is unchanged and still fail-closed. The gate only decides
whether a confirmed record is mandatory; it never relaxes a per-request scope
check. `GET/POST /api/settings` manages the switch, and changes are audited as
`settings.update`.

Verification at the time of this amendment (superseded by Amendment 2):

| check | result |
|---|---|
| `selftest.py` | **127/127** (six new gate assertions) |
| Containerized E2E | **32/32** (gate off, gate on blocks profile and hunt with `409`, gate off allows them) |
| UI | checkbox unchecked by default, chip switches optional → required → optional, no console errors |

Files touched by the amendment: `common.py`, `server.py`, `selftest.py`,
`static/dashboard.html`, `static/app.js`, `README.md`, `PHASE11-REPORT.md`.
A new runtime file, `settings.json`, appears under `HUNT_DATA_DIR`.

---

## Amendment 2 — empty-scope friction removed without relaxing the boundary

Requested after Amendment 1: the hunt was still blocked with “BLOCKED BY SCOPE:
no in-scope list configured” on a fresh install. Scope remains the hard boundary,
but the operator should not have to retype the target in a second form.

| ID | Change | Status |
|---|---|---|
| SEC-01a | `POST /api/start` calls `scope_guard.adopt_if_empty()`; when the in-scope list is empty and the host is not excluded, the submitted target is written as the only in-scope entry | PASS |
| SEC-01b | Adoption never replaces a non-empty list, never adopts a host that matches an out-of-scope entry, and ignores unparseable targets | PASS |
| SEC-01c | GET endpoints stay fail-closed: `/api/plan?profile=1` and `/api/profile` still return `403` on an empty list. Only the CSRF-protected start POST can seed scope | PASS |
| SEC-01d | The UI saves the target as scope before “Check & plan” (a GET), so the plan path works without weakening GET behaviour; an existing list is left intact | PASS |
| SEC-01e | The start response returns `scope_seeded` plus a warning; the UI refreshes the scope box and the header chip. Adoption is audited as `scope.auto_add` | PASS |

Why not simply make scope optional: “no scope, no traffic” is the invariant that
prevents a cross-site GET to `/api/plan?profile=1` (or a typo in the target) from
sending traffic. Auto-adopting on the start POST keeps that invariant: the only
way to seed scope is an explicit, same-origin, audited hunt start. An existing
scope is never widened, and out-of-scope entries still win.

Verification at the time of Amendment 2 (superseded by Amendment 3):

| check | result |
|---|---|
| `selftest.py` | **132/132** (five new adoption assertions) |
| Containerized E2E | **36/36** (empty-scope GET still `403`; start adopts and persists `127.0.0.1`; existing list not replaced; out-of-scope not adopted) |
| Container | image rebuilt from source; `selftest.py` runs inside the build |

Files touched by Amendment 2: `scope_guard.py` (`adopt_if_empty`),
`server.py` (`_adopt_target_as_scope`, `scope_seeded`), `static/app.js`
(`targetHost`, `ensureScopeForTarget`, post-start scope refresh),
`static/dashboard.html` (scope hint and panel label), `selftest.py`, `README.md`,
`PHASE11-REPORT.md`.

---

## Amendment 3 — in-scope list is optional (lenient scope by default)

Requested after Amendment 2: a saved list such as `localhost` still blocked
`ttzbd.com` with “does not match any in-scope entry”. The operator wants the
in-scope list to be optional, not a second gate.

| ID | Change | Status |
|---|---|---|
| SEC-01f | Scope is **lenient by default**: `POST /api/start` appends a target that is not listed, keeping existing entries, and audits `scope.auto_add` | PASS |
| SEC-01g | **Out-of-scope always wins**: an excluded host is never appended, and start/profile/plan still refuse it in every mode | PASS |
| SEC-01h | Scope-panel checkbox “Only allow targets already in the in-scope list (strict)” turns the list into a hard gate (`403`); `HUNT_STRICT_SCOPE=1` / `=0` pins it | PASS |
| SEC-01i | Live plan/profile in lenient mode may check a not-yet-listed target **only** with `X-Hunt-Request: 1`; GETs never write scope, so a cross-site image/link cannot start traffic | PASS |
| SEC-01j | Settings merge instead of overwrite: `strict_scope` and `require_auth` coexist in `settings.json` | PASS |
| SEC-01k | Header chip states are `scope auto-add`, `scope strict`, and `scope strict · empty` | PASS |

This supersedes Amendment 2's “GET endpoints stay fail-closed” wording: GETs are
still fail-closed for anonymous cross-site callers, but the dashboard can profile
an unlisted target because its GET carries the custom header. The worker-level
and per-asset checks are unchanged.

Verification after Amendment 3:

| check | result |
|---|---|
| `selftest.py` | **142/142** (three missing-target and seven scope-mode assertions) |
| Containerized E2E | **44/44** (lenient plan without header `403`, with header `200`; start appends and preserves entries; strict blocks an unlisted target; out-of-scope blocks in both modes) |
| Container | image rebuilt from source; `selftest.py` passes inside the build |

Files touched by Amendment 3: `common.py` (`load_settings`/`save_settings`,
`strict_scope`), `scope_guard.py` (`missing_from_scope`), `surface.py`
(`allow_unlisted`), `server.py` (lenient admission, header-gated live profile,
settings API), `static/app.js` (strict toggle, chip, header on plan),
`static/dashboard.html` (strict checkbox and hints), `selftest.py`, `README.md`,
`docker-compose.yml`, `PHASE11-REPORT.md`.
