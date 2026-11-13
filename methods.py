#!/usr/bin/env python3
"""methods.py — the written methodology behind every hunting category.

This module is pure data. Nothing here is executed, fetched or installed; it is
the reference the dashboard shows next to a category, and the checklist an
operator works through when a finding needs to be confirmed by hand.

Design rules:

  * One entry per category in dispatch.TASK_CATEGORIES. selftest.py fails if the
    two lists drift apart, so a new category cannot ship without a playbook.
  * Every command is a *template*. `{target}` is substituted for display only.
    The operator stays responsible for scope, rate limits and written
    authorization — a command in this file is not permission to run it.
  * `evidence` is what a report needs. `pitfalls` is what makes a finding
    embarrassing when it is skipped. Both are deliberately concrete.
  * `automated` mirrors checks.py: True means a bounded check exists, False
    means the category is manual by design (credentials, destructive payload,
    or application-specific logic).

Keeping this separate from checks.py means the UI can render rich guidance
without importing the network code, and the guidance can be corrected without
touching a scanner.
"""

# Fields shown in the UI, in display order.
FIELDS = ("objective", "why", "steps", "tools", "manual", "evidence",
          "pitfalls", "refs", "severity_hint")

# Categories that checks.py can exercise with bounded, safe requests. Kept in
# sync with checks.run() by selftest.py.
AUTOMATED = (
    "recon", "info_disclosure", "csrf_cors", "redirect", "xss", "js_audit",
    "api_diff", "subdomain_takeover",
)

METHODS = {
    # ------------------------------------------------------------------ recon
    "recon": {
        "name": "Reconnaissance",
        "tagline": "Find every host, endpoint and technology before testing anything.",
        "objective": (
            "Build an asset inventory you can defend: which hosts belong to the "
            "program, which answer HTTP, what stack each one runs, and which "
            "assets are new since the last run."
        ),
        "why": (
            "Every later category spends its time on whatever recon found. A "
            "missed dev/staging host is a missed finding; a host that is actually "
            "a third-party CNAME is an out-of-scope request that can end the "
            "engagement. Recon is also the cheapest place to catch scope errors."
        ),
        "steps": [
            {"title": "Confirm written authorization and exact scope",
             "detail": "Program URL, in-scope domains/CIDRs, exclusions, testing "
                       "window, rate limits, and the account/contact you report to. "
                       "Paste the in-scope and out-of-scope lists into the Scope "
                       "panel before the first request."},
            {"title": "Passive subdomain enumeration",
             "detail": "Certificate transparency, passive DNS and public datasets "
                       "only. Do not touch the hosts yet; collect names first.",
             "commands": ["subfinder -d {target} -all -silent",
                          "assetfinder --subs-only {target}",
                          "chaos -d {target} -silent"]},
            {"title": "Resolve and de-duplicate",
             "detail": "Resolve names, drop wildcards and dead records, and keep a "
                       "single canonical list. A wildcard DNS answer will otherwise "
                       "make every random name look alive.",
             "commands": ["dnsx -l subs.txt -a -resp -silent",
                          "puredns resolve subs.txt -r resolvers.txt"]},
            {"title": "HTTP probe and fingerprint",
             "detail": "Record status, title, server, TLS certificate and "
                       "redirect chain for every live host. Follow redirects only "
                       "after checking the destination is still in scope.",
             "commands": ["httpx -l live.txt -title -tech-detect -status-code "
                          "-web-server -follow-redirects -o httpx.txt",
                          "tlsx -l live.txt -san -cn -silent"]},
            {"title": "Map the visible surface",
             "detail": "Crawl the main app, read robots.txt/sitemap.xml, collect "
                       "JS files and note login, signup, API and admin routes. "
                       "Screenshot unusual hosts for a fast visual triage.",
             "commands": ["katana -u https://{target} -jc -d 3 -o urls.txt",
                          "gowitness scan file -f live.txt"]},
            {"title": "Diff against the previous run",
             "detail": "New hostnames and endpoints are the highest-value targets: "
                       "nobody has tested them yet. Open the Runs tab and work the "
                       "'new since previous run' list first."},
        ],
        "tools": ["subfinder", "amass", "assetfinder", "dnsx", "puredns",
                  "httpx", "tlsx", "katana", "gowitness", "cdncheck"],
        "manual": (
            "Check the program's own asset list, changelog and mobile/desktop "
            "clients. Ask whether acquired brands and regional domains are in "
            "scope; they are frequently missed by automated enumeration."
        ),
        "evidence": [
            "The exact command line and the raw output file for each stage",
            "Host list with first-seen timestamp and the source that produced it",
            "Screenshot or HTTP headers for any host you intend to test next",
        ],
        "pitfalls": [
            "Sending traffic to a host that is only a CNAME into a third-party SaaS",
            "Treating a wildcard DNS response as a real subdomain",
            "Forgetting that a redirect can leave scope mid-request",
            "Running aggressive brute-force during a stated low-rate window",
        ],
        "refs": [
            {"label": "OWASP WSTG — Information Gathering",
             "url": "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering/"},
            {"label": "ProjectDiscovery docs",
             "url": "https://docs.projectdiscovery.io/"},
        ],
        "severity_hint": "Recon itself is not a finding; it decides where findings come from.",
    },

    # --------------------------------------------------------------- js_audit
    "js_audit": {
        "name": "JavaScript & Secret Audit",
        "tagline": "Read the client code the developers shipped by accident.",
        "objective": (
            "Extract endpoints, feature flags, internal hostnames, API keys and "
            "source maps from JavaScript bundles, then verify which of them are "
            "actually reachable and sensitive."
        ),
        "why": (
            "Modern apps hide routes and keys in bundles that are served to every "
            "visitor. A leaked key or an undocumented admin route is often the "
            "shortest path from recon to a confirmed finding."
        ),
        "steps": [
            {"title": "Collect every script the app loads",
             "detail": "Crawl the app and list script src values, including lazy "
                       "chunks and workers.",
             "commands": ["katana -u https://{target} -jc -silent | grep -E '\\.js($|\\?)'",
                          "subjs -i urls.txt"]},
            {"title": "Look for source maps",
             "detail": "A .map file restores readable source. Check the end of each "
                       "bundle for sourceMappingURL and request the map directly.",
             "commands": ["curl -s https://{target}/static/app.js | tail -c 300"]},
            {"title": "Extract endpoints and parameters",
             "detail": "Pull absolute URLs, /api paths, GraphQL operations and "
                       "interesting parameter names; de-duplicate before probing.",
             "commands": ["linkfinder -i https://{target}/static/app.js -o cli",
                          "jsluice urls app.js"]},
            {"title": "Scan for secrets and classify them",
             "detail": "Separate public by design (Stripe publishable, Firebase "
                       "config) from server-side secrets. Never use a found key "
                       "against a third-party service; report it and stop."},
            {"title": "Verify reachability, not just presence",
             "detail": "A route in a bundle is a lead, not a finding. Request it "
                       "with a normal account and record the status and body. "
                       "That response is the evidence."},
            {"title": "Check build hygiene",
             "detail": "Debug flags, verbose comments, internal hostnames, test "
                       "credentials and old API versions are common in stale "
                       "chunks. Note the bundle hash so the report is reproducible."},
        ],
        "tools": ["subjs", "linkfinder", "jsluice", "secretfinder",
                  "trufflehog", "gitleaks", "katana", "gau"],
        "manual": (
            "Read the bundle around auth and payment code. Automated regexes miss "
            "custom token formats and logic flags such as isAdmin or betaEnabled."
        ),
        "evidence": [
            "Bundle URL, SHA-256 of the file, and the exact line or context",
            "Redacted excerpt showing the secret or endpoint",
            "The HTTP response proving an extracted endpoint exists",
        ],
        "pitfalls": [
            "Reporting a public key as a leaked secret",
            "Testing a discovered key against the vendor's live API",
            "Confusing an old bundle cached by a CDN with the current build",
            "Claiming an endpoint is unauthenticated without trying it",
        ],
        "refs": [
            {"label": "OWASP WSTG — Review Webpage Content",
             "url": "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/"},
            {"label": "jsluice",
             "url": "https://github.com/BishopFox/jsluice"},
        ],
        "severity_hint": "Verified server secret: critical/high. Internal route: informational until it returns data.",
    },

    # ----------------------------------------------------------- auth_session
    "auth_session": {
        "name": "Authentication & Session",
        "tagline": "Break login, reset and session lifecycle — with two accounts.",
        "objective": (
            "Prove whether an attacker can take over an account or keep access "
            "after logout, password change or MFA enrollment."
        ),
        "why": (
            "Authentication bugs are high impact and easy to reproduce. They also "
            "need two accounts and a real session, so they cannot be found by an "
            "unauthenticated sweep — they need a deliberate test."
        ),
        "steps": [
            {"title": "Map the auth flows",
             "detail": "Login, signup, email verification, password reset, MFA "
                       "enrollment/removal, remember-me, OAuth callback, logout. "
                       "Record every request with a proxy."},
            {"title": "Test password reset semantics",
             "detail": "Reuse a token, use it after the password changed, use "
                       "another user's token, and check whether the token is bound "
                       "to the account and expires."},
            {"title": "Test session lifecycle",
             "detail": "Log out and replay the cookie; change the password and "
                       "replay old sessions; check fixation (does a pre-login "
                       "session id survive login?) and remember-me token rotation."},
            {"title": "Test MFA enforcement",
             "detail": "Try skipping the MFA step, replaying a used OTP, using a "
                       "code after expiry, and disabling MFA without re-auth."},
            {"title": "Test OAuth / SSO",
             "detail": "Check state binding, redirect_uri allow-listing, email "
                       "verification before account linking, and whether an "
                       "unverified email can take over an existing account."},
            {"title": "Confirm impact with the second account",
             "detail": "Show account B's data or session being reached from "
                       "account A. Stop at the minimum proof; never change another "
                       "user's password or settings."},
        ],
        "tools": ["jwt_tool", "httpx", "ffuf"],
        "manual": (
            "All of this category is manual by design. Use a proxy (Caido/Burp) "
            "and two accounts you created for testing. Automating login attempts "
            "looks like credential stuffing and can breach program rules."
        ),
        "evidence": [
            "Both account identifiers (redacted) and the role each one has",
            "Full request/response pair for each step, including cookies",
            "A short screen recording of the takeover, if the program allows it",
        ],
        "pitfalls": [
            "Testing with a real user's account or data",
            "Locking out a shared test account with repeated attempts",
            "Reporting a logout issue that only affects the current tab",
            "Missing that the reset token is single-use but valid for 30 days",
        ],
        "refs": [
            {"label": "OWASP WSTG — Authentication Testing",
             "url": "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/04-Authentication_Testing/"},
            {"label": "PortSwigger — Authentication",
             "url": "https://portswigger.net/web-security/authentication"},
        ],
        "severity_hint": "Account takeover: critical. Session not invalidated: high/medium by exposure.",
    },

    # --------------------------------------------------------- access_control
    "access_control": {
        "name": "Access Control (IDOR / BOLA)",
        "tagline": "Ask the server whether you are allowed — not the UI.",
        "objective": (
            "Find objects, actions or fields a user can reach beyond their role, "
            "and prove it with a second account."
        ),
        "why": (
            "Broken object-level authorization is the most common high-impact API "
            "bug. The UI hides the button; the API rarely checks the owner."
        ),
        "steps": [
            {"title": "Inventory object identifiers and roles",
             "detail": "Collect numeric ids, UUIDs, slugs, tenant ids, org ids and "
                       "role names from requests. Note which endpoints change state."},
            {"title": "Create two accounts at different privilege levels",
             "detail": "A normal user and a second normal user are enough for IDOR; "
                       "add an admin only if the program provides one."},
            {"title": "Replay account B's identifiers with account A's session",
             "detail": "Change one identifier at a time. Compare status, body and "
                       "side effects; a 403 is a pass, a 200 with B's data is the "
                       "finding."},
            {"title": "Test horizontal and vertical movement",
             "detail": "Horizontal: same role, different owner. Vertical: lower "
                       "role calling an admin action. Also test tenant boundaries."},
            {"title": "Test mass assignment",
             "detail": "Add role, isAdmin, tenant_id, owner_id or verified to a "
                       "profile update. Verify the change by reading the object "
                       "back, not by trusting the response."},
            {"title": "Check indirect paths",
             "detail": "Export/download endpoints, GraphQL node(id:), batch APIs, "
                       "webhooks and mobile endpoints often skip the check the web "
                       "route has."},
        ],
        "tools": ["ffuf", "arjun", "kiterunner", "jwt_tool"],
        "manual": (
            "Requires two authenticated sessions. Automating id enumeration "
            "without authorization is indistinguishable from scraping user data; "
            "keep the sample small and stop at proof."
        ),
        "evidence": [
            "Request from account A, response containing account B's object",
            "The object's owner (B) and the fact that A is a different tenant/user",
            "Before/after state for mass assignment, read back from the API",
        ],
        "pitfalls": [
            "Only testing the id in the URL and missing the body/header copy",
            "Reporting a 200 that returns an empty or generic object",
            "Enumerating thousands of ids and touching real user data",
            "Forgetting GraphQL and export endpoints",
        ],
        "refs": [
            {"label": "OWASP API1: Broken Object Level Authorization",
             "url": "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"},
            {"label": "PortSwigger — Access control",
             "url": "https://portswigger.net/web-security/access-control"},
        ],
        "severity_hint": "Cross-tenant read/write: critical/high. Same-tenant role bypass: high.",
    },

    # -------------------------------------------------------------- injection
    "injection": {
        "name": "Injection (SQL / Command / Template / XXE)",
        "tagline": "One parameter, one safe payload, one reproducible response.",
        "objective": (
            "Determine whether user input reaches an interpreter, and prove it "
            "with a minimal, non-destructive payload."
        ),
        "why": (
            "Injection classes are still the fastest route to data access and "
            "remote execution. They are also the easiest to fake with a scanner, "
            "so every claim needs a response the developer can reproduce."
        ),
        "steps": [
            {"title": "Find interpreter-adjacent inputs",
             "detail": "Search, filters, sort/order, ids, file paths, XML/SOAP "
                       "bodies, template previews, import features. Note the "
                       "content type and encoding."},
            {"title": "Establish a baseline",
             "detail": "Send a benign value and record status, length, timing and "
                       "body. Every later difference is measured against this."},
            {"title": "Probe SQL injection safely",
             "detail": "Start with a single quote and a boolean pair. Use time-based "
                       "only if boolean is inconclusive, and keep delays small.",
             "commands": ["sqlmap -r request.txt --batch --level 2 --risk 1 "
                          "--technique=BEUST --time-sec=3"]},
            {"title": "Probe command/template injection with arithmetic",
             "detail": "Use a harmless expression such as 7*7 and look for 49 in the "
                       "response. Never use a payload that writes files or makes "
                       "outbound calls without explicit permission."},
            {"title": "Probe XXE with an in-band entity",
             "detail": "Use a local file that is safe to disclose, or an internal "
                       "entity that produces a deterministic error. Avoid external "
                       "DTDs unless OOB testing is authorized."},
            {"title": "Confirm, minimise, document",
             "detail": "Reduce to the smallest payload that still proves execution. "
                       "Record the exact request, response excerpt and timing."},
        ],
        "tools": ["sqlmap", "ghauri", "commix", "nosqlmap", "ffuf", "arjun"],
        "manual": (
            "sqlmap/ghauri need a captured request and a rate limit. Blind and "
            "time-based tests are slow and noisy; run them only inside the agreed "
            "window and stop if the target degrades."
        ),
        "evidence": [
            "Raw request file and the exact payload used",
            "Response excerpt showing the error, boolean difference or timing",
            "A repeat run proving it is deterministic, not a fluke",
        ],
        "pitfalls": [
            "Calling a generic 500 an SQL injection",
            "Using destructive payloads (DROP, xp_cmdshell, file writes)",
            "Ignoring WAF behaviour that changes results between runs",
            "Testing a third-party payment or auth provider outside scope",
        ],
        "refs": [
            {"label": "OWASP WSTG — Injection",
             "url": "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/"},
            {"label": "PortSwigger — SQL injection",
             "url": "https://portswigger.net/web-security/sql-injection"},
        ],
        "severity_hint": "Data access or RCE: critical. Error-only leak: medium at most.",
    },

    # -------------------------------------------------------------------- xss
    "xss": {
        "name": "Cross-Site Scripting",
        "tagline": "Reflection is a hint. Execution is the finding.",
        "objective": (
            "Find a context where attacker-controlled input reaches an HTML, "
            "attribute, URL or DOM sink and executes in a victim's browser."
        ),
        "why": (
            "Reflected strings are everywhere and mostly harmless. A report needs "
            "the exact sink, the encoding that failed, and a payload that runs."
        ),
        "steps": [
            {"title": "Map reflections and sinks",
             "detail": "Send a unique marker to every parameter and search the "
                       "response for it. Note the surrounding HTML context."},
            {"title": "Classify the context",
             "detail": "HTML text, attribute value, quoted/unquoted attribute, "
                       "script string, URL, CSS or DOM sink such as innerHTML, "
                       "eval, location or document.write."},
            {"title": "Build a context-specific payload",
             "detail": "Break out of the exact quoting, then prove execution with "
                       "a harmless marker such as alert(document.domain) or a "
                       "console entry. No data exfiltration."},
            {"title": "Test stored and DOM flows",
             "detail": "Submit through the UI, then load the page as a second user "
                       "or in a clean session. For DOM XSS, trace source to sink in "
                       "the bundle and confirm in a browser."},
            {"title": "Check the defences that matter",
             "detail": "CSP (does it actually block inline?), HttpOnly on session "
                       "cookies, Trusted Types, framework escaping and server-side "
                       "sanitisation."},
            {"title": "Capture reproducible evidence",
             "detail": "URL, payload, browser, and a screenshot or short video of "
                       "the alert. For stored XSS, state who else can see it."},
        ],
        "tools": ["dalfox", "xsstrike", "gf", "katana", "subjs"],
        "manual": (
            "DOM XSS needs a browser and source review. dalfox finds reflections "
            "quickly, but a reflection without execution is not a finding."
        ),
        "evidence": [
            "Full URL or stored field plus the exact payload",
            "Screenshot/video of execution and the DOM context",
            "The response snippet showing the unencoded sink",
        ],
        "pitfalls": [
            "Reporting a payload that only appears inside a JS string and never runs",
            "Ignoring CSP that blocks the payload in every supported browser",
            "Testing with your own admin account and claiming privilege escalation",
            "Using a payload that calls home to a third-party server",
        ],
        "refs": [
            {"label": "OWASP — XSS Prevention Cheat Sheet",
             "url": "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"},
            {"label": "PortSwigger — XSS",
             "url": "https://portswigger.net/web-security/cross-site-scripting"},
        ],
        "severity_hint": "Stored XSS in an admin-viewed field: high. Self-XSS: informational.",
    },

    # ------------------------------------------------------------------- ssrf
    "ssrf": {
        "name": "Server-Side Request Forgery",
        "tagline": "Make the server fetch something it should not reach.",
        "objective": (
            "Prove that a server-side fetch can be pointed at an internal service, "
            "cloud metadata endpoint, or an attacker-controlled listener."
        ),
        "why": (
            "SSRF bypasses network boundaries and often leads to cloud credential "
            "theft. It also needs an out-of-band listener and strict restraint: "
            "internal services can be fragile."
        ),
        "steps": [
            {"title": "Find server-side fetchers",
             "detail": "Webhooks, URL imports, image proxies, PDF renderers, link "
                       "previews, avatar fetch, RSS/feed readers, integrations."},
            {"title": "Start with your own listener",
             "detail": "Point the parameter at a host you control and confirm the "
                       "callback with the target's source IP and user agent."},
            {"title": "Test address-family and parser bypasses",
             "detail": "Only after the callback works: localhost variants, decimal/"
                       "octal IPs, IPv6, DNS rebinding, redirects and allow-list "
                       "evasions."},
            {"title": "Check metadata reachability carefully",
             "detail": "Use a single GET to the metadata root with the shortest "
                       "possible timeout. Do not request credentials unless the "
                       "program explicitly allows it."},
            {"title": "Stop at the first proof",
             "detail": "A callback or a metadata banner is enough. Do not pivot "
                       "into internal services or attempt to modify state."},
        ],
        "tools": ["interactsh", "ssrfmap", "gopherus", "ffuf"],
        "manual": (
            "interactsh-client gives you a unique OOB domain. Keep one listener "
            "per test, log the timestamp, and shut it down afterwards."
        ),
        "evidence": [
            "The vulnerable request and the parameter value used",
            "Callback log with timestamp, source IP and full request line",
            "Response body showing internal content, if in-band",
        ],
        "pitfalls": [
            "Calling a DNS-only callback full SSRF without checking the HTTP hit",
            "Hitting internal admin panels or cloud metadata beyond the root",
            "Leaving a public listener running after the test",
            "Ignoring egress filtering that makes the callback source ambiguous",
        ],
        "refs": [
            {"label": "OWASP — SSRF Prevention Cheat Sheet",
             "url": "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"},
            {"label": "PortSwigger — SSRF",
             "url": "https://portswigger.net/web-security/ssrf"},
        ],
        "severity_hint": "Metadata credentials or internal admin access: critical. Blind callback: medium/high.",
    },

    # ------------------------------------------------------------- csrf_cors
    "csrf_cors": {
        "name": "CSRF, CORS & Browser Headers",
        "tagline": "Check what another origin can read or change.",
        "objective": (
            "Determine whether a cross-site request can change state (CSRF) or "
            "whether a hostile origin can read authenticated responses (CORS)."
        ),
        "why": (
            "Both are configuration bugs with direct impact: CSRF changes data as "
            "the victim, CORS leaks it. They are cheap to test and easy to get "
            "wrong in the other direction, so evidence must show the browser "
            "actually allowing it."
        ),
        "steps": [
            {"title": "List state-changing endpoints",
             "detail": "Profile update, email change, password change, payment, "
                       "invite, API keys, delete actions. Note the method and "
                       "whether a token is required."},
            {"title": "Check CSRF defences",
             "detail": "Synchronizer token, double-submit cookie, SameSite, Origin/"
                       "Referer validation. Test removing the token and sending a "
                       "foreign Origin."},
            {"title": "Build a minimal CSRF proof",
             "detail": "A local HTML form that submits cross-origin. The finding is "
                       "the state change, not the form."},
            {"title": "Test CORS with a hostile origin",
             "detail": "Send Origin: https://evil.example and a second arbitrary "
                       "origin. Look for reflection plus Allow-Credentials: true."},
            {"title": "Check preflight behaviour",
             "detail": "A permissive simple request is not enough; confirm the "
                       "browser can send credentialed requests and read the body."},
            {"title": "Review frame and header gaps",
             "detail": "X-Frame-Options/CSP frame-ancestors for clickjacking, HSTS, "
                       "nosniff, and cookie SameSite/HttpOnly/Secure flags."},
        ],
        "tools": ["corsy", "httpx", "ffuf"],
        "manual": (
            "CORS needs a browser check: curl can show headers, but only a page "
            "from the hostile origin proves the browser will expose the response."
        ),
        "evidence": [
            "Request with Origin and the exact ACAO/ACAC response headers",
            "Browser console/screenshot showing the cross-origin read",
            "For CSRF: the before/after account state and the HTML used",
        ],
        "pitfalls": [
            "Reporting ACAO: * as credential theft (it is not, without ACAC)",
            "Missing that SameSite=Lax still allows top-level GET navigation",
            "Testing CORS on an endpoint that requires no authentication",
            "Forgetting that a CSRF token in a cookie is not a defence alone",
        ],
        "refs": [
            {"label": "OWASP WSTG — Session Management",
             "url": "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/06-Session_Management_Testing/"},
            {"label": "PortSwigger — CORS",
             "url": "https://portswigger.net/web-security/cors"},
        ],
        "severity_hint": "Credentialed CORS read: high. CSRF on email/password change: high.",
    },

    # --------------------------------------------------------------- redirect
    "redirect": {
        "name": "Open Redirect",
        "tagline": "A redirect is only interesting when it leaves the trusted host.",
        "objective": (
            "Find a parameter that lets an attacker choose the destination host, "
            "and show the browser following it."
        ),
        "why": (
            "Open redirects are low severity alone but valuable in phishing chains "
            "and OAuth token theft. Programs vary: many accept only redirects that "
            "carry a token or bypass an allow-list."
        ),
        "steps": [
            {"title": "Collect redirect-shaped parameters",
             "detail": "next, url, redirect, return, returnTo, continue, target, "
                       "callback, checkout_url, image_url. Include path segments "
                       "such as /out/ or /r/."},
            {"title": "Test with a harmless external host",
             "detail": "Use a domain you control or example.invalid. Confirm the "
                       "Location header and follow it in a browser."},
            {"title": "Test allow-list bypasses",
             "detail": "Only if a filter is present: userinfo, backslashes, encoded "
                       "slashes, double encoding, scheme-relative //, and suffix "
                       "tricks such as trusted.com.evil.example."},
            {"title": "Check the response code",
             "detail": "A 302/303 with an external Location is the finding. A 200 "
                       "page that merely contains a link is not."},
            {"title": "Assess the chain",
             "detail": "Does the redirect carry an OAuth code, session token or "
                       "password-reset token to the attacker? That changes severity."},
        ],
        "tools": ["ffuf", "gf", "httpx"],
        "manual": (
            "Crawl for redirect endpoints first; ffuf with a redirect-param "
            "wordlist is only useful once you have candidate URLs."
        ),
        "evidence": [
            "Full request and the raw Location header",
            "Browser screenshot of the final external page",
            "Any token or sensitive value included in the redirect",
        ],
        "pitfalls": [
            "Reporting a same-host redirect as open",
            "Missing that a JavaScript location assignment also redirects",
            "Ignoring an interstitial warning page that blocks the hop",
            "Following the redirect with an authenticated session unnecessarily",
        ],
        "refs": [
            {"label": "OWASP — Unvalidated Redirects",
             "url": "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"},
        ],
        "severity_hint": "Token-bearing redirect: high. Plain phishing redirect: low/informational.",
    },

    # --------------------------------------------------------------- api_diff
    "api_diff": {
        "name": "API Discovery & Spec Diff",
        "tagline": "The API is bigger than the documentation admits.",
        "objective": (
            "Compare the documented API with the routes that actually exist, and "
            "test the undocumented ones for missing authorization or extra data."
        ),
        "why": (
            "Shadow endpoints, old API versions and debug routes are rarely "
            "hardened. A spec diff turns a huge surface into a short, high-value "
            "list."
        ),
        "steps": [
            {"title": "Collect specs and clients",
             "detail": "openapi.json, swagger.json, GraphQL schema, Postman "
                       "collections, mobile app traffic and JS bundles."},
            {"title": "Build a route inventory",
             "detail": "Extract paths and methods from the spec and from traffic. "
                       "Normalise ids and versions before comparing."},
            {"title": "Diff spec vs reality",
             "detail": "Look for routes in traffic that are absent from the spec, "
                       "old versions (/v1 next to /v3), internal prefixes, and "
                       "methods the spec does not mention."},
            {"title": "Test the undocumented routes",
             "detail": "Request them unauthenticated and with a low-privilege "
                       "session. Compare with the documented equivalent."},
            {"title": "Test GraphQL specifically",
             "detail": "Introspection, field suggestions, batching, aliases, "
                       "depth limits and mutations that skip authorization."},
            {"title": "Record what is actually exposed",
             "detail": "A route that returns 401 is still useful (it exists). A "
                       "route that returns data is a finding."},
        ],
        "tools": ["kiterunner", "ffuf", "katana", "arjun", "httpx"],
        "manual": (
            "Mobile clients often call API versions the web app never uses. "
            "Capture their traffic only on a test account you own."
        ),
        "evidence": [
            "Spec excerpt versus the live request/response",
            "The route, method and authentication state used",
            "A diff list of documented vs observed endpoints",
        ],
        "pitfalls": [
            "Brute-forcing API routes at high volume and tripping rate limits",
            "Treating a 404 from a WAF as proof the route is absent",
            "Ignoring GraphQL because the REST spec looks complete",
            "Reporting route existence without showing a response",
        ],
        "refs": [
            {"label": "OWASP API9: Improper Inventory Management",
             "url": "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/"},
            {"label": "GraphQL Cheat Sheet",
             "url": "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"},
        ],
        "severity_hint": "Undocumented admin route returning data: high. Route existence only: informational.",
    },

    # -------------------------------------------------------- deserialization
    "deserialization": {
        "name": "Deserialization & Prototype Pollution",
        "tagline": "Native object formats are code, not data.",
        "objective": (
            "Determine whether untrusted serialized data is deserialized, and "
            "whether prototype pollution can change application behaviour."
        ),
        "why": (
            "Deserialization bugs usually mean remote code execution. They are "
            "framework-specific and dangerous to test, so the bar for evidence is "
            "high and the payloads must be non-destructive."
        ),
        "steps": [
            {"title": "Find serialized formats",
             "detail": "Java serialized streams (rO0AB / aced0005), PHP objects "
                       "(O:), Python pickle, .NET ViewState, Node cookies and "
                       "JSON with __proto__."},
            {"title": "Fingerprint the stack",
             "detail": "Framework and version decide which gadget chains are even "
                       "plausible. Confirm with headers, error pages and libraries."},
            {"title": "Test prototype pollution first",
             "detail": "It is safer: send __proto__ / constructor[prototype] in a "
                       "JSON body and check whether a later response changes."},
            {"title": "Use a benign deserialization probe",
             "detail": "Only with explicit permission, and only a payload that "
                       "causes a delay or a DNS callback — never a file write or "
                       "a reverse shell."},
            {"title": "Stop and report",
             "detail": "If execution is proven, do not build a full chain. A "
                       "timestamped delay or callback is enough."},
        ],
        "tools": ["ysoserial", "phpggc", "ysoserial.net"],
        "manual": (
            "This category is manual and permission-gated. Payload generators are "
            "listed so the report can name the chain; they are not run unattended."
        ),
        "evidence": [
            "The exact serialized blob and the endpoint that accepted it",
            "Timing or callback proof, with the timestamp",
            "Stack/framework version supporting the gadget chain",
        ],
        "pitfalls": [
            "Sending a real RCE payload to a production system",
            "Confusing a JSON parser error with deserialization",
            "Testing an endpoint that only deserializes trusted server data",
            "Leaving generated payload files on the target",
        ],
        "refs": [
            {"label": "OWASP — Deserialization Cheat Sheet",
             "url": "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html"},
            {"label": "PortSwigger — Insecure deserialization",
             "url": "https://portswigger.net/web-security/deserialization"},
        ],
        "severity_hint": "Proven code execution: critical. Prototype pollution with impact: high.",
    },

    # ------------------------------------------------------------- jwt_crypto
    "jwt_crypto": {
        "name": "JWT, Tokens & Cryptography",
        "tagline": "Trust the signature, not the claims.",
        "objective": (
            "Test whether tokens are verified correctly and whether weak crypto "
            "lets an attacker forge or predict them."
        ),
        "why": (
            "A token bug turns into full account takeover with one request. It is "
            "also easy to misreport: a decoded JWT is not a vulnerability."
        ),
        "steps": [
            {"title": "Capture and decode tokens",
             "detail": "Record header, payload and signature. Note alg, kid, jku, "
                       "x5u, exp, aud and iss."},
            {"title": "Test alg=none and algorithm confusion",
             "detail": "Change alg to none and to HS256 with the public key as the "
                       "secret. A 200 with the original claims is the finding."},
            {"title": "Test key handling",
             "detail": "Weak HMAC secret (offline dictionary), kid path traversal, "
                       "jku/x5u pointing at your host, and key confusion."},
            {"title": "Test claim validation",
             "detail": "Expired token, wrong audience, wrong issuer, missing exp, "
                       "role escalation in the payload with a valid signature."},
            {"title": "Check reset and API tokens",
             "detail": "Predictability, length, expiry, single use, and whether "
                       "they are stored in URLs or logs."},
        ],
        "tools": ["jwt_tool", "hashcat", "john"],
        "manual": (
            "Cracking a weak secret is offline and safe; forging a token against "
            "the live app is an authenticated test. Keep both within scope."
        ),
        "evidence": [
            "Original and forged token (redacted) plus the accepted response",
            "The exact claim or header that was not validated",
            "For weak secrets: the wordlist entry and crack time",
        ],
        "pitfalls": [
            "Reporting a decoded token as a vulnerability",
            "Claiming alg=none without a 200 and the original claims",
            "Cracking a secret that belongs to a third-party service",
            "Ignoring server-side session revocation after token theft",
        ],
        "refs": [
            {"label": "OWASP — JWT Cheat Sheet",
             "url": "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html"},
            {"label": "PortSwigger — JWT attacks",
             "url": "https://portswigger.net/web-security/jwt"},
        ],
        "severity_hint": "Signature bypass or forgeable admin token: critical. Weak secret: high.",
    },

    # ------------------------------------------------------------- file_upload
    "file_upload": {
        "name": "File Upload & Path Traversal",
        "tagline": "Where the file lands matters more than what it is called.",
        "objective": (
            "Determine whether an uploaded file can be stored outside the intended "
            "directory, served as executable content, or used to read local files."
        ),
        "why": (
            "Upload bugs range from stored XSS to RCE. They need a writable test "
            "account and careful cleanup, so they are manual and tightly scoped."
        ),
        "steps": [
            {"title": "Map upload surfaces",
             "detail": "Avatars, attachments, imports, invoice PDFs, theme/plugin "
                       "uploads, CSV imports, archive extraction."},
            {"title": "Test extension and content-type handling",
             "detail": "Double extension, trailing dot/space, case changes, null "
                       "byte, SVG with script, HTML polyglot, and MIME mismatch."},
            {"title": "Test storage location and serving",
             "detail": "Is the file served from the app origin? With what "
                       "Content-Type and Content-Disposition? Can it execute?"},
            {"title": "Test traversal in the filename",
             "detail": "Use ../ sequences to see whether the file escapes the "
                       "upload directory. Read back only the file you uploaded."},
            {"title": "Test archive extraction",
             "detail": "Zip-slip and symlink entries. Use a small archive you "
                       "created; never extract into a shared directory."},
            {"title": "Clean up",
             "detail": "Delete the uploaded file and note the deletion in the "
                       "report. Leaving a webshell on a target is not acceptable."},
        ],
        "tools": ["ffuf", "curl", "exiftool"],
        "manual": (
            "Requires a test account with upload rights. Never upload a real "
            "webshell; a harmless marker file or an SVG with alert() is enough."
        ),
        "evidence": [
            "Upload request, stored path and the response serving the file",
            "The exact filename/content-type combination that bypassed the filter",
            "Proof of execution or traversal, plus cleanup confirmation",
        ],
        "pitfalls": [
            "Uploading executable code to a production host",
            "Reporting a stored file that is served as text/plain",
            "Forgetting to delete test artifacts",
            "Testing a CDN upload path that belongs to a third party",
        ],
        "refs": [
            {"label": "OWASP — File Upload Cheat Sheet",
             "url": "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"},
            {"label": "PortSwigger — File upload vulnerabilities",
             "url": "https://portswigger.net/web-security/file-upload"},
        ],
        "severity_hint": "Executable upload: critical. Stored HTML/SVG XSS: high. Traversal read: high.",
    },

    # ---------------------------------------------------------- rate_limiting
    "rate_limiting": {
        "name": "Rate Limiting & Resource Abuse",
        "tagline": "Small sample, clear threshold, immediate stop.",
        "objective": (
            "Determine whether authentication, OTP, password reset and expensive "
            "endpoints enforce a limit that makes brute force impractical."
        ),
        "why": (
            "Missing limits enable credential stuffing and cost abuse. Testing "
            "them looks exactly like an attack, so the sample must be tiny and "
            "authorized."
        ),
        "steps": [
            {"title": "Pick the endpoints that matter",
             "detail": "Login, OTP verify, password reset request, invite accept, "
                       "search/export, AI or file-processing endpoints."},
            {"title": "Measure the baseline",
             "detail": "Send 5-10 requests with wrong credentials and record "
                       "status, latency and any Retry-After or lockout message."},
            {"title": "Test the expected control",
             "detail": "Per-account, per-IP, per-device and global limits. Check "
                       "whether a new session or header resets the counter."},
            {"title": "Test OTP specifically",
             "detail": "Is the code invalidated after N attempts? Can the counter "
                       "be reset by requesting a new code? Is the code bound to "
                       "the account?"},
            {"title": "Stop at proof",
             "detail": "Twenty attempts without a 429 is enough for a report. Do "
                       "not run a real wordlist against a live login."},
        ],
        "tools": ["ffuf", "httpx"],
        "manual": (
            "Manual and deliberately small. Automating this category at scale is "
            "credential stuffing, even with good intentions."
        ),
        "evidence": [
            "The exact number of attempts and the responses (status + timing)",
            "Missing 429/lockout across the sample",
            "The account/IP rotation that reset the counter, if any",
        ],
        "pitfalls": [
            "Locking out the test account or a shared IP",
            "Reporting a limit that exists but is higher than the sample",
            "Ignoring caching/CDN behaviour that masks the origin",
            "Running the test during a business-critical window",
        ],
        "refs": [
            {"label": "OWASP — Credential Stuffing",
             "url": "https://owasp.org/www-community/attacks/Credential_stuffing"},
        ],
        "severity_hint": "No limit on login/OTP: high. Expensive endpoint abuse: medium.",
    },

    # ------------------------------------------------------- info_disclosure
    "info_disclosure": {
        "name": "Information Disclosure",
        "tagline": "A version string is a lead; a secret is a finding.",
        "objective": (
            "Find files, endpoints or error paths that expose credentials, source, "
            "internal topology or user data."
        ),
        "why": (
            "Disclosure is often the first step of a chain. It is also the easiest "
            "category to over-report, so each item needs a clear sensitivity call."
        ),
        "steps": [
            {"title": "Probe common exposure paths",
             "detail": ".git/HEAD, .env, backups, server-status, actuator, debug "
                       "routes, phpinfo, source maps, directory listings."},
            {"title": "Trigger verbose errors",
             "detail": "Malformed JSON, wrong content type, huge values, unexpected "
                       "methods. Record the stack trace and versions."},
            {"title": "Check headers and cookies",
             "detail": "Server versions, internal hostnames, debug flags, verbose "
                       "CORS and cache headers."},
            {"title": "Look for user-data exposure",
             "detail": "Exports, logs, sitemaps, API responses with more fields "
                       "than the UI shows, and error pages containing other users' "
                       "identifiers."},
            {"title": "Classify sensitivity",
             "detail": "Public by design vs internal vs secret. A framework name "
                       "alone is informational; a live key or another user's PII "
                       "is not."},
        ],
        "tools": ["nuclei", "ffuf", "httpx", "nikto", "trufflehog"],
        "manual": (
            "Read the error page like a developer. Automated exposure templates "
            "find the obvious files; the interesting leak is usually in a custom "
            "error path."
        ),
        "evidence": [
            "URL, status and a redacted response excerpt",
            "Why the data is sensitive and who can reach it",
            "Whether authentication was required",
        ],
        "pitfalls": [
            "Reporting a 404 page as an exposed file",
            "Publishing a live secret in the report body",
            "Counting framework version disclosure as high severity",
            "Ignoring cache headers that make a leak public",
        ],
        "refs": [
            {"label": "OWASP WSTG — Configuration",
             "url": "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/"},
        ],
        "severity_hint": "Live credential or cross-user PII: high/critical. Version banner: informational.",
    },

    # ---------------------------------------------------------- business_logic
    "business_logic": {
        "name": "Business Logic",
        "tagline": "The code does exactly what it was told. That is the bug.",
        "objective": (
            "Find a sequence of legitimate requests that produces an outcome the "
            "business did not intend: free goods, skipped steps, duplicated value "
            "or privilege gain."
        ),
        "why": (
            "No scanner can decide whether a coupon should stack or a workflow "
            "step can be skipped. This is where a human who understands the "
            "product beats automation."
        ),
        "steps": [
            {"title": "Map the money and privilege flows",
             "detail": "Signup, trial, coupon, cart, checkout, refund, invite, "
                       "role change, approval, export. Draw the intended state "
                       "machine."},
            {"title": "Look for missing server-side checks",
             "detail": "Price/quantity in the client, negative values, currency "
                       "swaps, coupon reuse, trial restart, step skipping."},
            {"title": "Test sequencing and replay",
             "detail": "Send step 3 without step 2, replay the final request, "
                       "interleave two carts, and run the same action twice."},
            {"title": "Test race conditions safely",
             "detail": "Small parallel burst (5-10) on a test object, never on "
                       "payments. Look for double-spend or double-credit."},
            {"title": "Confirm the business impact",
             "detail": "State what the attacker gains in money, access or data. "
                       "A logic quirk with no gain is not a finding."},
            {"title": "Restore state",
             "detail": "Cancel test orders, refund test credits, and tell the "
                       "program what was created."},
        ],
        "tools": ["ffuf", "curl", "httpx"],
        "manual": (
            "Application-specific and entirely manual. Requires a test account and "
            "a clear description of intended behaviour from the program."
        ),
        "evidence": [
            "The request sequence, in order, with timestamps",
            "Before/after account or order state",
            "The intended rule (policy, UI copy or program statement) it violates",
        ],
        "pitfalls": [
            "Testing on real customer orders or money",
            "Calling a UI-only restriction a server-side bug without replaying it",
            "Reporting a discount that the business intentionally allows",
            "Running race tests against production payment rails",
        ],
        "refs": [
            {"label": "OWASP WSTG — Business Logic",
             "url": "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/10-Business_Logic_Testing/"},
        ],
        "severity_hint": "Direct financial loss or privilege gain: high/critical. Cosmetic rule break: low.",
    },

    # --------------------------------------------------------- http_smuggling
    "http_smuggling": {
        "name": "HTTP Request Smuggling",
        "tagline": "Two parsers, one request. Never on a shared cache.",
        "objective": (
            "Determine whether a front-end and back-end disagree about request "
            "boundaries, allowing a request to be prefix-injected into another "
            "user's."
        ),
        "why": (
            "Smuggling can poison caches and hijack other users' requests. It is "
            "also the category most likely to cause collateral damage, so it is "
            "manual, permission-gated and never part of an unattended sweep."
        ),
        "steps": [
            {"title": "Confirm the architecture",
             "detail": "CDN/WAF in front of an origin, HTTP/2 downgrade, multiple "
                       "proxies. Ask the program before sending desync probes."},
            {"title": "Establish a timing baseline",
             "detail": "Send normal requests and record latency. Desync findings "
                       "are usually a repeatable timing or response anomaly."},
            {"title": "Run one probe type at a time",
             "detail": "CL.TE, TE.CL, TE.TE obfuscation. Use a dedicated test path "
                       "and a harmless target request."},
            {"title": "Never poison shared infrastructure",
             "detail": "If the target sits behind a shared CDN, stop. A cache "
                       "poisoning test can affect unrelated customers."},
            {"title": "Report with restraint",
             "detail": "A reproducible timing difference on your own requests is "
                       "enough. Do not attempt to capture another user's request."},
        ],
        "tools": ["smuggler", "h2csmuggler"],
        "manual": (
            "Manual only. smuggler/h2cSmuggler are listed for the operator who has "
            "explicit permission; the dashboard never runs them automatically."
        ),
        "evidence": [
            "Raw bytes of the probe (not a parsed request)",
            "Repeatable timing/response difference with timestamps",
            "Written confirmation that desync testing is allowed",
        ],
        "pitfalls": [
            "Testing a shared CDN or cache",
            "Leaving a poisoned cache entry behind",
            "Confusing a WAF block with a desync",
            "Running probes at high volume",
        ],
        "refs": [
            {"label": "PortSwigger — HTTP request smuggling",
             "url": "https://portswigger.net/web-security/request-smuggling"},
        ],
        "severity_hint": "Cross-user impact: critical. Timing-only anomaly: medium pending confirmation.",
    },

    # ------------------------------------------------------ subdomain_takeover
    "subdomain_takeover": {
        "name": "Subdomain Takeover",
        "tagline": "A dangling CNAME is a claim ticket for your brand.",
        "objective": (
            "Find a hostname that points at a third-party service which no longer "
            "claims it, and prove the name can be taken over."
        ),
        "why": (
            "A takeover lets an attacker serve content on the program's domain, "
            "which breaks cookie scope, phishing defences and brand trust. The "
            "fingerprint matters more than the CNAME."
        ),
        "steps": [
            {"title": "Collect CNAMEs and their providers",
             "detail": "Resolve every in-scope host and record CNAME targets. Group "
                       "by provider (S3, GitHub Pages, Heroku, Azure, Fastly...)."},
            {"title": "Check the provider's claim response",
             "detail": "Request the host and look for the provider's 'not found' "
                       "fingerprint. A CNAME alone is not a finding."},
            {"title": "Confirm the name is claimable",
             "detail": "Only claim it with the program's written permission. The "
                       "usual proof is the provider's signup page accepting the "
                       "name, not actually publishing content."},
            {"title": "Check DNS-only variants",
             "detail": "Dangling A records, NS delegation to a dead zone, and "
                       "unclaimed mail providers (MX) are related but separate."},
            {"title": "Report before claiming",
             "detail": "Many programs prohibit claiming the asset. Send the "
                       "fingerprint and let the program decide."},
        ],
        "tools": ["subzy", "subjack", "dnsx", "httpx", "nuclei"],
        "manual": (
            "Claiming is a state change on a third-party service. Never do it "
            "without explicit permission; the fingerprint is usually enough."
        ),
        "evidence": [
            "CNAME chain and the provider's not-found response",
            "Screenshot of the fingerprint page",
            "Confirmation from the program before any claim",
        ],
        "pitfalls": [
            "Reporting every CNAME as a takeover",
            "Claiming a name and publishing content without permission",
            "Testing a host that resolves to a shared third-party IP",
            "Missing that the provider now reserves the name automatically",
        ],
        "refs": [
            {"label": "OWASP — Subdomain Takeover",
             "url": "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Testing_Subdomain_Takeover"},
            {"label": "can-i-take-over-xyz",
             "url": "https://github.com/EdOverflow/can-i-take-over-xyz"},
        ],
        "severity_hint": "Claimable host serving content: high/critical. Dangling record only: medium.",
    },
}


# --- helpers ---------------------------------------------------------------

def get(category):
    """Return one playbook, or None for an unknown category."""
    return METHODS.get(category)


def all_methods():
    """List form for the API, in a stable order."""
    return [
        {"id": cid, "name": m["name"], "tagline": m["tagline"],
         "automated": cid in AUTOMATED, "severity_hint": m["severity_hint"]}
        for cid, m in METHODS.items()
    ]


def commands_for(category):
    """Every command template in one list, for copy-to-clipboard in the UI."""
    out = []
    for step in (METHODS.get(category) or {}).get("steps", []):
        for cmd in step.get("commands", []):
            out.append({"step": step["title"], "command": cmd})
    return out


def validate():
    """Structural check used by selftest.py; returns a list of problems."""
    problems = []
    for cid, m in METHODS.items():
        for field in ("name", "tagline", "objective", "why", "steps", "tools",
                      "manual", "evidence", "pitfalls", "refs",
                      "severity_hint"):
            if not m.get(field):
                problems.append("%s: missing %s" % (cid, field))
        if len(m.get("steps") or []) < 4:
            problems.append("%s: fewer than 4 steps" % cid)
        for i, step in enumerate(m.get("steps") or []):
            if not step.get("title") or not step.get("detail"):
                problems.append("%s: step %d incomplete" % (cid, i + 1))
    return problems
