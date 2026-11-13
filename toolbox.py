#!/usr/bin/env python3
"""toolbox.py — the bug-bounty tool catalog, selection and detection.

Every tool an agent could use is registered here exactly once: which stage of
a hunt it belongs to, the GitHub repo it lives in, how it is normally
installed, and which dashboard task categories need that stage. The Tools tab
is generated from this file, so adding a tool is one line in `_RAW`.

Two separate things are tracked:

  * what the *catalog* knows   -> this file, identical for everyone
  * what *you* chose to use    -> tools.json, stored with the run data

Nothing here installs anything. Detection is `shutil.which` plus a short
`--version` probe; a missing tool is reported as missing, together with the
command that would fix it. That distinction matters: "not installed" is
information, silently installing binaries is not something a recon tool should
do behind your back.
"""

import os
import shutil
import subprocess
import threading
import time

import common

SELECTION_PATH = os.path.join(common.DATA_DIR, "tools.json")
CACHE_TTL = 60          # seconds; a fresh install shows up within a minute
VERSION_TIMEOUT = 3


# --- stages ---------------------------------------------------------------
# Order is the order shown in the UI, roughly the order a hunt runs in.
PURPOSES = [
    ("subdomains",   "Subdomain enumeration", "finding hosts that are not linked anywhere"),
    ("dns",          "DNS & resolvers",       "resolving, filtering and validating what was found"),
    ("probing",      "HTTP probing",          "which hosts actually answer, and with what"),
    ("shots",        "Screenshots",           "seeing hundreds of hosts in minutes"),
    ("crawl",        "Crawling",              "walking a site to collect pages and parameters"),
    ("urls",         "Archive & URL sources", "URLs other people already discovered"),
    ("content",      "Content discovery",     "brute-forcing paths, files and directories"),
    ("params",       "Parameter discovery",   "finding inputs that are not in any link"),
    ("js",           "JavaScript & secrets",  "endpoints and keys left in shipped bundles"),
    ("vuln",         "Vulnerability scanning","template and signature based checks"),
    ("xss",          "Cross-site scripting",  "reflection, DOM sinks, stored payloads"),
    ("ssrf",         "Server-side requests",  "making the server fetch for you"),
    ("sqli",         "Injection",             "SQL / command / template injection"),
    ("takeover",     "Subdomain takeover",    "dangling DNS pointing at someone else"),
    ("cors",         "CORS & headers",        "origins, credentials and frame rules"),
    ("smuggling",    "Request smuggling",     "desync between proxy and origin"),
    ("jwt",          "JWT & tokens",          "algorithm confusion, weak secrets"),
    ("graphql",      "GraphQL",               "introspection, hidden fields, batching"),
    ("cloud",        "Cloud & storage",       "public buckets, cloud asset inventories"),
    ("secrets",      "Secret scanning",       "verified keys in code, history and builds"),
    ("intercept",    "Interception",          "the proxy where manual testing happens"),
    ("recon_suite",  "Full recon frameworks", "orchestrators that chain the rest"),
    ("wordlists",    "Wordlists",             "the input every brute-force needs"),
    ("utils",        "Glue & utilities",      "the one-liners between tools"),
]

PURPOSE_IDS = [p[0] for p in PURPOSES]

# Which stages each dashboard task category needs. An empty list means the task
# is manual testing — there is no CLI tool for "is this business logic wrong",
# and pretending otherwise would be worse than saying so.
CATEGORY_NEEDS = {
    "recon":               ["subdomains", "dns", "probing", "shots"],
    "js_audit":            ["js", "urls", "crawl"],
    "auth_session":        [],
    "access_control":      [],
    "injection":           ["sqli"],
    "xss":                 ["xss"],
    "ssrf":                ["ssrf"],
    "csrf_cors":           ["cors"],
    "redirect":            ["content"],
    "api_diff":            ["content", "crawl"],
    "deserialization":     [],
    "jwt_crypto":          ["jwt"],
    "file_upload":         [],
    "rate_limiting":       ["content"],
    "info_disclosure":     ["vuln", "content"],
    "business_logic":      [],
    "http_smuggling":      ["smuggling"],
    "subdomain_takeover":  ["takeover", "subdomains"],
}

# Executable name, when it is not the tool id. The image installs every other
# tool under a wrapper or binary that matches the id, so these are the only
# mismatches left.
BIN_OVERRIDES = {
    "kiterunner": "kr",
    "interactsh": "interactsh-client",
    "testssl": "testssl.sh",
}

# Tools that are used from a git checkout rather than a PATH binary. The image
# installs them under /opt and adds a wrapper where needed; these directories
# are the fallback so a manual clone is still recognised.
CHECK_DIRS = {
    "massdns":        ["/opt/massdns", "~/massdns"],
    "xsstrike":       ["/opt/XSStrike", "~/XSStrike"],
    "secretfinder":   ["/opt/SecretFinder", "~/SecretFinder"],
    "linkfinder":     ["/opt/LinkFinder", "~/LinkFinder"],
    "jwt_tool":       ["/opt/jwt_tool", "~/jwt_tool"],
    "ssrfmap":        ["/opt/SSRFmap", "~/SSRFmap"],
    "corsy":          ["/opt/Corsy", "~/Corsy"],
    "gopherus":       ["/opt/Gopherus", "~/Gopherus"],
    "smuggler":       ["/opt/smuggler", "~/smuggler"],
    "h2csmuggler":    ["/opt/h2cSmuggler", "~/h2cSmuggler"],
    "commix":         ["/opt/commix", "~/commix"],
    "nosqlmap":       ["/opt/NoSQLMap", "~/NoSQLMap"],
    "nikto":          ["/opt/nikto", "~/nikto"],
    "reconftw":       ["/opt/reconftw", "~/reconftw"],
    "seclists":       ["/opt/SecLists", "~/SecLists", "/usr/share/seclists"],
    "onelistforall":  ["/opt/OneListForAll", "~/OneListForAll"],
}

# --- the catalog ----------------------------------------------------------
# (id, purpose, what it is good at, github owner/repo, install command, default)
_RAW = [
    # subdomains
    ("subfinder", "subdomains", "passive enumeration across 30+ public sources; the usual starting point",
     "projectdiscovery/subfinder", "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", True),
    ("amass", "subdomains", "OWASP project; slower than subfinder but deeper, with graph output",
     "owasp-amass/amass", "go install -v github.com/owasp-amass/amass/v4/...@master", False),
    ("assetfinder", "subdomains", "tiny and fast; crt.sh, Facebook, threatcrowd and friends",
     "tomnomnom/assetfinder", "go install github.com/tomnomnom/assetfinder@latest", False),
    ("findomain", "subdomains", "fast certificate-log harvesting, ships a monitoring mode",
     "Findomain/Findomain", "download the release binary for your platform", False),
    ("chaos", "subdomains", "ProjectDiscovery's public bug-bounty host dataset",
     "projectdiscovery/chaos-client", "go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest", False),
    ("gotator", "subdomains", "permutations of known subdomains — finds the dev/staging twins",
     "Josue87/gotator", "go install github.com/Josue87/gotator@latest", False),
    ("alterx", "subdomains", "permutation engine from ProjectDiscovery, pipes into dnsx",
     "projectdiscovery/alterx", "go install github.com/projectdiscovery/alterx/cmd/alterx@latest", False),
    ("shuffledns", "subdomains", "massdns wrapper with wildcard filtering and clean output",
     "projectdiscovery/shuffledns", "go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest", False),

    # dns
    ("dnsx", "dns", "bulk resolution, wildcard filtering and record checks",
     "projectdiscovery/dnsx", "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest", True),
    ("massdns", "dns", "very high volume resolving; needs puredns in front of it",
     "blechschmidt/massdns", "git clone https://github.com/blechschmidt/massdns ~/massdns && make -C ~/massdns", False),
    ("puredns", "dns", "trusted resolver with wildcard/poisoning protection",
     "d3mondev/puredns", "go install github.com/d3mondev/puredns/v2@latest", False),
    ("tlsx", "dns", "TLS handshake data: SANs, expiry, misconfigurations",
     "projectdiscovery/tlsx", "go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest", False),

    # probing
    ("httpx", "probing", "probe hosts for status, title, tech and TLS — the recon workhorse",
     "projectdiscovery/httpx", "go install github.com/projectdiscovery/httpx/cmd/httpx@latest", True),
    ("httprobe", "probing", "minimal \"does this answer on 80/443\" probe",
     "tomnomnom/httprobe", "go install github.com/tomnomnom/httprobe@latest", False),
    ("cdncheck", "probing", "flags hosts sitting behind a CDN or WAF",
     "projectdiscovery/cdncheck", "go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest", False),
    ("naabu", "probing", "fast port discovery before HTTP probing; keeps scope to open ports",
     "projectdiscovery/naabu", "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest", False),

    # screenshots
    ("gowitness", "shots", "screenshot every live host, browse them in one view",
     "sensepost/gowitness", "go install github.com/sensepost/gowitness@latest", True),
    ("aquatone", "shots", "older but still useful screenshot + report generator",
     "michenriksen/aquatone", "download the release binary for your platform", False),

    # crawl
    ("katana", "crawl", "fast crawler with JS parsing and headless mode",
     "projectdiscovery/katana", "go install github.com/projectdiscovery/katana/cmd/katana@latest", True),
    ("hakrawler", "crawl", "simple, fast, good with JS files",
     "hakluke/hakrawler", "go install github.com/hakluke/hakrawler@latest", False),
    ("gospider", "crawl", "concurrent spider with sitemap and robots parsing",
     "jaeles-project/gospider", "go install github.com/jaeles-project/gospider@latest", False),
    ("waymore", "crawl", "pulls from Wayback, Common Crawl, AlienVault and URLScan",
     "xnl-h4ck3r/waymore", "pipx install waymore", False),

    # urls
    ("gau", "urls", "getallurls from Wayback, Common Crawl and OTX",
     "lc/gau", "go install github.com/lc/gau/v2/cmd/gau@latest", True),
    ("waybackurls", "urls", "the original Wayback URL dump",
     "tomnomnom/waybackurls", "go install github.com/tomnomnom/waybackurls@latest", False),

    # content discovery
    ("ffuf", "content", "the standard for fuzzing paths, params and vhosts",
     "ffuf/ffuf", "go install github.com/ffuf/ffuf/v2@latest", True),
    ("dirsearch", "content", "directory brute-force with sensible defaults",
     "maurosoria/dirsearch", "pipx install dirsearch", False),
    ("feroxbuster", "content", "recursive discovery, Rust speed",
     "epi052/feroxbuster", "download the release binary for your platform", False),
    ("gobuster", "content", "dir/dns/vhost brute-force in one binary",
     "OJ/gobuster", "go install github.com/OJ/gobuster/v3@latest", False),
    ("kiterunner", "content", "API-aware wordlists; finds routes ffuf misses",
     "assetnote/kiterunner", "download the release binary (installs as kr)", False),

    # params
    ("arjun", "params", "parameter discovery by fuzzing and comparing responses",
     "s0md3v/Arjun", "pipx install arjun", True),
    ("x8", "params", "Rust parameter brute-forcer, quieter than arjun",
     "Sh1Yo/x8", "download the release binary for your platform", False),
    ("paramspider", "params", "harvests parameters from archived URLs",
     "devanshbatham/ParamSpider", "pipx install git+https://github.com/devanshbatham/ParamSpider", False),

    # js & secrets
    ("linkfinder", "js", "endpoints and paths inside JS files",
     "GerbenJavado/LinkFinder", "git clone https://github.com/GerbenJavado/LinkFinder ~/LinkFinder && pip install -r ~/LinkFinder/requirements.txt", True),
    ("jsluice", "js", "structured JS analysis: URLs, secrets, DOM sinks",
     "BishopFox/jsluice", "go install github.com/BishopFox/jsluice/cmd/jsluice@latest", False),
    ("secretfinder", "js", "regex sweep for keys in JS",
     "m4ll0k/SecretFinder", "git clone https://github.com/m4ll0k/SecretFinder ~/SecretFinder && pip install jsbeautifier lxml requests", False),
    ("subjs", "js", "lists every JS file a site loads",
     "lc/subjs", "go install github.com/lc/subjs@latest", False),
    ("trufflehog", "js", "verified secret scanning across repos and filesystems",
     "trufflesecurity/trufflehog", "download the release binary for your platform", False),
    ("gitleaks", "js", "fast secret scanning for git history and working trees",
     "gitleaks/gitleaks", "go install github.com/zricethezav/gitleaks/v8@latest", False),
    ("sourcemapper", "js", "restores readable source from a leaked .map file",
     "denandz/sourcemapper", "go install github.com/denandz/sourcemapper@latest", False),

    # vuln scanning
    ("nuclei", "vuln", "template engine for CVEs, misconfigurations and takeovers",
     "projectdiscovery/nuclei", "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", True),
    ("nikto", "vuln", "classic web server misconfiguration scanner",
     "sullo/nikto", "git clone https://github.com/sullo/nikto ~/nikto", False),
    ("jaeles", "vuln", "signature based scanner with its own template language",
     "jaeles-project/jaeles", "go install github.com/jaeles-project/jaeles@latest", False),
    ("wpscan", "vuln", "WordPress specific: plugins, themes, users",
     "wpscanteam/wpscan", "gem install wpscan", False),
    ("wafw00f", "vuln", "identifies which WAF is in front of a host",
     "EnableSecurity/wafw00f", "pipx install wafw00f", False),

    # xss
    ("dalfox", "xss", "parameter analysis, reflected/stored/DOM XSS, heads-up on WAF",
     "hahwul/dalfox", "go install github.com/hahwul/dalfox/v2@latest", True),
    ("xsstrike", "xss", "payload generation and context-aware fuzzing",
     "s0md3v/XSStrike", "git clone https://github.com/s0md3v/XSStrike ~/XSStrike && pip install -r ~/XSStrike/requirements.txt", False),
    ("gf", "xss", "pattern matcher; `gf xss` narrows URLs down to testable ones",
     "tomnomnom/gf", "go install github.com/tomnomnom/gf@latest", False),
    ("kxss", "xss", "finds which parameters actually reflect, before payload work",
     "Emoe/kxss", "go install github.com/Emoe/kxss@latest", False),

    # ssrf
    ("ssrfmap", "ssrf", "exploits SSRF once found: gopher, files, metadata endpoints",
     "swisskyrepo/SSRFmap", "git clone https://github.com/swisskyrepo/SSRFmap ~/SSRFmap && pip install -r ~/SSRFmap/requirements.txt", True),
    ("interactsh", "ssrf", "out-of-band interaction server + client for blind SSRF",
     "projectdiscovery/interactsh", "go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest", False),
    ("gopherus", "ssrf", "payload generator for gopher-based SSRF chains",
     "tarunkant/Gopherus", "git clone https://github.com/tarunkant/Gopherus ~/Gopherus", False),

    # injection
    ("sqlmap", "sqli", "the reference SQL injection tool; slow but thorough",
     "sqlmapproject/sqlmap", "pipx install sqlmap", True),
    ("ghauri", "sqli", "modern, faster sqlmap alternative",
     "r0oth3x49/ghauri", "pipx install git+https://github.com/r0oth3x49/ghauri", False),
    ("commix", "sqli", "command injection exploitation",
     "commixproject/commix", "git clone https://github.com/commixproject/commix ~/commix", False),
    ("nosqlmap", "sqli", "NoSQL injection and exploitation",
     "codingo/NoSQLMap", "git clone https://github.com/codingo/NoSQLMap ~/NoSQLMap && pip install -r ~/NoSQLMap/requirements.txt", False),

    # takeover
    ("subzy", "takeover", "checks a host list for claimable dangling services",
     "PentestPad/subzy", "go install github.com/PentestPad/subzy@latest", True),
    ("subjack", "takeover", "the original takeover checker; older fingerprint set",
     "haccer/subjack", "go install github.com/haccer/subjack@latest", False),

    # cors
    ("corsy", "cors", "finds reflected origins, null origin and credential leaks",
     "s0md3v/Corsy", "git clone https://github.com/s0md3v/Corsy ~/Corsy && pip install requests", True),

    # smuggling
    ("smuggler", "smuggling", "CL.TE / TE.CL desync probes",
     "defparam/smuggler", "git clone https://github.com/defparam/smuggler ~/smuggler", True),
    ("h2csmuggler", "smuggling", "HTTP/2 cleartext upgrade smuggling",
     "BishopFox/h2cSmuggler", "git clone https://github.com/BishopFox/h2cSmuggler ~/h2cSmuggler && pip install requests", False),

    # jwt
    ("jwt_tool", "jwt", "alg confusion, none, weak secrets, kid injection",
     "ticarpi/jwt_tool", "git clone https://github.com/ticarpi/jwt_tool ~/jwt_tool && pip install -r ~/jwt_tool/requirements.txt", True),

    # graphql
    ("graphql-cop", "graphql", "security audit for GraphQL: introspection, batching, depth",
     "dolevf/graphql-cop", "git clone https://github.com/dolevf/graphql-cop ~/graphql-cop && pip install -r ~/graphql-cop/requirements.txt", True),
    ("clairvoyance", "graphql", "recovers a schema even when introspection is disabled",
     "nikitastupin/clairvoyance", "pipx install clairvoyance", False),
    ("graphqlmap", "graphql", "interactive GraphQL exploitation and query builder",
     "dolevf/graphqlmap", "pipx install graphqlmap", False),

    # cloud & storage
    ("cloudlist", "cloud", "lists cloud assets across providers using your own credentials",
     "projectdiscovery/cloudlist", "go install github.com/projectdiscovery/cloudlist/cmd/cloudlist@latest", True),
    ("s3scanner", "cloud", "checks storage buckets for public read/write and listing",
     "sa7mon/s3scanner", "go install github.com/sa7mon/s3scanner@latest", False),
    ("cloud_enum", "cloud", "multi-cloud public asset enumeration (AWS, Azure, GCP)",
     "initstring/cloud_enum", "git clone https://github.com/initstring/cloud_enum ~/cloud_enum && pip install -r ~/cloud_enum/requirements.txt", False),

    # secret scanning
    ("noseyparker", "secrets", "high-signal secret scan across repos and filesystems",
     "praetorian-inc/noseyparker", "download the release binary for your platform", True),

    # interception
    ("mitmproxy", "intercept", "scriptable HTTPS proxy for manual auth/logic testing",
     "mitmproxy/mitmproxy", "pipx install mitmproxy", True),
    ("caido", "intercept", "modern lightweight web proxy with a plugin API",
     "caido/caido", "download the desktop/release build from caido.io", False),

    # frameworks
    ("bbot", "recon_suite", "recursive recon framework: subdomains, ports, web, vulns",
     "blacklanternsecurity/bbot", "pipx install bbot", False),
    ("reconftw", "recon_suite", "shell framework that chains subfinder/httpx/nuclei/dalfox",
     "six2dez/reconftw", "git clone https://github.com/six2dez/reconftw ~/reconftw", True),
    ("osmedeus", "recon_suite", "workflow engine for recon and vuln scanning",
     "j3ssie/osmedeus", "download the release binary for your platform", False),
    ("rengine", "recon_suite", "web UI that runs the whole recon pipeline for you",
     "yogeshojha/rengine", "external platform: clone it and run `docker compose up` on its own host — cannot live inside this image", False),

    # wordlists
    ("seclists", "wordlists", "the default wordlist collection for everything above",
     "danielmiessler/SecLists", "git clone --depth 1 https://github.com/danielmiessler/SecLists ~/SecLists", True),
    ("onelistforall", "wordlists", "one merged wordlist, handy for ffuf",
     "six2dez/OneListForAll", "git clone --depth 1 https://github.com/six2dez/OneListForAll ~/OneListForAll", False),

    # utils
    ("unfurl", "utils", "split URLs into their parts for piping",
     "tomnomnom/unfurl", "go install github.com/tomnomnom/unfurl@latest", True),
    ("anew", "utils", "append only new lines — the dedupe primitive",
     "tomnomnom/anew", "go install github.com/tomnomnom/anew@latest", False),
    ("qsreplace", "utils", "swap query values across a list of URLs",
     "tomnomnom/qsreplace", "go install github.com/tomnomnom/qsreplace@latest", False),
    ("notify", "utils", "push results to Slack/Discord/Telegram",
     "projectdiscovery/notify", "go install github.com/projectdiscovery/notify/cmd/notify@latest", False),
    ("gron", "utils", "turn JSON into greppable lines — the fastest way to read an API response",
     "tomnomnom/gron", "go install github.com/tomnomnom/gron@latest", False),
]

TOOLS = {}
for _id, _purpose, _what, _repo, _install, _default in _RAW:
    TOOLS[_id] = {
        "id": _id,
        "name": _id,
        "bin": BIN_OVERRIDES.get(_id, _id),
        "purpose": _purpose,
        "what": _what,
        "repo": "https://github.com/" + _repo,
        "slug": _repo,
        "install": _install,
        "default": bool(_default),
    }


# --- catalog queries ------------------------------------------------------

def get(tool_id):
    return TOOLS.get(tool_id)


def purpose_label(purpose_id):
    for pid, label, _blurb in PURPOSES:
        if pid == purpose_id:
            return label
    return purpose_id


def tools_in(purpose_id):
    """Catalog order, defaults first."""
    return [t for t in TOOLS.values() if t["purpose"] == purpose_id]


def alternatives(tool_id):
    tool = TOOLS.get(tool_id)
    if not tool:
        return []
    return [t["id"] for t in tools_in(tool["purpose"]) if t["id"] != tool_id]


def default_for(purpose_id):
    candidates = tools_in(purpose_id)
    for t in candidates:
        if t["default"]:
            return t["id"]
    return candidates[0]["id"] if candidates else None


def categories_for_purpose(purpose_id):
    return [c for c, needs in CATEGORY_NEEDS.items() if purpose_id in needs]


# --- selection (tools.json) ----------------------------------------------

def load_selection():
    data = common.read_json(SELECTION_PATH, {}) or {}
    raw = data.get("selected") or {}
    chosen = {}
    for pid in PURPOSE_IDS:
        tid = raw.get(pid)
        if tid in TOOLS and TOOLS[tid]["purpose"] == pid:
            chosen[pid] = tid
    return chosen


def save_selection(partial):
    """Merge a partial {purpose: tool_id} map into tools.json."""
    current = load_selection()
    for pid, tid in (partial or {}).items():
        if pid not in PURPOSE_IDS:
            raise ValueError("unknown stage %r" % pid)
        if tid not in TOOLS:
            raise ValueError("unknown tool %r" % tid)
        if TOOLS[tid]["purpose"] != pid:
            raise ValueError("%s is not part of the %s stage" % (tid, pid))
        current[pid] = tid
    common.atomic_write_json(SELECTION_PATH, {"selected": current})
    return current


def selected_for(purpose_id):
    return load_selection().get(purpose_id) or default_for(purpose_id)


def tools_for_category(category):
    """The tools a task in this category is expected to reach for."""
    out = []
    for pid in CATEGORY_NEEDS.get(category, []):
        tid = selected_for(pid)
        if tid:
            out.append(tid)
    return out


# --- detection ------------------------------------------------------------

_cache = {}
_cache_lock = threading.Lock()


def _probe(tool):
    # A binary on PATH is the normal case. Tools that are used from a git
    # checkout count as present when that checkout exists, so the UI does not
    # keep saying "need install" for something the user just cloned.
    path = shutil.which(tool["bin"])
    if path:
        version = None
        for flag in ("--version", "-version", "-v"):
            try:
                done = subprocess.run(
                    [path, flag], capture_output=True, text=True, timeout=VERSION_TIMEOUT
                )
            except Exception:
                continue
            text = ((done.stdout or "") + "\n" + (done.stderr or "")).strip()
            first = text.splitlines()[0].strip() if text else ""
            if first:
                version = first[:80]
                break
        return {"installed": True, "version": version, "path": path}

    for candidate in CHECK_DIRS.get(tool["id"], []):
        expanded = os.path.expanduser(candidate)
        if os.path.isdir(expanded):
            return {"installed": True, "version": None, "path": expanded}

    return {"installed": False, "version": None, "path": None}


def detect(tool_id, refresh=False):
    """{installed, version, path}. Cached briefly so the UI can poll."""
    tool = TOOLS.get(tool_id)
    if not tool:
        return {"installed": False, "version": None, "path": None}
    now = time.time()
    with _cache_lock:
        hit = _cache.get(tool_id)
        if hit and not refresh and now - hit[0] < CACHE_TTL:
            return dict(hit[1])
    result = _probe(tool)
    with _cache_lock:
        _cache[tool_id] = (now, result)
    return dict(result)


def is_installed(tool_id):
    return detect(tool_id)["installed"]


def missing_for_categories(categories):
    """Tools the selected task categories need but that are not installed."""
    wanted = []
    for category in categories or []:
        for tid in tools_for_category(category):
            if tid not in wanted:
                wanted.append(tid)
    missing = []
    for tid in wanted:
        if not is_installed(tid):
            tool = TOOLS[tid]
            missing.append({
                "id": tid,
                "name": tool["name"],
                "purpose": tool["purpose"],
                "install": tool["install"],
                "repo": tool["repo"],
            })
    return missing


# --- view for the dashboard ----------------------------------------------

def purpose_view(refresh=False):
    chosen = load_selection()
    stages = []
    for pid, label, blurb in PURPOSES:
        tools = []
        selected_id = chosen.get(pid) or default_for(pid)
        for tool in tools_in(pid):
            status = detect(tool["id"], refresh=refresh)
            tools.append({
                "id": tool["id"],
                "name": tool["name"],
                "bin": tool["bin"],
                "what": tool["what"],
                "repo": tool["repo"],
                "install": tool["install"],
                "default": tool["id"] == default_for(pid),
                "installed": status["installed"],
                "version": status["version"],
                "selected": tool["id"] == selected_id,
            })
        chosen_tool = TOOLS.get(selected_id) if selected_id else None
        stages.append({
            "id": pid,
            "label": label,
            "blurb": blurb,
            "selected": selected_id,
            "selected_installed": bool(chosen_tool and detect(selected_id)["installed"]),
            "needed_by": categories_for_purpose(pid),
            "tools": tools,
        })
    return stages


def summary(refresh=False, stages=None):
    stages = stages if stages is not None else purpose_view(refresh=refresh)
    selected_total = 0
    installed = 0
    missing = []
    for stage in stages:
        selected_total += 1
        if stage["selected_installed"]:
            installed += 1
        elif stage["selected"]:
            tool = TOOLS[stage["selected"]]
            missing.append({
                "id": tool["id"],
                "name": tool["name"],
                "purpose": stage["id"],
                "install": tool["install"],
                "repo": tool["repo"],
            })
    return {
        "catalogued": len(TOOLS),
        "stages": len(stages),
        "selected_total": selected_total,
        "installed": installed,
        "missing": missing,
    }
