#!/usr/bin/env python3
"""planning.py — turn a target profile into a ranked, explained hunt plan.

surface.py already answers "what is this target?" and returns categories with a
confidence. That is a good start, but "high/medium/low" is not an order of
work. This module adds what an experienced tester actually does next:

  * a numeric priority, so two categories with the same confidence still sort
  * concrete surface evidence (a form, a JWT, an upload field) that lifts a
    category above the generic baseline
  * the first two manual steps, so the operator is never staring at a blank tab
  * an explicit automated/manual flag from methods.AUTOMATED

No network access. The caller passes the profile it already fetched; if there
is no profile, the plan is the honest default: recon, then breadth.
"""

from datetime import datetime, timezone

import methods

CONFIDENCE_SCORE = {"high": 90, "medium": 60, "low": 30}

# A category can be lifted by observable surface features. These are the same
# signals surface.py collects; keeping the weights here makes the ordering
# tunable without touching the profiler.
SURFACE_BOOSTS = {
    "forms": {"injection": 18, "xss": 18, "csrf_cors": 16, "business_logic": 10},
    "upload": {"file_upload": 45, "xss": 8},
    "graphql": {"api_diff": 30, "access_control": 12},
    "jwt": {"jwt_crypto": 40, "auth_session": 12},
    "api": {"api_diff": 25, "access_control": 15, "business_logic": 8},
    "redirect": {"redirect": 25},
    "ssrf": {"ssrf": 30},
    "object_ids": {"access_control": 25},
    "cookies": {"auth_session": 15, "csrf_cors": 10},
    "no_csp": {"xss": 10},
}

# Always worth a first pass, regardless of fingerprint. Small on purpose: the
# profile should still dominate the order.
BASELINE = {
    "recon": 55,
    "info_disclosure": 22,
    "access_control": 18,
    "auth_session": 12,
    "xss": 10,
}

MAX_STEPS = 10


def _now():
    return datetime.now(timezone.utc).isoformat()


def _profile_features(profile):
    """Which SURFACE_BOOSTS keys the profile actually supports."""
    if not profile or not profile.get("ok"):
        return set()
    feats = set()
    params = profile.get("params") or {}
    if (params.get("search") or []):
        feats.add("forms")
    if (params.get("redirect") or []):
        feats.add("redirect")
    if (params.get("ssrf") or []):
        feats.add("ssrf")
    if (params.get("object") or []):
        feats.add("object_ids")
    if (profile.get("forms") or []):
        feats.add("forms")
    if (profile.get("uploads") or []):
        feats.add("upload")
    if (profile.get("graphql")):
        feats.add("graphql")
    if (profile.get("jwt_seen")):
        feats.add("jwt")
    if (profile.get("api_hints") or profile.get("openapi")):
        feats.add("api")
    if (profile.get("cookies") or []):
        feats.add("cookies")
    sec = profile.get("security") or {}
    if sec.get("csp") is False:
        feats.add("no_csp")
    return feats


def _first_actions(category, limit=2):
    playbook = methods.get(category) or {}
    out = []
    for step in (playbook.get("steps") or [])[:limit]:
        out.append({"title": step["title"], "detail": step["detail"]})
    return out


def build_plan(target, profile=None):
    """Rank categories for `target`. Pure function; never raises on bad input."""
    scores = {}
    reasons = {}
    confidence = {}

    def add(category, points, reason):
        if category not in methods.METHODS:
            return
        scores[category] = scores.get(category, 0) + points
        reasons.setdefault(category, [])
        if reason and reason not in reasons[category]:
            reasons[category].append(reason)

    for category, points in BASELINE.items():
        add(category, points, "baseline: worth a first pass on almost any web target")

    if profile and profile.get("ok"):
        for c in profile.get("categories") or []:
            cat = c.get("category")
            conf = c.get("confidence")
            add(cat, CONFIDENCE_SCORE.get(conf, 20),
                c.get("reason") or ("%s confidence from the target check" % conf))
            confidence[cat] = conf

    for feature in _profile_features(profile):
        for category, points in SURFACE_BOOSTS.get(feature, {}).items():
            label = {
                "forms": "a form or search parameter is present",
                "upload": "an upload field is present",
                "graphql": "a GraphQL endpoint answered",
                "jwt": "a JWT was observed",
                "api": "API documentation or API-shaped routes were seen",
                "redirect": "a redirect parameter is present",
                "ssrf": "a URL-fetch parameter is present",
                "object_ids": "object-id parameters are present",
                "cookies": "session cookies are set",
                "no_csp": "the CSP header is missing, so injected markup is not restricted by policy",
            }.get(feature, feature)
            reason = "surface: " + label
            # The profile already explains a missing CSP; adding the boost's
            # wording on top reads as the same fact stated twice.
            if feature == "no_csp" and any(
                    "csp" in r.lower() or "content-security-policy" in r.lower()
                    for r in reasons.get(category, [])):
                reason = None
            add(category, points, reason)

    if not scores:
        add("recon", 60, "no profile available — start with recon")

    steps = []
    for rank, (category, score) in enumerate(
            sorted(scores.items(), key=lambda kv: (-kv[1], kv[0]))[:MAX_STEPS], 1):
        playbook = methods.get(category) or {}
        steps.append({
            "rank": rank,
            "category": category,
            "name": playbook.get("name", category),
            "tagline": playbook.get("tagline", ""),
            "score": round(score, 1),
            "confidence": confidence.get(category, "baseline"),
            "automated": category in methods.AUTOMATED,
            "tools": list(playbook.get("tools") or [])[:6],
            "reason": "; ".join(reasons.get(category, [])[:3]),
            "first_actions": _first_actions(category),
            "severity_hint": playbook.get("severity_hint", ""),
        })

    automated = [s["category"] for s in steps if s["automated"]]
    manual = [s["category"] for s in steps if not s["automated"]]
    return {
        "ok": True,
        "target": target,
        "generated": _now(),
        "profile_ok": bool(profile and profile.get("ok")),
        "steps": steps,
        "automated": automated,
        "manual": manual,
        "summary": (
            "Start with %s. %d category(ies) can run bounded checks; %d need a "
            "manual pass with credentials or a browser."
            % (", ".join(s["category"] for s in steps[:3]) or "recon",
               len(automated), len(manual))
        ),
    }
