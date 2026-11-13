#!/usr/bin/env python3
"""scope_guard.py — the one place that answers "is this target allowed?".

The form in the dashboard is a convenience; this module is the enforcement
point. Call assert_allowed(host) immediately before any tool actually touches
a host — nuclei, ffuf, httpx, a redirect target, a webhook URL. Subfinder
regularly surfaces names that are CNAMEs into a third-party SaaS; those are
out of scope even though they matched your wildcard, and only a per-host check
catches them.

Entry syntax (scope.json, one per line in the UI):

    example.com          -> example.com and every subdomain of it
    *.example.com        -> the same (the "*." is stripped; the apex is
                            included, because that is what people mean)
    api.partner.com      -> exactly that host
    10.0.0.0/8           -> any address inside the range
    203.0.113.9          -> exactly that address
    https://app.x.com/a  -> scheme, path and port are ignored

Out-of-scope always wins over in-scope.
"""

import ipaddress

from urllib.parse import urlsplit

from common import load_scope


class ScopeError(Exception):
    """Raised when an agent tries to touch something outside the scope."""


def _clean(value):
    return (value or "").strip().lower().rstrip(".")


def host_of(target):
    """'https://user:pw@App.Example.com:8443/x?y=1' -> 'app.example.com'."""
    raw = _clean(target)
    if not raw:
        return ""
    candidate = raw if "://" in raw else "//" + raw
    try:
        host = urlsplit(candidate).hostname or ""
    except ValueError:
        host = ""
    if not host:
        host = raw.split("/")[0].split("@")[-1]
        if host.count(":") == 1:  # host:port that urlsplit could not parse
            host = host.split(":")[0]
    return _clean(host)


def _is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def parse_entry(entry):
    """-> (kind, value) with kind in {'cidr', 'domain'} or (None, None)."""
    raw = _clean(entry).lstrip("*").lstrip(".")
    if not raw:
        return (None, None)
    if "://" in raw:
        raw = host_of(raw)
        if not raw:
            return (None, None)
    if "/" in raw:
        try:
            return ("cidr", ipaddress.ip_network(raw, strict=False))
        except ValueError:
            raw = raw.split("/")[0]
    if _is_ip(raw):
        try:
            return ("cidr", ipaddress.ip_network(raw, strict=False))
        except ValueError:
            return (None, None)
    host = host_of(raw)
    return ("domain", host) if host else (None, None)


def matches(host, parsed):
    kind, value = parsed
    if not kind or not host:
        return False
    if kind == "cidr":
        try:
            return ipaddress.ip_address(host) in value
        except ValueError:
            return False
    return host == value or host.endswith("." + value)


def check(target, scope=None, allow_empty=False):
    """-> (allowed: bool, reason: str | None).

    Fail closed: an empty in-scope list blocks every target. The old behaviour
    warned and allowed, which meant a fresh install would happily scan anything
    the operator typed. `allow_empty=True` exists only for offline previews and
    tests that never make a request.
    """
    scope = scope if scope is not None else load_scope()
    host = host_of(target)
    if not host:
        return (False, "could not parse a hostname out of %r" % (target,))

    for entry in scope.get("out_scope", []):
        if matches(host, parse_entry(entry)):
            return (False, '"%s" matches an out-of-scope entry: "%s"' % (host, entry))

    in_scope = scope.get("in_scope", [])
    if in_scope:
        for entry in in_scope:
            if matches(host, parse_entry(entry)):
                return (True, None)
        return (False, '"%s" does not match any in-scope entry. Add it under Scope, '
                       'or turn off strict scope so it is added automatically.' % host)

    if allow_empty:
        return (True, "no in-scope list configured — empty-scope test mode")
    return (False, "no in-scope list configured. Add the program's domains under "
                   "Scope, or turn off strict scope so the submitted target is "
                   "added automatically.")



def missing_from_scope(target, scope=None):
    """-> host when it is parseable, not excluded, and not already in scope.

    Pure decision helper used by lenient mode and by the UI before a live plan.
    An out-of-scope match returns None, so a host can never be admitted through
    this path; an existing entry (including a wildcard or CIDR) returns None.
    """
    scope = scope if scope is not None else load_scope()
    host = host_of(target)
    if not host:
        return None
    for entry in scope.get("out_scope", []):
        if matches(host, parse_entry(entry)):
            return None
    for entry in scope.get("in_scope", []):
        if matches(host, parse_entry(entry)):
            return None
    return host


def adopt_if_empty(target, scope=None):
    """-> host to adopt when the in-scope list is empty, else None.

    Kept for callers that only want first-target adoption; lenient mode uses
    missing_from_scope so a target outside a non-empty list is added too.
    """
    scope = scope if scope is not None else load_scope()
    if scope.get("in_scope"):
        return None
    return missing_from_scope(target, scope)


def assert_allowed(target, scope=None):
    """Raise ScopeError unless target is in scope. Returns the parsed host."""
    allowed, reason = check(target, scope)
    if not allowed:
        raise ScopeError(reason)
    return host_of(target)


def describe_entries(entries):
    """Small helper for the dashboard: how each entry was understood."""
    out = []
    for entry in entries:
        kind, value = parse_entry(entry)
        out.append({"entry": entry, "kind": kind, "parsed": str(value) if value else None})
    return out
