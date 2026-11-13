#!/usr/bin/env python3
"""logs.py — safe management of the per-agent log files.

The dashboard exposes log deletion, which is a destructive action, so the rules
live in one place instead of in a request handler:

  * a log name is an agent name plus `.log`; anything with a path separator,
    `..`, or a name that does not match common.NAME_RE is rejected
  * every deletion is appended to an audit log first, so "who deleted the
    evidence" is answerable even after the file is gone
  * clearing is explicit: the caller must pass confirm="CLEAR"
  * reading is tail-based and bounded, so a 500 MB log cannot be pulled into
    the browser in one response

Nothing here touches state/runs/ — those are the evidence store, not logs, and
are only removed by the retention policy in common.prune_runs().
"""

import os

import common

MAX_TAIL = 2000                 # lines returned by read()
AUDIT_DIR = os.path.join(common.DATA_DIR, "audit")
AUDIT_PATH = os.path.join(AUDIT_DIR, "audit.jsonl")


def _safe_log_name(name):
    raw = (name or "").strip()
    if not raw.endswith(".log"):
        raw += ".log"
    stem = raw[:-4]
    if not common.NAME_RE.match(stem) or stem in (".", ".."):
        raise ValueError("invalid log name %r" % name)
    return stem + ".log"


def _path(name):
    return os.path.join(common.LOG_DIR, _safe_log_name(name))


def audit(action, detail, actor="dashboard"):
    """Append one line to the audit trail. Never raises into a request."""
    entry = {
        "ts": common.now_iso(),
        "actor": (actor or "dashboard")[:60],
        "action": (action or "unknown")[:60],
        "detail": detail if isinstance(detail, (dict, list)) else str(detail)[:2000],
    }
    try:
        common.append_jsonl(AUDIT_PATH, entry)
    except OSError:
        pass
    return entry


def list_logs():
    """Every *.log in the data directory, newest first, with a cheap summary."""
    common.ensure_dirs()
    out = []
    try:
        names = os.listdir(common.LOG_DIR)
    except OSError:
        return out
    for fname in names:
        if not fname.endswith(".log"):
            continue
        try:
            stem = fname[:-4]
            if not common.NAME_RE.match(stem):
                continue
            path = os.path.join(common.LOG_DIR, fname)
            st = os.stat(path)
        except (OSError, ValueError):
            continue
        out.append({
            "name": fname,
            "agent": fname[:-4],
            "size": st.st_size,
            "modified": st.st_mtime,
            "lines": _count_lines(path, limit=200000),
        })
    out.sort(key=lambda x: x["modified"], reverse=True)
    return out


def _count_lines(path, limit=200000):
    count = 0
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for _ in f:
                count += 1
                if count >= limit:
                    break
    except OSError:
        return 0
    return count


def read_log(name, tail=400):
    """Return the last `tail` lines of one log. Bounded and path-safe."""
    path = _path(name)
    if not os.path.isfile(path):
        raise FileNotFoundError("no such log: %s" % _safe_log_name(name))
    try:
        tail = int(tail)
    except (TypeError, ValueError):
        tail = 400
    tail = max(1, min(tail, MAX_TAIL))
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError as exc:
        raise OSError("could not read %s: %s" % (name, exc))
    return {
        "name": _safe_log_name(name),
        "lines": [line.rstrip("\n") for line in lines[-tail:]],
        "returned": min(len(lines), tail),
        "total": len(lines),
        "size": os.path.getsize(path),
    }


def delete_log(name):
    """Delete one log file. Returns {deleted, name, bytes}."""
    path = _path(name)
    safe = _safe_log_name(name)
    if not os.path.isfile(path):
        raise FileNotFoundError("no such log: %s" % safe)
    size = os.path.getsize(path)
    audit("log.delete", {"name": safe, "bytes": size})
    os.remove(path)
    return {"deleted": True, "name": safe, "bytes": size}


def clear_logs(confirm, actor="dashboard"):
    """Delete every log file. Requires confirm == 'CLEAR'."""
    if (confirm or "").strip().upper() != "CLEAR":
        raise ValueError('confirmation required: send {"confirm": "CLEAR"}')
    common.ensure_dirs()
    deleted, failed = [], []
    try:
        names = sorted(os.listdir(common.LOG_DIR))
    except OSError:
        names = []
    for fname in names:
        if not fname.endswith(".log"):
            continue
        path = os.path.join(common.LOG_DIR, fname)
        if not os.path.isfile(path):
            continue
        try:
            size = os.path.getsize(path)
            os.remove(path)
            deleted.append({"name": fname, "bytes": size})
        except OSError as exc:
            failed.append({"name": fname, "error": str(exc)})
    audit("log.clear", {"deleted": len(deleted), "failed": len(failed)}, actor=actor)
    return {"cleared": len(deleted), "deleted": deleted, "failed": failed}


def trim(name, max_bytes=5 * 1024 * 1024):
    """Keep a log from growing without bound. Called by the writer, not the UI."""
    path = _path(name)
    try:
        if os.path.getsize(path) <= max_bytes:
            return False
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        keep = lines[len(lines) // 2:]
        with open(path, "w", encoding="utf-8") as f:
            f.writelines(keep)
        return True
    except OSError:
        return False


def audit_tail(tail=100):
    rows = common.read_jsonl(AUDIT_PATH)
    return rows[-max(1, min(int(tail or 100), 1000)):]
