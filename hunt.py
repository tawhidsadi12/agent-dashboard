#!/usr/bin/env python3
"""hunt.py — one command to run an agent hunt.

    python3 hunt.py example.com            3 rounds, target added to scope
    python3 hunt.py example.com 5          5 rounds
    python3 hunt.py example.com 3 xss,ssrf only those categories
    python3 hunt.py --web                  dashboard at http://127.0.0.1:8777
    python3 hunt.py --tools                installed / missing catalog tools
    python3 hunt.py --install-tools        install the catalog (Linux, sudo, slow)
    python3 hunt.py --stop                 request an emergency stop

The first run creates .venv and installs Flask, so a fresh clone only needs:

    python3 hunt.py example.com

Scope, authorization and the stop latch are checked exactly as the dashboard
does it. Out-of-scope targets are refused; there is no flag that bypasses that.
"""

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
VENV = os.path.join(ROOT, ".venv")
REQUIREMENTS = os.path.join(ROOT, "requirements.txt")


def _venv_python():
    if os.name == "nt":
        return os.path.join(VENV, "Scripts", "python.exe")
    return os.path.join(VENV, "bin", "python")


def _say(message):
    print("[hunt] %s" % message)


def _in_project_venv():
    try:
        return os.path.samefile(sys.executable, _venv_python())
    except OSError:
        return False


def _ensure_venv():
    python = _venv_python()
    if not os.path.isfile(python):
        _say("creating .venv (first run only)")
        subprocess.check_call([sys.executable, "-m", "venv", VENV])
    probe = subprocess.run([python, "-c", "import flask"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if probe.returncode != 0:
        _say("installing Flask")
        subprocess.check_call([python, "-m", "pip", "install", "-q",
                               "-r", REQUIREMENTS])


def _relaunch_in_venv(argv):
    """Re-run this file with the project venv, so system Python stays untouched."""
    _ensure_venv()
    os.execv(_venv_python(), [_venv_python(), os.path.abspath(__file__)] + argv)


def _project():
    """Import the app's modules from the project root."""
    if ROOT not in sys.path:
        sys.path.insert(0, ROOT)
    import common
    import scope_guard
    return common, scope_guard


def prepare_target(target):
    """Scope + authorization + stop-latch checks; returns the parsed host."""
    common, scope_guard = _project()
    common.ensure_dirs()

    host = scope_guard.host_of(target)
    if not host:
        raise SystemExit("[hunt] cannot parse a hostname out of %r" % target)

    scope = scope_guard.load_scope()
    for entry in scope.get("out_scope", []):
        if scope_guard.matches(host, scope_guard.parse_entry(entry)):
            raise SystemExit("[hunt] %s is out of scope (%r)" % (host, entry))

    if common.auth_required():
        record = common.load_authorization()
        if not record.get("confirmed"):
            raise SystemExit(
                "[hunt] this installation requires a confirmed authorization "
                "record.\n[hunt] add it under Scope & authorization in the "
                "dashboard, or set HUNT_REQUIRE_AUTH=0 if you accept the risk.")

    in_scope = scope.setdefault("in_scope", [])
    known = any(scope_guard.matches(host, scope_guard.parse_entry(entry))
                for entry in in_scope)
    if not known:
        in_scope.append(host)
        common.atomic_write_json(common.SCOPE_PATH, scope)
        _say("added %s to scope.json" % host)

    if common.stop_requested():
        common.clear_stop()
        _say("cleared the emergency-stop latch")

    return host


def parse_target(argv):
    """argv -> (target, rounds, categories or None)."""
    target = argv[0]
    rounds = 3
    if len(argv) > 1:
        try:
            rounds = int(argv[1])
        except ValueError:
            raise SystemExit("[hunt] rounds must be a number, got %r" % argv[1])
        if not 1 <= rounds <= 20:
            raise SystemExit("[hunt] rounds must be between 1 and 20")
    categories = argv[2] if len(argv) > 2 else None
    return target, rounds, categories


def run_hunt(argv):
    target, rounds, categories = parse_target(argv)
    prepare_target(target)

    command = [_venv_python(), "dispatch.py", target, str(rounds)]
    if categories:
        command.append(categories)

    _say("starting: dispatch.py %s" % " ".join(command[2:]))
    code = subprocess.call(command, cwd=ROOT)
    print()
    print("  results: %s" % os.path.join(ROOT, "state", "runs"))
    print("  view:    python3 hunt.py --web")
    return code


def show_tools():
    _project()
    import toolbox

    summary = toolbox.summary(refresh=True)
    print("%d/%d stage tools installed (%d catalogued)"
          % (summary["installed"], summary["selected_total"],
             summary["catalogued"]))
    if not summary["missing"]:
        return 0
    print()
    for tool in summary["missing"]:
        print("  missing %-12s %-16s %s"
              % (tool["id"], tool["purpose"], tool["install"]))
    print("\n  install them with: python3 hunt.py --install-tools")
    return 0


def install_tools():
    """Lay the catalog down on a Linux host. Needs sudo, takes a while."""
    if os.name == "nt":
        raise SystemExit("[hunt] the catalog installers are Linux-only; "
                         "use Docker on Windows")

    go_bin = "/usr/local/go/bin/go"
    if not os.path.isfile(go_bin):
        _say("installing the Go toolchain")
        version = subprocess.check_output(
            ["curl", "-s", "--max-time", "20", "https://go.dev/VERSION?m=text"]
        ).decode().split()[0]
        tarball = "%s.linux-amd64.tar.gz" % version
        subprocess.check_call(["curl", "-fsSL", "--retry", "3", "-O",
                               "https://go.dev/dl/%s" % tarball], cwd="/tmp")
        subprocess.check_call(["sudo", "rm", "-rf", "/usr/local/go"])
        subprocess.check_call(["sudo", "tar", "-C", "/usr/local", "-xzf",
                               tarball], cwd="/tmp")
        os.remove(os.path.join("/tmp", tarball))

    path = "/usr/local/go/bin:" + os.environ.get("PATH", "/usr/bin:/bin")
    stages = ("install-apt-tools.sh", "install-go-tools.sh",
              "install-python-tools.sh", "install-git-tools.sh",
              "install-release-tools.sh")
    for stage in stages:
        script = os.path.join(ROOT, "tools", stage)
        if not os.path.isfile(script):
            _say("skipping %s (not found)" % stage)
            continue
        _say("running %s" % stage)
        subprocess.call(["sudo", "env", "PATH=%s" % path,
                         "PIP_BREAK_SYSTEM_PACKAGES=1",
                         "GOBIN=/usr/local/bin", "sh", script], cwd=ROOT)

    if os.path.isdir("/out/bin"):
        names = [os.path.join("/out/bin", n) for n in os.listdir("/out/bin")]
        if names:
            subprocess.call(["sudo", "install", "-m", "0755"] + names +
                            ["/usr/local/bin/"])
    return show_tools()


def main(argv):
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(__doc__.strip())
        return 0

    if not _in_project_venv():
        _relaunch_in_venv(argv)

    command = argv[0]
    if command == "--web":
        env = dict(os.environ)
        env.setdefault("HUNT_HOST", "127.0.0.1")
        env.setdefault("HUNT_PORT", "8777")
        return subprocess.call([_venv_python(), "server.py"], cwd=ROOT, env=env)
    if command == "--tools":
        return show_tools()
    if command == "--install-tools":
        return install_tools()
    if command == "--stop":
        common, _ = _project()
        state = common.request_stop("cli")
        _say("stop requested: %s" % (state["reason"] or "cli"))
        return 0

    return run_hunt(argv)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
