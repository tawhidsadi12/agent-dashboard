#!/bin/sh
# Python tools, installed with pipx so each keeps its own dependencies.
# All of them end up in /usr/local/bin via PIPX_BIN_DIR.
set -u

export PIPX_HOME=/opt/pipx
export PIPX_BIN_DIR=/usr/local/bin

python -m pip install --no-cache-dir --upgrade pip pipx

ok=0
fail=0
failed=""

pipx_install() {
    name=$1
    shift
    printf '==> pipx %s\n' "$name"
    if pipx install --global "$@" 2>"/tmp/pipx-$name.err"; then
        ok=$((ok + 1))
        printf 'OK   %s\n' "$name"
    else
        fail=$((fail + 1))
        failed="$failed $name"
        printf 'FAIL %s\n' "$name"
        sed -n '1,5p' "/tmp/pipx-$name.err" | sed 's/^/     /'
    fi
}

pipx_install arjun       arjun
pipx_install dirsearch   dirsearch
pipx_install waymore     waymore
pipx_install sqlmap      sqlmap
pipx_install ghauri      'git+https://github.com/r0oth3x49/ghauri'
pipx_install wafw00f     wafw00f
pipx_install paramspider 'git+https://github.com/devanshbatham/ParamSpider'
# graphql-cop ships no installable package; install-git-tools.sh clones it
# into a dedicated venv and exposes a wrapper.
pipx_install mitmproxy   mitmproxy

# linkfinder, jwt_tool and h2csmuggler are run from a git checkout; see
# install-git-tools.sh. They ship no installable Python package entry point.

# Shared runtime deps for the cloned script tools below.
python -m pip install --no-cache-dir requests lxml jsbeautifier pymongo

printf '\nPython tools: %d installed, %d failed%s\n' "$ok" "$fail" "${failed:+ (failed:$failed)}"
