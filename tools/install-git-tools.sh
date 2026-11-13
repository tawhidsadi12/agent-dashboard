#!/bin/sh
# Tools that are used from a git checkout. Each one gets a small wrapper in
# /usr/local/bin so it behaves like a normal command and is detected by
# shutil.which() in toolbox.py.
set -u

ok=0
fail=0

clone() {
    name=$1
    url=$2
    dir=/opt/$name
    printf '==> clone %s\n' "$name"
    if [ -d "$dir/.git" ]; then
        printf 'OK   %s (already present)\n' "$name"
        ok=$((ok + 1))
    elif git clone --depth 1 "$url" "$dir"; then
        printf 'OK   %s\n' "$name"
        ok=$((ok + 1))
    else
        printf 'FAIL %s (%s)\n' "$name" "$url"
        fail=$((fail + 1))
    fi
}

mkbin() {
    name=$1
    shift
    target=""
    for a in "$@"; do target=$a; done
    if [ -n "$target" ] && [ ! -e "$target" ]; then
        printf 'SKIP %s (%s not present)\n' "$name" "$target"
        return 0
    fi
    printf '#!/bin/sh\nexec %s "$@"\n' "$*" > "/usr/local/bin/$name"
    chmod 0755 "/usr/local/bin/$name"
}

clone XSStrike     https://github.com/s0md3v/XSStrike
clone SecretFinder https://github.com/m4ll0k/SecretFinder
clone graphql-cop  https://github.com/dolevf/graphql-cop
clone LinkFinder   https://github.com/GerbenJavado/LinkFinder
clone jwt_tool     https://github.com/ticarpi/jwt_tool
clone SSRFmap      https://github.com/swisskyrepo/SSRFmap
clone Corsy        https://github.com/s0md3v/Corsy
clone Gopherus     https://github.com/tarunkant/Gopherus
clone smuggler     https://github.com/defparam/smuggler
clone h2cSmuggler  https://github.com/BishopFox/h2cSmuggler
clone commix       https://github.com/commixproject/commix
clone NoSQLMap     https://github.com/codingo/NoSQLMap
clone nikto        https://github.com/sullo/nikto
clone reconftw     https://github.com/six2dez/reconftw
clone testssl      https://github.com/testssl/testssl.sh

mkbin xsstrike     python3 /opt/XSStrike/xsstrike.py
mkbin secretfinder python3 /opt/SecretFinder/SecretFinder.py
mkbin linkfinder   python3 /opt/LinkFinder/linkfinder.py
mkbin jwt_tool     python3 /opt/jwt_tool/jwt_tool.py
mkbin ssrfmap      python3 /opt/SSRFmap/ssrfmap.py
mkbin corsy        python3 /opt/Corsy/corsy.py
mkbin gopherus     python3 /opt/Gopherus/gopherus.py
mkbin smuggler     python3 /opt/smuggler/smuggler.py
mkbin h2csmuggler  python3 /opt/h2cSmuggler/h2csmuggler.py
mkbin commix       python3 /opt/commix/commix.py
mkbin nosqlmap     python3 /opt/NoSQLMap/nosqlmap.py
mkbin nikto        perl /opt/nikto/program/nikto.pl
mkbin reconftw     bash /opt/reconftw/reconftw.sh
mkbin testssl.sh   bash /opt/testssl/testssl.sh

# graphql-cop ships no packaging metadata, so it gets its own venv instead of
# being installed into the shared interpreter (its requirements pin old
# versions of common libraries).
if [ -d /opt/graphql-cop ]; then
    printf '==> graphql-cop venv\n'
    if python -m venv /opt/graphql-cop/.venv \
       && /opt/graphql-cop/.venv/bin/pip install -q --no-cache-dir \
            -r /opt/graphql-cop/requirements.txt; then
        printf 'OK   graphql-cop deps\n'
        ok=$((ok + 1))
    else
        printf 'FAIL graphql-cop deps\n'
        fail=$((fail + 1))
    fi
fi
mkbin graphql-cop  /opt/graphql-cop/.venv/bin/python /opt/graphql-cop/graphql-cop.py

# Extra Python deps for the cloned tools (some ship no requirements file).
python -m pip install --no-cache-dir requests lxml jsbeautifier pymongo termcolor pycryptodomex
for req in /opt/XSStrike/requirements.txt /opt/SSRFmap/requirements.txt \
           /opt/NoSQLMap/requirements.txt /opt/LinkFinder/requirements.txt \
           /opt/jwt_tool/requirements.txt; do
    [ -f "$req" ] && python -m pip install --no-cache-dir -r "$req" || true
done

# --- massdns is C, built from source ---------------------------------------
printf '==> build massdns\n'
if [ -d /opt/massdns/.git ] || git clone --depth 1 https://github.com/blechschmidt/massdns /opt/massdns; then
    if make -C /opt/massdns >/tmp/massdns-build.log 2>&1; then
        ln -sf /opt/massdns/bin/massdns /usr/local/bin/massdns
        printf 'OK   massdns\n'
        ok=$((ok + 1))
    else
        printf 'FAIL massdns (build)\n'
        sed -n '1,5p' /tmp/massdns-build.log
        fail=$((fail + 1))
    fi
fi

# --- wordlists -------------------------------------------------------------
# SecLists is huge; a sparse checkout of the parts the catalog actually uses
# keeps the image sane while still giving ffuf/gobuster real files.
printf '==> clone SecLists (sparse)\n'
if [ -d /opt/SecLists/.git ] || \
   git clone --depth 1 --filter=blob:none --sparse \
       https://github.com/danielmiessler/SecLists /opt/SecLists; then
    git -C /opt/SecLists sparse-checkout set \
        Discovery/Web-Content Discovery/DNS Passwords/Common-Credentials >/dev/null 2>&1 || true
    printf 'OK   SecLists\n'
    ok=$((ok + 1))
else
    printf 'FAIL SecLists\n'
    fail=$((fail + 1))
fi

printf '==> clone OneListForAll\n'
if [ -d /opt/OneListForAll/.git ] || \
   git clone --depth 1 https://github.com/six2dez/OneListForAll /opt/OneListForAll; then
    printf 'OK   OneListForAll\n'
    ok=$((ok + 1))
else
    printf 'FAIL OneListForAll\n'
    fail=$((fail + 1))
fi

printf '\nCheckout tools: %d ok, %d failed\n' "$ok" "$fail"
