#!/bin/sh
# Build-time installer for the Go-based tools in toolbox.py.
#
# Runs inside the `gotools` stage (golang image) as root, writes every binary
# to /out/bin, which the final image copies into /usr/local/bin. A failure is
# reported and skipped instead of failing the whole build: one upstream module
# path moving must not make the dashboard unbuildable. The Tools tab shows
# exactly what actually landed.
set -u

OUT=${GOBIN:-/out/bin}
mkdir -p "$OUT"

ok=0
fail=0
failed=""

install_go() {
    name=$1
    pkg=$2
    cgo=${3:-0}
    printf '==> go install %s\n' "$name"
    if CGO_ENABLED="$cgo" GOBIN="$OUT" go install "$pkg" 2>"/tmp/go-$name.err"; then
        ok=$((ok + 1))
        printf 'OK   %s\n' "$name"
    else
        fail=$((fail + 1))
        failed="$failed $name"
        printf 'FAIL %s (%s)\n' "$name" "$pkg"
        sed -n '1,5p' "/tmp/go-$name.err" | sed 's/^/     /'
    fi
}

# --- subdomains -------------------------------------------------------------
install_go subfinder    github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
install_go amass        github.com/owasp-amass/amass/v4/cmd/amass@master
install_go assetfinder  github.com/tomnomnom/assetfinder@latest
install_go chaos        github.com/projectdiscovery/chaos-client/cmd/chaos@latest
install_go gotator      github.com/Josue87/gotator@latest
install_go alterx       github.com/projectdiscovery/alterx/cmd/alterx@latest

# --- dns / probing / http ---------------------------------------------------
install_go dnsx         github.com/projectdiscovery/dnsx/cmd/dnsx@latest
install_go puredns      github.com/d3mondev/puredns/v2@latest
install_go tlsx         github.com/projectdiscovery/tlsx/cmd/tlsx@latest
install_go httpx        github.com/projectdiscovery/httpx/cmd/httpx@latest
install_go httprobe     github.com/tomnomnom/httprobe@latest
install_go cdncheck     github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest
install_go gowitness    github.com/sensepost/gowitness@latest

# --- crawling / urls / content ---------------------------------------------
install_go katana       github.com/projectdiscovery/katana/cmd/katana@latest
install_go hakrawler    github.com/hakluke/hakrawler@latest
install_go gospider     github.com/jaeles-project/gospider@latest
install_go gau          github.com/lc/gau/v2/cmd/gau@latest
install_go waybackurls  github.com/tomnomnom/waybackurls@latest
install_go ffuf         github.com/ffuf/ffuf/v2@latest
install_go gobuster     github.com/OJ/gobuster/v3@latest

# --- js / secrets -----------------------------------------------------------
install_go jsluice      github.com/BishopFox/jsluice/cmd/jsluice@latest 1
install_go subjs        github.com/lc/subjs@latest
install_go gitleaks     github.com/zricethezav/gitleaks/v8@latest

# --- cloud ------------------------------------------------------------------
# cloudlist needs a newer Go toolchain than the builder image, so it is
# installed from its release binary by install-release-tools.sh instead.

# --- vuln scanning / xss ----------------------------------------------------
install_go nuclei       github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
install_go jaeles       github.com/jaeles-project/jaeles@latest
install_go dalfox       github.com/hahwul/dalfox/v2@latest
install_go gf           github.com/tomnomnom/gf@latest

# --- ssrf / takeover / smuggling -------------------------------------------
install_go interactsh   github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
install_go subzy        github.com/PentestPad/subzy@latest
install_go subjack      github.com/haccer/subjack@latest

# --- utilities --------------------------------------------------------------
install_go unfurl       github.com/tomnomnom/unfurl@latest
install_go anew         github.com/tomnomnom/anew@latest
install_go qsreplace    github.com/tomnomnom/qsreplace@latest
install_go notify       github.com/projectdiscovery/notify/cmd/notify@latest

printf '\nGo tools: %d installed, %d failed%s\n' "$ok" "$fail" "${failed:+ (failed:$failed)}"
printf '%d %d\n' "$ok" "$fail" > /tmp/go-tool-counts
