#!/bin/sh
# Build-time installer for catalog tools that ship as GitHub release binaries.
#
# Runs in the `reltools` stage. Deliberately avoids api.github.com: the
# unauthenticated API allows only 60 requests per hour, which is easily
# exhausted and used to leave this stage with zero binaries. Instead it follows
# the `releases/latest` redirect to find the tag, then reads the public
# `expanded_assets` HTML fragment to list asset names. Those are plain web
# requests with no quota. Failures are reported and skipped; the Tools tab
# reflects what actually landed.
set -u

OUT=/out/bin
mkdir -p "$OUT"

latest_tag() {
    curl -sSI "https://github.com/$1/releases/latest" \
        | tr -d '\r' \
        | awk 'tolower($1) == "location:" {print $2}' \
        | sed 's#.*/tag/##'
}

asset_url() {
    # $1 = owner/repo, $2 = extended regex matching the asset name
    local repo=$1 regex=$2 tag url
    tag=$(latest_tag "$repo")
    if [ -z "$tag" ] || [ "$tag" = "https://github.com/$repo/releases" ]; then
        return 1
    fi
    url=$(curl -fsSL "https://github.com/$repo/releases/expanded_assets/$tag" 2>/dev/null \
          | grep -oE 'href="[^"]*/releases/download/[^"]+"' \
          | sed 's/^href="//; s/"$//' \
          | grep -E "$regex" \
          | head -n1)
    [ -n "$url" ] || return 1
    case "$url" in
        http*) printf '%s' "$url" ;;
        *)     printf 'https://github.com%s' "$url" ;;
    esac
}

pick() {
    # $1 = extracted dir, $2 = preferred file name
    local f
    f=$(find "$1" -type f -name "$2" 2>/dev/null | head -n1)
    if [ -z "$f" ]; then
        f=$(find "$1" -type f \
            ! -iname '*.md' ! -iname 'license*' ! -iname '*.txt' \
            ! -iname '*.json' ! -iname '*.yaml' ! -iname '*.yml' 2>/dev/null | head -n1)
    fi
    printf '%s' "$f"
}

fetch() {
    # $1 = owner/repo, $2 = asset regex, $3 = binary name to install
    local repo=$1 regex=$2 dest=$3
    local url tmp dir bin
    printf '==> %s (%s)\n' "$dest" "$repo"

    url=$(asset_url "$repo" "$regex") || {
        echo "FAIL $dest (no asset matching $regex)"
        return 1
    }

    tmp="/tmp/asset-$(basename "$url")"
    curl -fsSL "$url" -o "$tmp" || { echo "FAIL $dest (download)"; return 1; }

    dir="/tmp/x-$dest"
    rm -rf "$dir"; mkdir -p "$dir"
    case "$tmp" in
        *.zip)
            unzip -o -q "$tmp" -d "$dir" || { echo "FAIL $dest (unzip)"; return 1; }
            bin=$(pick "$dir" "$dest")
            ;;
        *.tar.gz|*.tgz)
            tar -xzf "$tmp" -C "$dir" || { echo "FAIL $dest (untar)"; return 1; }
            bin=$(pick "$dir" "$dest")
            ;;
        *.gz)
            gunzip -c "$tmp" > "$dir/$dest" || { echo "FAIL $dest (gunzip)"; return 1; }
            bin="$dir/$dest"
            ;;
        *)
            bin="$tmp"
            ;;
    esac

    if [ -z "${bin:-}" ] || [ ! -f "$bin" ]; then
        echo "FAIL $dest (no binary inside archive)"
        return 1
    fi
    install -m 0755 "$bin" "$OUT/$dest" && echo "OK   $dest"
}

# --- catalog tools that are distributed as binaries -------------------------
fetch Findomain/Findomain      'findomain-linux\.zip$'                  findomain
fetch assetnote/kiterunner     '_linux_amd64\.tar\.gz$'                 kr
fetch j3ssie/osmedeus          'osmedeus_.*_linux_amd64\.tar\.gz$'      osmedeus
fetch epi052/feroxbuster       'x86_64-linux-feroxbuster\.tar\.gz$'     feroxbuster
fetch Sh1Yo/x8                 'x86_64-linux-x8\.gz$'                  x8
fetch michenriksen/aquatone    'aquatone_linux_amd64_.*\.zip$'          aquatone
fetch praetorian-inc/noseyparker 'x86_64-unknown-linux-gnu\.tar\.gz$'   noseyparker
fetch projectdiscovery/cloudlist 'cloudlist_.*_linux_amd64\.zip$'        cloudlist

# trufflehog builds with Go 1.26+, which is newer than the builder image, so
# the release binary is the reliable path. Install it only if absent.
[ -x "$OUT/trufflehog" ] || \
    fetch trufflesecurity/trufflehog 'trufflehog_.*_linux_amd64\.tar\.gz$' trufflehog

# gowitness ships release binaries too; used only if the Go build failed.
[ -x "$OUT/gowitness" ] || \
    fetch sensepost/gowitness 'gowitness-.*-linux-amd64$' gowitness

printf '\nRelease binaries in %s:\n' "$OUT"
ls -1 "$OUT" 2>/dev/null | sed 's/^/  /'
