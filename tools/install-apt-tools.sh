#!/bin/sh
# System packages + language runtimes the catalog needs at runtime.
# Runs as root in the final image. Keep this list in sync with the "install"
# column in toolbox.py.
set -u
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y --no-install-recommends \
    ca-certificates git curl wget jq unzip tar \
    make gcc g++ \
    libpcap-dev libssl-dev libcurl4-openssl-dev \
    libxml2-dev libxslt1-dev zlib1g-dev \
    ruby ruby-dev perl dnsutils
rm -rf /var/lib/apt/lists/*

printf '==> wpscan (ruby gem)\n'
if gem install wpscan --no-document; then
    echo 'OK   wpscan'
else
    echo 'FAIL wpscan (gem install)'
fi
