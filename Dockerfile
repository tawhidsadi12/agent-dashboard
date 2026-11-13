# syntax=docker/dockerfile:1

# =============================================================================
# Hunt Dashboard image.
#
# Three stages:
#   gotools   compiles every Go-based catalog tool into /out/bin
#   reltools  downloads the tools that only ship as GitHub release binaries
#   final     python:3.12-slim + apt/pip/git tool installs + the app itself
#
# Every installer reports failures instead of aborting, so one upstream module
# moving cannot make the image unbuildable. What actually landed is visible in
# the dashboard's Tools tab (it probes PATH at runtime).
# =============================================================================

FROM golang:1.25-bookworm AS gotools

ENV CGO_ENABLED=0 \
    GOTOOLCHAIN=auto \
    GOFLAGS=-trimpath \
    GOBIN=/out/bin

RUN mkdir -p /out/bin
COPY tools/install-go-tools.sh /usr/local/bin/install-go-tools.sh
RUN chmod 0755 /usr/local/bin/install-go-tools.sh \
 && /usr/local/bin/install-go-tools.sh

# -----------------------------------------------------------------------------

FROM debian:bookworm-slim AS reltools

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl jq unzip tar gzip \
 && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /out/bin
COPY tools/install-release-tools.sh /usr/local/bin/install-release-tools.sh
RUN chmod 0755 /usr/local/bin/install-release-tools.sh \
 && /usr/local/bin/install-release-tools.sh

# -----------------------------------------------------------------------------

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HUNT_DATA_DIR=/data \
    HUNT_HOST=0.0.0.0 \
    HUNT_PORT=8777 \
    PIPX_HOME=/opt/pipx \
    PIPX_BIN_DIR=/usr/local/bin \
    PATH=/usr/local/bin:$PATH

WORKDIR /app

# Tools first: this is by far the slowest layer, and it only rebuilds when one
# of the installer scripts changes.
COPY tools/install-apt-tools.sh tools/install-python-tools.sh tools/install-git-tools.sh /usr/local/bin/
RUN chmod 0755 /usr/local/bin/install-apt-tools.sh \
              /usr/local/bin/install-python-tools.sh \
              /usr/local/bin/install-git-tools.sh \
 && /usr/local/bin/install-apt-tools.sh \
 && /usr/local/bin/install-python-tools.sh \
 && /usr/local/bin/install-git-tools.sh

# Compiled Go binaries and release binaries.
COPY --from=gotools /out/bin/ /usr/local/bin/
COPY --from=reltools /out/bin/ /usr/local/bin/

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY hunt.py common.py scope_guard.py toolbox.py checks.py worker.py dispatch.py server.py selftest.py surface.py methods.py planning.py logs.py ./
COPY static ./static
# The installer scripts are documentation as much as build input; selftest
# also checks that every stage default is named by one of them.
COPY tools ./tools

# Build-time verification: syntax of every module, then the scope/diff/tool
# logic. A broken image cannot be produced — this is the equivalent of the
# local `python selftest.py` step.
RUN python -m compileall -q hunt.py common.py scope_guard.py toolbox.py checks.py worker.py dispatch.py server.py selftest.py surface.py methods.py planning.py logs.py \
 && python selftest.py \
 && python -c "import common, scope_guard, toolbox, checks, dispatch, worker, server, surface, methods, planning, logs; print('imports ok')"

# Non-root. The named volume inherits this ownership on first use.
RUN useradd --create-home --uid 1000 hunter \
 && mkdir -p /data/state /data/logs \
 && chown -R hunter:hunter /data /app
USER hunter

EXPOSE 8777

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8777/api/state', timeout=3)"

CMD ["python", "server.py"]
