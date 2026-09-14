# The Firmbatch control-plane image (Milestone 3.3b container foundation, ADR 0011).
#
# One image, deployed by immutable digest to every ECS service and one-off task. This file
# builds it; nothing in Milestone 3.3b runs it in AWS or pushes it anywhere.
#
# What is and is not inside, stated plainly:
#   * the web/API entry point, `python3 -m firmbatch.control_plane.api`, which exists today;
#   * `python3 -m firmbatch.control_plane.migrate`, which exists today;
#   * the compiled portal under /app/firmbatch/portal/dist. Serving it from the web/API process
#     is M3.3c's work; today's API does not serve it;
#   * NOT the identity broker, the database bootstrap command or the identity-binding command.
#     They do not exist until M3.3c.
#
# No credential, no valued environment file, no package-manager cache, no build toolchain and no
# test code reach the final stage, which runs as an unprivileged numeric user. Base images are
# pinned by digest; dependencies come only from the committed locks.

# ------------------------------------------------------------------ portal build: Node 24
FROM node:24.19.0-bookworm-slim@sha256:a9f5f7c91a432850b2a8a7797adf5eadb6c733ceed61167806cee7ea7fbc29df AS portal

ENV NPM_CONFIG_AUDIT=false \
    NPM_CONFIG_FUND=false \
    NPM_CONFIG_UPDATE_NOTIFIER=false

WORKDIR /build/portal
COPY portal/package.json portal/package-lock.json portal/.npmrc ./
RUN npm ci
COPY portal/index.html portal/tsconfig.json portal/vite.config.ts ./
COPY portal/scripts ./scripts
COPY portal/src ./src
RUN node scripts/require-node.mjs && npm run build

# ------------------------------------------------------------------ Python runtime dependencies
FROM python:3.11.16-slim-bookworm@sha256:528257d48c1da0dcecc2e725d1ae34498d60c965f1241e39cd6a85a8859bdf84 AS python-dependencies

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

COPY requirements-v1-lock.txt /tmp/requirements-v1-lock.txt
RUN python -m venv /opt/firmbatch-venv \
 && /opt/firmbatch-venv/bin/pip install --require-hashes --no-deps --only-binary=:all: \
      -r /tmp/requirements-v1-lock.txt

# ------------------------------------------------------------------ runtime
FROM python:3.11.16-slim-bookworm@sha256:528257d48c1da0dcecc2e725d1ae34498d60c965f1241e39cd6a85a8859bdf84 AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/opt/firmbatch-venv/bin:/usr/local/bin:/usr/bin:/bin

RUN groupadd --system --gid 10001 firmbatch \
 && useradd --system --uid 10001 --gid 10001 --home-dir /nonexistent --no-create-home \
      --shell /usr/sbin/nologin firmbatch

WORKDIR /app
COPY --from=python-dependencies /opt/firmbatch-venv /opt/firmbatch-venv
COPY __init__.py /app/firmbatch/__init__.py
COPY control_plane /app/firmbatch/control_plane
COPY --from=portal /build/portal/dist /app/firmbatch/portal/dist

USER 10001:10001
EXPOSE 8080

CMD ["python3", "-m", "firmbatch.control_plane.api", "--host", "0.0.0.0", "--port", "8080"]
