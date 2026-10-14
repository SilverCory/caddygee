#!/bin/sh
set -e

CADDYFILE_PATH="${CADDYFILE_PATH:-/etc/caddy/Caddyfile}"
CADDY_ADMIN="${CADDY_ADMIN:-localhost:2019}"
DEPLOY_PORT="${DEPLOY_PORT:-9090}"

# caddygee-server handles cold-start GCS fetch, writes the Caddyfile,
# then starts listening for /deploy requests.
# Caddy is started separately once the Caddyfile is ready.

echo "Starting caddygee-server (deploy endpoint on :${DEPLOY_PORT})..."
caddygee-server &
SERVER_PID=$!

# Wait for the Caddyfile to be written by caddygee-server (up to 30s).
i=0
while [ ! -f "$CADDYFILE_PATH" ] && [ $i -lt 30 ]; do
  sleep 1
  i=$((i + 1))
done

if [ ! -f "$CADDYFILE_PATH" ]; then
  echo "ERROR: Caddyfile not ready after 30s, aborting"
  exit 1
fi

echo "Starting Caddy..."
exec caddy run --config "$CADDYFILE_PATH" --adapter caddyfile
