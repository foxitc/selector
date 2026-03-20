#!/usr/bin/env bash
# ================================================================
# TEST PLAYER — Deploy
# Run from your LOCAL machine in the test-player-deploy folder.
# Usage: bash deploy.sh [user@host]
# Default: root@51.75.142.7
# ================================================================

set -euo pipefail

SERVER="${1:-root@51.75.142.7}"
APP_DIR="/var/www/test-player"
ENV_FILE="/etc/test-player/.env"

GREEN='\033[0;32m'; BLUE='\033[0;34m'; RED='\033[0;31m'; NC='\033[0m'
log()  { echo -e "${GREEN}[deploy]${NC} $*"; }
step() { echo -e "${BLUE}[deploy]${NC} $*"; }
err()  { echo -e "${RED}[deploy]${NC} $*"; exit 1; }

[[ -f "tp-api.tar.gz" ]] || err "Run from the test-player-deploy directory (tp-api.tar.gz not found)"

echo ""
log "Deploying Test Player to $SERVER"
echo ""

# ----------------------------------------------------------------
# Upload API
# ----------------------------------------------------------------
step "Uploading API..."
scp tp-api.tar.gz "$SERVER:/tmp/tp-api.tar.gz"

ssh "$SERVER" bash << 'REMOTE'
set -e
cd /var/www/test-player/api
tar -xzf /tmp/tp-api.tar.gz
echo "[remote] API files extracted"
REMOTE

# ----------------------------------------------------------------
# Install production dependencies on server
# ----------------------------------------------------------------
step "Installing API dependencies on server..."
ssh "$SERVER" bash << 'REMOTE'
set -e
cd /var/www/test-player/api
npm install --omit=dev --silent 2>&1 | tail -3
chown -R tp:tp /var/www/test-player
echo "[remote] Dependencies installed"
REMOTE

# ----------------------------------------------------------------
# Upload App
# ----------------------------------------------------------------
step "Uploading app..."
scp tp-app.tar.gz "$SERVER:/tmp/tp-app.tar.gz"

ssh "$SERVER" bash << 'REMOTE'
set -e
rm -rf /var/www/test-player/app/*
tar -xzf /tmp/tp-app.tar.gz -C /var/www/test-player/app/ --strip-components=1
chown -R tp:tp /var/www/test-player/app
echo "[remote] App files extracted"
REMOTE

# ----------------------------------------------------------------
# Run migrations
# ----------------------------------------------------------------
step "Running database migrations..."
ssh "$SERVER" bash << 'REMOTE'
set -a
source /etc/test-player/.env
set +a
cd /var/www/test-player/api
node dist/db/migrate.js
echo "[remote] Migrations complete"
REMOTE

# ----------------------------------------------------------------
# Run seed (idempotent — skips if already done)
# ----------------------------------------------------------------
step "Seeding database..."
ssh "$SERVER" bash << 'REMOTE'
set -a
source /etc/test-player/.env
set +a
cd /var/www/test-player/api
node dist/db/seed.js 2>&1 || echo "[remote] Seed skipped (already applied)"
REMOTE

# ----------------------------------------------------------------
# Start / restart service
# ----------------------------------------------------------------
step "Starting Test Player service..."
ssh "$SERVER" "systemctl restart test-player"
sleep 4

# ----------------------------------------------------------------
# Health check
# ----------------------------------------------------------------
step "Health check..."
HTTP=$(ssh "$SERVER" "curl -s -o /dev/null -w '%{http_code}' http://localhost:3100/health 2>/dev/null")

if [[ "$HTTP" == "200" ]]; then
    log "API is healthy (HTTP 200)"
else
    echo ""
    echo "Health check returned HTTP $HTTP — checking logs:"
    ssh "$SERVER" "journalctl -u test-player --no-pager -n 40"
    err "Service may not have started — check logs above"
fi

# ----------------------------------------------------------------
# Reload Nginx
# ----------------------------------------------------------------
step "Reloading Nginx..."
ssh "$SERVER" "nginx -t && systemctl reload nginx"

# ----------------------------------------------------------------
# Done
# ----------------------------------------------------------------
echo ""
log "════════════════════════════════════════════════"
log "  Test Player is live!"
log ""
log "  App:     http://51.75.142.7"
log "  API:     http://51.75.142.7/health"
log ""
log "  Login:   admin@catandwickets.com"
log "  Pass:    (shown during setup.sh)"
log ""
log "  To view logs:"
log "  ssh $SERVER 'journalctl -u test-player -f'"
log "════════════════════════════════════════════════"
echo ""
