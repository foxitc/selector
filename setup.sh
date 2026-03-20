#!/usr/bin/env bash
# ================================================================
# TEST PLAYER — Server Setup & Deploy
# Run as root on 51.75.142.7
# Usage: bash setup.sh
# ================================================================

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

SERVER_IP="51.75.142.7"
APP_DIR="/var/www/test-player"
ENV_FILE="/etc/test-player/.env"
DB_NAME="test_player"
DB_USER="test_player"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log()  { echo -e "${GREEN}[tp]${NC} $*"; }
warn() { echo -e "${YELLOW}[tp]${NC} $*"; }
err()  { echo -e "${RED}[tp]${NC} $*"; exit 1; }

[[ $EUID -ne 0 ]] && err "Run as root: sudo bash setup.sh"

log "Test Player — server setup starting on $SERVER_IP"

# ----------------------------------------------------------------
# 1. System packages
# ----------------------------------------------------------------
log "Installing system packages..."
apt-get update -qq
apt-get install -y -qq curl wget ufw nginx postgresql postgresql-contrib certbot python3-certbot-nginx

# ----------------------------------------------------------------
# 2. Node.js 20
# ----------------------------------------------------------------
if ! command -v node &>/dev/null || [[ $(node --version | cut -c2- | cut -d. -f1) -lt 20 ]]; then
    log "Installing Node.js 20 LTS..."
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash - 2>/dev/null
    apt-get install -y -qq nodejs
fi
log "Node $(node --version)"

# ----------------------------------------------------------------
# 3. System user
# ----------------------------------------------------------------
id tp &>/dev/null || useradd --system --shell /usr/sbin/nologin --home-dir "$APP_DIR" tp
log "System user: tp"

# ----------------------------------------------------------------
# 4. PostgreSQL
# ----------------------------------------------------------------
log "Setting up PostgreSQL..."
systemctl enable --now postgresql

DB_PASSWORD=$(openssl rand -hex 24)

sudo -u postgres psql << SQLEOF 2>/dev/null || true
DO \$\$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '$DB_USER') THEN
    CREATE ROLE $DB_USER WITH LOGIN PASSWORD '$DB_PASSWORD';
  END IF;
END \$\$;
SQLEOF

sudo -u postgres psql -c \
    "SELECT 'CREATE DATABASE $DB_NAME OWNER $DB_USER' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname='$DB_NAME')\gexec" 2>/dev/null || true

sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;" 2>/dev/null || true

# Allow test_player user to create extensions
sudo -u postgres psql -d "$DB_NAME" -c "GRANT ALL ON SCHEMA public TO $DB_USER;" 2>/dev/null || true
sudo -u postgres psql -c "ALTER USER $DB_USER CREATEDB;" 2>/dev/null || true

log "Database: $DB_NAME ready"

# ----------------------------------------------------------------
# 5. Directories
# ----------------------------------------------------------------
mkdir -p "$APP_DIR"/{api/dist,app,logs}
mkdir -p /etc/test-player
log "Directories created"

# ----------------------------------------------------------------
# 6. Environment file (generate once — never overwrite)
# ----------------------------------------------------------------
if [[ ! -f "$ENV_FILE" ]]; then
    JWT_SECRET=$(openssl rand -hex 32)
    ENC_KEY=$(openssl rand -hex 32)
    ADMIN_PASS=$(openssl rand -base64 16 | tr -d '=/+' | head -c 16)

    cat > "$ENV_FILE" << ENVEOF
NODE_ENV=production
PORT=3100

DB_HOST=localhost
DB_PORT=5432
DB_NAME=$DB_NAME
DB_USER=$DB_USER
DB_PASSWORD=$DB_PASSWORD
DB_SSL=false

JWT_SECRET=$JWT_SECRET
ENCRYPTION_KEY=$ENC_KEY

ALLOWED_ORIGINS=http://$SERVER_IP,http://$SERVER_IP/app,https://testplayer.catandwickets.com

ADMIN_EMAIL=admin@catandwickets.com
ADMIN_PASSWORD=$ADMIN_PASS

# Uncomment to enable AI coaching narratives:
# ANTHROPIC_API_KEY=sk-ant-...
ENVEOF

    chmod 600 "$ENV_FILE"
    chown root:root "$ENV_FILE"

    echo ""
    warn "════════════════════════════════════════════════"
    warn "  CREDENTIALS — SAVE THESE NOW, SHOWN ONCE"
    warn ""
    warn "  Admin email:    admin@catandwickets.com"
    warn "  Admin password: $ADMIN_PASS"
    warn "  DB password:    $DB_PASSWORD"
    warn ""
    warn "  Full env: $ENV_FILE"
    warn "════════════════════════════════════════════════"
    echo ""
else
    log "Env file exists — skipping (delete $ENV_FILE to regenerate)"
fi

# ----------------------------------------------------------------
# 7. systemd service
# ----------------------------------------------------------------
cat > /etc/systemd/system/test-player.service << 'SVCEOF'
[Unit]
Description=Test Player API — Cat & Wickets
After=network.target postgresql.service
Requires=postgresql.service

[Service]
Type=simple
User=tp
Group=tp
WorkingDirectory=/var/www/test-player/api
EnvironmentFile=/etc/test-player/.env
ExecStart=/usr/bin/node dist/server.js
Restart=on-failure
RestartSec=5s
StartLimitInterval=60s
StartLimitBurst=3
NoNewPrivileges=true
PrivateTmp=true
StandardOutput=journal
StandardError=journal
SyslogIdentifier=test-player

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable test-player
log "systemd service: test-player"

# ----------------------------------------------------------------
# 8. Nginx
# ----------------------------------------------------------------
cat > /etc/nginx/sites-available/test-player << NGINXEOF
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name $SERVER_IP testplayer.catandwickets.com _;

    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;

    gzip on;
    gzip_types text/plain text/css application/json application/javascript image/svg+xml;
    gzip_min_length 1024;

    # API
    location /api/ {
        proxy_pass         http://127.0.0.1:3100;
        proxy_http_version 1.1;
        proxy_set_header   Host              \$host;
        proxy_set_header   X-Real-IP         \$remote_addr;
        proxy_set_header   X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_buffering    off;
        proxy_read_timeout 120s;
        proxy_connect_timeout 10s;
    }

    # Health check
    location = /health {
        proxy_pass http://127.0.0.1:3100/health;
        access_log off;
    }

    # TV display (no auth, sub-path)
    location /display/ {
        alias /var/www/test-player/app/;
        try_files \$uri \$uri/ /display/index.html;
        location ~* \.(js|css|woff2|svg|png|ico)$ {
            expires 1y;
            add_header Cache-Control "public, immutable";
            access_log off;
        }
    }

    # Admin app (everything else)
    location / {
        root /var/www/test-player/app;
        try_files \$uri \$uri/ /index.html;
        location ~* \.(js|css|woff2|svg|png|ico)$ {
            expires 1y;
            add_header Cache-Control "public, immutable";
            access_log off;
        }
    }

    client_max_body_size 5m;
    access_log /var/log/nginx/test-player.log combined;
    error_log  /var/log/nginx/test-player-error.log warn;
}
NGINXEOF

ln -sf /etc/nginx/sites-available/test-player /etc/nginx/sites-enabled/test-player
rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true
nginx -t && systemctl enable --now nginx
log "Nginx configured"

# ----------------------------------------------------------------
# 9. Firewall
# ----------------------------------------------------------------
ufw allow ssh    2>/dev/null || true
ufw allow 80/tcp 2>/dev/null || true
ufw allow 443/tcp 2>/dev/null || true
ufw --force enable 2>/dev/null || true
log "Firewall configured"

chown -R tp:tp "$APP_DIR" 2>/dev/null || true

log ""
log "Server setup complete. Now run: bash deploy.sh"
