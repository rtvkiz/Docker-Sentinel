#!/bin/bash
set -e

# Docker Sentinel Installer
# Usage: curl -sSL https://raw.githubusercontent.com/rtvkiz/docker-sentinel/main/scripts/install.sh | sudo bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

REPO="rtvkiz/docker-sentinel"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/sentinel"
SYSTEMD_DIR="/etc/systemd/system"

echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════╗"
echo "║       Docker Sentinel Installer           ║"
echo "╚═══════════════════════════════════════════╝"
echo -e "${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root (use sudo)${NC}"
    exit 1
fi

# Check for Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: Docker is not installed${NC}"
    exit 1
fi

echo -e "${BLUE}[1/6]${NC} Detecting system..."
ARCH=$(uname -m)
OS=$(uname -s | tr '[:upper:]' '[:lower:]')

case $ARCH in
    x86_64)  ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
    armv7l)  ARCH="arm" ;;
    *)
        echo -e "${YELLOW}Architecture $ARCH not pre-built, will build from source${NC}"
        BUILD_FROM_SOURCE=true
        ;;
esac

echo "  OS: $OS, Arch: $ARCH"

# Download or build
if [ "$BUILD_FROM_SOURCE" = true ] || [ ! -z "$SENTINEL_BUILD_SOURCE" ]; then
    echo -e "${BLUE}[2/6]${NC} Building from source..."

    if ! command -v go &> /dev/null; then
        echo -e "${RED}Error: Go is required to build from source${NC}"
        echo "Install Go from https://golang.org/dl/"
        exit 1
    fi

    TEMP_DIR=$(mktemp -d)
    cd "$TEMP_DIR"
    git clone --depth 1 https://github.com/$REPO.git
    cd docker-sentinel
    go build -o sentinel ./cmd/sentinel
    mv sentinel "$INSTALL_DIR/sentinel"
    cd /
    rm -rf "$TEMP_DIR"
else
    echo -e "${BLUE}[2/6]${NC} Downloading sentinel binary..."

    # Try to get latest release, fallback to building from source
    LATEST_URL="https://github.com/$REPO/releases/latest/download/sentinel-${OS}-${ARCH}"

    if curl -sSL --fail -o /tmp/sentinel "$LATEST_URL" 2>/dev/null; then
        mv /tmp/sentinel "$INSTALL_DIR/sentinel"
    else
        echo -e "${YELLOW}No pre-built binary found, building from source...${NC}"

        if ! command -v go &> /dev/null; then
            echo -e "${RED}Error: Go is required to build from source${NC}"
            echo "Install Go from https://golang.org/dl/"
            exit 1
        fi

        TEMP_DIR=$(mktemp -d)
        cd "$TEMP_DIR"
        git clone --depth 1 https://github.com/$REPO.git
        cd docker-sentinel
        go build -buildvcs=false -o sentinel ./cmd/sentinel
        mv sentinel "$INSTALL_DIR/sentinel"
        cd /
        rm -rf "$TEMP_DIR"
    fi
fi

chmod +x "$INSTALL_DIR/sentinel"
echo -e "  ${GREEN}✓${NC} Installed to $INSTALL_DIR/sentinel"

# Create config directory
echo -e "${BLUE}[3/6]${NC} Setting up configuration..."
mkdir -p "$CONFIG_DIR/policies"
mkdir -p "$CONFIG_DIR/cache"

# Create default config if not exists
if [ ! -f "$CONFIG_DIR/config.yaml" ]; then
    cat > "$CONFIG_DIR/config.yaml" << 'EOF'
version: "1.0"
mode: warn
active_policy: default

global_settings:
  max_risk_score: 50
  require_image_scan: false
  require_non_root: false

image_scanning:
  enabled: true
  scanners:
    - trivy
  max_critical: 0
  max_high: 5
  cache_duration: 24h
EOF
    echo -e "  ${GREEN}✓${NC} Created default config"
fi

# Create default policy if not exists
if [ ! -f "$CONFIG_DIR/policies/default.yaml" ]; then
    cat > "$CONFIG_DIR/policies/default.yaml" << 'EOF'
version: "1.0"
name: default
description: "Default security policy - balanced protection with warnings"
mode: warn

settings:
  max_risk_score: 50
  require_image_scan: false

rules:
  privileged:
    action: block
    message: "Privileged containers are not allowed"

  host_namespaces:
    network:
      action: block
    pid:
      action: block
    ipc:
      action: warn
    uts:
      action: warn

  capabilities:
    blocked:
      - name: SYS_ADMIN
        message: "Grants near-root privileges"
      - name: SYS_PTRACE
      - name: NET_ADMIN
      - name: SYS_MODULE

  mounts:
    blocked:
      - path: "/"
        message: "Host root access denied"
      - path: "/var/run/docker.sock"
        message: "Docker socket access denied"
    warned:
      - path: "/etc"
      - path: "/home"
      - path: "/proc"
      - path: "/sys"

  security_options:
    require_seccomp: false
    require_apparmor: false

  container:
    require_non_root: false
    require_resource_limits: false

  images:
    block_latest_tag: false
    allowed_registries: []
EOF
    echo -e "  ${GREEN}✓${NC} Created default policy"
fi

# Create systemd service
echo -e "${BLUE}[4/6]${NC} Installing systemd service..."
cat > "$SYSTEMD_DIR/docker-sentinel.service" << EOF
[Unit]
Description=Docker Sentinel Authorization Plugin
Documentation=https://github.com/$REPO
After=network.target
Before=docker.service

[Service]
Type=simple
ExecStart=$INSTALL_DIR/sentinel authz start --foreground
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
echo -e "  ${GREEN}✓${NC} Created systemd service"

# Configure Docker
echo -e "${BLUE}[5/6]${NC} Configuring Docker daemon..."
DOCKER_CONFIG="/etc/docker/daemon.json"
PLUGIN_DIR="/etc/docker/plugins"
SOCKET_PATH="/run/docker/plugins/sentinel.sock"

mkdir -p "$PLUGIN_DIR"
mkdir -p "$(dirname $SOCKET_PATH)"

# Create plugin spec
cat > "$PLUGIN_DIR/sentinel.json" << EOF
{
    "Name": "sentinel",
    "Addr": "unix://$SOCKET_PATH"
}
EOF

# Update daemon.json
if [ -f "$DOCKER_CONFIG" ]; then
    # Backup existing config
    cp "$DOCKER_CONFIG" "$DOCKER_CONFIG.backup.$(date +%s)"

    # Check if authorization-plugins already configured
    if grep -q "authorization-plugins" "$DOCKER_CONFIG"; then
        echo -e "  ${YELLOW}!${NC} Docker already has authorization plugins configured"
        echo "  Please manually add 'sentinel' to authorization-plugins in $DOCKER_CONFIG"
    else
        # Add authorization-plugins to existing config
        if command -v jq &> /dev/null; then
            jq '. + {"authorization-plugins": ["sentinel"]}' "$DOCKER_CONFIG" > "$DOCKER_CONFIG.tmp"
            mv "$DOCKER_CONFIG.tmp" "$DOCKER_CONFIG"
            echo -e "  ${GREEN}✓${NC} Updated Docker daemon config"
        else
            echo -e "  ${YELLOW}!${NC} jq not installed, please manually add to $DOCKER_CONFIG:"
            echo '    "authorization-plugins": ["sentinel"]'
        fi
    fi
else
    cat > "$DOCKER_CONFIG" << EOF
{
    "authorization-plugins": ["sentinel"]
}
EOF
    echo -e "  ${GREEN}✓${NC} Created Docker daemon config"
fi

# Start services
echo -e "${BLUE}[6/6]${NC} Starting services..."
systemctl enable docker-sentinel
systemctl start docker-sentinel

echo ""
echo -e "${YELLOW}Restarting Docker daemon...${NC}"
systemctl restart docker

# Wait for services
sleep 2

# Verify
echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║       Installation Complete!              ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════╝${NC}"
echo ""

if systemctl is-active --quiet docker-sentinel; then
    echo -e "  ${GREEN}✓${NC} Sentinel daemon is running"
else
    echo -e "  ${RED}✗${NC} Sentinel daemon failed to start"
    echo "    Check logs: journalctl -u docker-sentinel -f"
fi

if systemctl is-active --quiet docker; then
    echo -e "  ${GREEN}✓${NC} Docker daemon is running"
else
    echo -e "  ${RED}✗${NC} Docker daemon failed to start"
    echo "    Check logs: journalctl -u docker -f"
fi

echo ""
echo -e "${BLUE}Quick Start:${NC}"
echo "  sudo sentinel policy list      # View available policies"
echo "  sudo sentinel policy use strict # Switch to strict policy"
echo "  sudo sentinel authz status     # Check plugin status"
echo ""
echo -e "${BLUE}Test it:${NC}"
echo "  docker run nginx:latest        # Should work"
echo "  docker run --privileged ubuntu # Should be blocked"
echo ""
