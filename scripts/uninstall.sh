#!/bin/bash
set -e

# Docker Sentinel Uninstaller

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════╗"
echo "║      Docker Sentinel Uninstaller          ║"
echo "╚═══════════════════════════════════════════╝"
echo -e "${NC}"

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root (use sudo)${NC}"
    exit 1
fi

echo -e "${BLUE}[1/5]${NC} Stopping services..."
systemctl stop docker-sentinel 2>/dev/null || true
systemctl disable docker-sentinel 2>/dev/null || true
echo -e "  ${GREEN}✓${NC} Stopped sentinel daemon"

echo -e "${BLUE}[2/5]${NC} Removing systemd service..."
rm -f /etc/systemd/system/docker-sentinel.service
systemctl daemon-reload
echo -e "  ${GREEN}✓${NC} Removed systemd service"

echo -e "${BLUE}[3/5]${NC} Removing Docker plugin configuration..."
rm -f /etc/docker/plugins/sentinel.json

# Remove from daemon.json
DOCKER_CONFIG="/etc/docker/daemon.json"
if [ -f "$DOCKER_CONFIG" ]; then
    if command -v jq &> /dev/null; then
        jq 'del(.["authorization-plugins"])' "$DOCKER_CONFIG" > "$DOCKER_CONFIG.tmp"
        mv "$DOCKER_CONFIG.tmp" "$DOCKER_CONFIG"
        echo -e "  ${GREEN}✓${NC} Updated Docker daemon config"
    else
        echo -e "  ${YELLOW}!${NC} Please manually remove 'authorization-plugins' from $DOCKER_CONFIG"
    fi
fi

echo -e "${BLUE}[4/5]${NC} Restarting Docker..."
systemctl restart docker
echo -e "  ${GREEN}✓${NC} Docker restarted"

echo -e "${BLUE}[5/5]${NC} Removing sentinel binary..."
rm -f /usr/local/bin/sentinel
echo -e "  ${GREEN}✓${NC} Removed sentinel binary"

echo ""
echo -e "${GREEN}Uninstallation complete!${NC}"
echo ""
echo -e "${YELLOW}Note:${NC} Configuration files preserved at /etc/sentinel/"
echo "To remove completely: sudo rm -rf /etc/sentinel"
echo ""
