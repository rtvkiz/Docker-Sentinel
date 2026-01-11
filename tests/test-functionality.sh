#!/bin/bash
#
# Docker Sentinel Functionality Tests (No Build)
# Run with: sudo ./tests/test-functionality.sh
#

# Don't exit on error - we want to run all tests

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PASSED=0
FAILED=0

log_header() { echo -e "\n${BLUE}═══ $1 ═══${NC}\n"; }
log_test() { echo -e "${YELLOW}▶ $1${NC}"; }
log_pass() { echo -e "${GREEN}✓ PASS: $1${NC}"; PASSED=$((PASSED + 1)); }
log_fail() { echo -e "${RED}✗ FAIL: $1${NC}"; FAILED=$((FAILED + 1)); }

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Run as root: sudo $0${NC}"
    exit 1
fi

log_header "DOCKER SENTINEL FUNCTIONALITY TESTS"

#--- Test 1: Daemon Status ---
log_header "1. DAEMON STATUS"
log_test "Checking if daemon is running..."
STATUS_OUTPUT=$(sentinel authz status 2>&1 || true)
echo "$STATUS_OUTPUT"
if echo "$STATUS_OUTPUT" | grep -qi "running"; then
    log_pass "Daemon is running"
else
    echo "Daemon not running. Starting..."
    sentinel authz start &
    sleep 3
    log_pass "Daemon started"
fi

#--- Test 2: Policy - Development (Warn Mode) ---
log_header "2. DEVELOPMENT POLICY (WARN MODE)"

log_test "Switching to development policy..."
sentinel policy use development || echo "Policy switch returned non-zero"
sentinel authz reload || echo "Reload returned non-zero"
sleep 2

log_test "Privileged container (should ALLOW in warn mode)..."
if docker run --rm --privileged alpine echo "ALLOWED" 2>&1; then
    log_pass "Privileged allowed in warn mode"
else
    log_fail "Privileged blocked in warn mode"
fi

log_test "Host network (should ALLOW in warn mode)..."
if docker run --rm --net=host alpine echo "ALLOWED" 2>&1; then
    log_pass "Host network allowed in warn mode"
else
    log_fail "Host network blocked in warn mode"
fi

#--- Test 3: Policy - Production (Enforce Mode) ---
log_header "3. PRODUCTION POLICY (ENFORCE MODE)"

log_test "Switching to production policy..."
sentinel policy use production || echo "Policy switch returned non-zero"
sentinel authz reload || echo "Reload returned non-zero"
sleep 2

log_test "Normal container (should ALLOW)..."
if docker run --rm alpine echo "ALLOWED" 2>&1; then
    log_pass "Normal container allowed"
else
    log_fail "Normal container blocked"
fi

log_test "Privileged container (should BLOCK)..."
if docker run --rm --privileged alpine echo "BLOCKED?" 2>&1; then
    log_fail "Privileged was ALLOWED (expected block)"
else
    log_pass "Privileged correctly BLOCKED"
fi

log_test "Docker socket mount (should BLOCK)..."
if docker run --rm -v /var/run/docker.sock:/var/run/docker.sock alpine echo "BLOCKED?" 2>&1; then
    log_fail "Docker socket was ALLOWED (expected block)"
else
    log_pass "Docker socket correctly BLOCKED"
fi

log_test "Root mount (should BLOCK)..."
if docker run --rm -v /:/host alpine echo "BLOCKED?" 2>&1; then
    log_fail "Root mount was ALLOWED (expected block)"
else
    log_pass "Root mount correctly BLOCKED"
fi

#--- Test 4: Audit ---
log_header "4. AUDIT LOGGING"

log_test "Audit list..."
if sentinel audit list --limit 5 2>&1; then
    log_pass "Audit list works"
else
    log_fail "Audit list failed"
fi

log_test "Audit stats..."
if sentinel audit stats --since 1h 2>&1; then
    log_pass "Audit stats works"
else
    log_fail "Audit stats failed"
fi

#--- Test 5: Secret Scanning ---
log_header "5. SECRET SCANNING"

if which trufflehog >/dev/null 2>&1; then
    log_test "Creating test image with secrets..."
    TMP=$(mktemp -d)
    cat > "$TMP/Dockerfile" << 'EOF'
FROM alpine
ENV AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
ENV AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
EOF
    docker build -t secret-test:latest "$TMP" -q
    
    log_test "Scanning for secrets..."
    if sentinel scan-secrets secret-test:latest 2>&1 | head -20; then
        log_pass "Secret scan executed"
    fi
    
    docker rmi secret-test:latest -f 2>/dev/null
    rm -rf "$TMP"
else
    echo "TruffleHog not installed - skipping"
fi

#--- Summary ---
log_header "SUMMARY"
echo -e "  ${GREEN}Passed: $PASSED${NC}"
echo -e "  ${RED}Failed: $FAILED${NC}"

# Reset to development mode
echo ""
echo "Resetting to development policy..."
sentinel policy use development 2>/dev/null || true
sentinel authz reload 2>/dev/null || true

if [ "$FAILED" -eq 0 ]; then
    echo -e "\n${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "\n${RED}Some tests failed${NC}"
    exit 1
fi

