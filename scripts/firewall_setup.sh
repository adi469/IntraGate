#!/usr/bin/env bash
# ==========================================================================
# INTRAGATE SECURE GATEWAY — FIREWALL SETUP SCRIPT
# Locks down internal ports to block direct connection bypassing the gateway.
# ==========================================================================

set -euo pipefail

# Ensure script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "ERROR: Please run this script as root (sudo)."
  exit 1
fi

echo "=========================================="
echo "  IntraGate Secure Gateway Firewall Setup"
echo "=========================================="
echo ""

# Check if UFW is installed
if ! command -v ufw &> /dev/null; then
  echo "ufw is not installed. Installing ufw..."
  apt-get update && apt-get install -y ufw
fi

echo "Configuring firewall rules..."

# 1. Default Policies
ufw default deny incoming
ufw default allow outgoing

# 2. Allow SSH so the connection doesn't drop
ufw allow 22/tcp comment 'SSH Port'

# 3. Allow Public Web Ports (Traefik SSL Proxy)
ufw allow 80/tcp comment 'Traefik HTTP'
ufw allow 443/tcp comment 'Traefik HTTPS'

# 4. Deny Gateway & Internal App Ports from external networks
# Note: Since they bind to 127.0.0.1, the OS won't route external requests anyway.
# This UFW block acts as defense-in-depth in case someone accidentally rebinds to 0.0.0.0.
ufw deny 9000/tcp comment 'Gateway Internal Port'
ufw deny 8001/tcp comment 'Dispatch Internal Port'
ufw deny 8002/tcp comment 'Assembly Internal Port'
ufw deny 8003/tcp comment 'Quality Internal Port'
ufw deny 8004/tcp comment 'VMC Internal Port'

echo ""
echo "Enabling UFW..."
# --force avoids the interactive prompt so it can run non-interactively
ufw --force enable

echo ""
echo "=========================================="
echo "UFW Firewall is now ACTIVE and LOCKED DOWN"
echo "=========================================="
ufw status verbose
