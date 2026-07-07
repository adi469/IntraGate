#!/usr/bin/env bash
# ==========================================================================
# INTRAGATE SECURE GATEWAY — SYSTEMD SERVICE INSTALLER
# Dynamically configures paths and installs systemd services for all apps.
# ==========================================================================

set -euo pipefail

# Ensure script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "ERROR: Please run this script as root (sudo)."
  exit 1
fi

# Detect absolute paths
SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPTS_DIR}/../.." && pwd)"
GATEWAY_DIR="${PROJECT_ROOT}/gateway"
USER_NAME="$(logname || echo "aditya")"
USER_HOME="$(eval echo "~${USER_NAME}")"

echo "=========================================="
echo "  IntraGate Services systemd Installer"
echo "=========================================="
echo "Project Root: ${PROJECT_ROOT}"
echo "Gateway Dir:  ${GATEWAY_DIR}"
echo "System User:  ${USER_NAME}"
echo "=========================================="
echo ""

# Ensure virtualenvs or dependencies are installed in each directory
# We assume the user has python3-venv installed.
# We will create a shared virtual environment for the gateway.
if [ ! -d "${GATEWAY_DIR}/venv" ]; then
  echo "Creating Gateway Virtual Environment..."
  python3 -m venv "${GATEWAY_DIR}/venv"
  "${GATEWAY_DIR}/venv/bin/pip" install --upgrade pip
  "${GATEWAY_DIR}/venv/bin/pip" install -r "${GATEWAY_DIR}/requirements.txt"
fi

# Function to write a systemd service file
write_service() {
  local service_name=$1
  local description=$2
  local working_dir=$3
  local exec_cmd=$4

  echo "Generating /etc/systemd/system/${service_name}.service..."
  cat <<EOF > "/etc/systemd/system/${service_name}.service"
[Unit]
Description=${description}
After=network.target

[Service]
Type=simple
User=${USER_NAME}
WorkingDirectory=${working_dir}
ExecStart=${exec_cmd}
Restart=always
RestartSec=5
Environment=PATH=${working_dir}/venv/bin:/usr/local/bin:/usr/bin:/bin
# Load local .env file if it exists
EnvironmentFile=-${working_dir}/.env
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user-target
EOF
}

# 1. Gateway Service
# Uses Gateway's private venv
write_service \
  "intragate-gateway" \
  "IntraGate Secure Auth Gateway" \
  "${GATEWAY_DIR}" \
  "${GATEWAY_DIR}/venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 9000 --workers 2"

# 2. Dispatch Planner
# Check if dispatch has a virtualenv; otherwise fall back to system python
DISPATCH_DIR="${PROJECT_ROOT}/Dispatch Planning/dispatch_app"
DISPATCH_BIN="python3"
if [ -d "${DISPATCH_DIR}/venv" ]; then
  DISPATCH_BIN="${DISPATCH_DIR}/venv/bin/python3"
fi
write_service \
  "intragate-dispatch" \
  "Schneider & Eaton Dispatch Planner" \
  "${DISPATCH_DIR}" \
  "${DISPATCH_BIN} server.py"

# 3. FG Assembly Planner
ASSEMBLY_DIR="${PROJECT_ROOT}/FG Assembly Planning/planner_server"
write_service \
  "intragate-assembly" \
  "LUG FG Assembly Planner" \
  "${ASSEMBLY_DIR}" \
  "/usr/bin/bash run.sh"

# 4. Quality Dashboard
QUALITY_DIR="${PROJECT_ROOT}/Quality/Supplier Dashboard App/V171 Supplier Dashboard App"
QUALITY_BIN="python3"
if [ -d "${QUALITY_DIR}/venv" ]; then
  QUALITY_BIN="${QUALITY_DIR}/venv/bin/python3"
fi
write_service \
  "intragate-quality" \
  "Supplier PPM Quality Dashboard" \
  "${QUALITY_DIR}" \
  "${QUALITY_BIN} app.py"

# 5. VMC Machine Planning
VMC_DIR="${PROJECT_ROOT}/VMC Machine Planning"
VMC_BIN="python3"
if [ -d "${VMC_DIR}/venv" ]; then
  VMC_BIN="${VMC_DIR}/venv/bin/python3"
fi
write_service \
  "intragate-vmc" \
  "VMC CNC Machine Loading Planner" \
  "${VMC_DIR}" \
  "${VMC_BIN} planner_app.py"

echo ""
echo "Reloading systemd daemon..."
systemctl daemon-reload

# Function to enable and start service
enable_start_service() {
  local service_name=$1
  echo "Enabling and starting ${service_name}..."
  systemctl enable "${service_name}"
  systemctl restart "${service_name}"
}

enable_start_service "intragate-gateway"
enable_start_service "intragate-dispatch"
enable_start_service "intragate-assembly"
enable_start_service "intragate-quality"
enable_start_service "intragate-vmc"

echo ""
echo "=========================================="
echo "  All IntraGate services installed & active"
echo "=========================================="
systemctl status intragate-gateway --no-pager
