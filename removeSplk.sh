#!/usr/bin/env bash
# splunk-cleanup.sh
# Cleanup Splunk Enterprise installation (RHEL/CentOS 8+)
# - Removes Splunk RPM via dnf
# - Deletes Splunk directory (/opt/splunk)
# - Cleans up systemd unit and user

set -euo pipefail

SPLUNK_RPM="splunk"
SPLUNK_HOME="/opt/splunk"

echo "[*] Starting Splunk cleanup..."

# Stop Splunk service if running
if systemctl is-active --quiet Splunkd.service 2>/dev/null; then
  echo "[*] Stopping Splunk service..."
  systemctl stop Splunkd.service || true
fi

# Remove systemd unit if exists
if [ -f /etc/systemd/system/Splunkd.service ]; then
  echo "[*] Disabling and removing systemd unit..."
  systemctl disable Splunkd.service || true
  rm -f /etc/systemd/system/Splunkd.service
  systemctl daemon-reload
fi

# Remove Splunk RPM via dnf
if rpm -q ${SPLUNK_RPM} >/dev/null 2>&1; then
  echo "[*] Removing Splunk RPM..."
  dnf -y remove ${SPLUNK_RPM} || true
else
  echo "[INFO] Splunk RPM not found in RPM database, skipping."
fi

# Delete Splunk directory
if [ -d "$SPLUNK_HOME" ]; then
  echo "[*] Deleting $SPLUNK_HOME ..."
  rm -rf "$SPLUNK_HOME"
else
  echo "[INFO] $SPLUNK_HOME not found, skipping."
fi

# Optionally remove splunk user/group
if id splunk &>/dev/null; then
  echo "[*] Removing splunk user..."
  userdel -r splunk || true
fi
if getent group splunk >/dev/null; then
  echo "[*] Removing splunk group..."
  groupdel splunk || true
fi

echo "[OK] Splunk cleanup completed."
