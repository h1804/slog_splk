#!/bin/bash
# Developed by [JR Presmy] from Oslitanditech 
# Script: setup_rsyslog_forwarder.sh
# Target: RHEL 6 Server with rsyslog 5.8.10-12
# Function: Installs rsyslog (if needed), configures forwarding,
#           creates 'logreader' user, sets ACLs, and opens port 514 UDP.

LOG_SERVER_IP="1.1.1.220"
LOG_SERVER_PORT="514"
CONFIG_FILE="/etc/rsyslog.conf"

# --- 1. Check and Install Rsyslog ---
echo "1. Checking and installing rsyslog..."
if ! rpm -q rsyslog &>/dev/null; then
    yum install -y rsyslog
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to install rsyslog. Exiting."
        exit 1
    fi
else
    echo "rsyslog is already installed."
fi

# --- 2. Configure Rsyslog Forwarding and Internal Diagnostics ---
echo "2. Configuring rsyslog for forwarding and diagnostics..."

# Backup original config
cp -f "$CONFIG_FILE" "$CONFIG_FILE.bak.$(date +%F)"

# a) Add Internal Diagnostics and Stop Processing
cat << 'RSYSLOG_DIAG' >> "$CONFIG_FILE"
# --- START Custom Diagnostics and Forwarding ---
# Log rsyslog internal errors/warnings locally and stop processing
syslog.err;syslog.warning    /var/log/Rsyslog_Error.log
& stop

# Log rsyslog informational/debug messages locally and stop processing
syslog.info;syslog.notice;syslog.debug    /var/log/Rsyslog_run.log
& stop
# --- END Custom Diagnostics ---
RSYSLOG_DIAG

# b) Add the forwarding rule
echo "*.* @${LOG_SERVER_IP}:${LOG_SERVER_PORT}" >> "$CONFIG_FILE"

# --- 3. Create 'logreader' User with no login ---
echo "3. Creating logreader user..."
# Create user with no home directory, no shell (no login)
useradd -r -s /sbin/nologin logreader
if [ $? -eq 0 ]; then
    echo "User 'logreader' created successfully."
else
    echo "User 'logreader' already exists or creation failed."
fi

# --- 4. Grant logreader read access to /var/log via file ACL ---
echo "4. Setting File ACLs for /var/log..."
# ACLs require the 'acl' package and the filesystem to be mounted with 'acl' support.
# Assuming basic RHEL 6 setup where it works.
yum install -y acl
setfacl -R -m user:logreader:rX /var/log/
# Set default ACL to apply to new files created in /var/log/
setfacl -R -d -m user:logreader:rX /var/log/
echo "Read access (rX) granted to 'logreader' for /var/log."

# --- 5. Open UDP Port 514 on iptables Firewall (RHEL 6) ---
echo "5. Opening port ${LOG_SERVER_PORT} UDP on iptables..."
# RHEL 6 uses iptables by default.
/sbin/iptables -I INPUT 1 -p udp --dport 514 -j ACCEPT
# Persist the rule across reboots
/sbin/service iptables save
echo "Firewall rule added and saved."

# --- 6. Connectivity Check: Ping Central Log Collector ---
echo "6. Checking connectivity to central log collector (${LOG_SERVER_IP})..."
ping -c 4 "${LOG_SERVER_IP}"
if [ $? -ne 0 ]; then
    echo "WARNING: Ping to ${LOG_SERVER_IP} failed or had packet loss. Log forwarding may fail."
else
    echo "Connectivity check successful."
fi

# --- 7. Restart Rsyslog Service ---
echo "7. Restarting rsyslog service to apply changes..."
# Use 'service' command for RHEL 6 compatibility
service rsyslog restart

# --- 8. Functional Test and Conclusion ---
echo "8. Running functional test..."
echo "-------------------------------------------------------------------"
echo "# Quick functional test: send a host-local message (NOT the imfile tail)"
# Use the bash variables directly in the logger command
logger -t rsyslog_bootstrap_test "RHEL6 rsyslog forwarder configured to ${LOG_SERVER_IP}:${LOG_SERVER_PORT} at $(date -Is)" || true

echo "-------------------------------------------------------------------"
echo "[OK] Installation and configuration complete."
echo "----------------------------------------------------------------------"
echo "  Verify receipt of the 'rsyslog_bootstrap_test' message on the remote collector."
echo "----------------------------------------------------------------------"