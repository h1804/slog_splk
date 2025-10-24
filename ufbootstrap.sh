#!/bin/bash
# ----------------------------------------------------------------------
# Splunk Universal Forwarder Installation and Configuration Script
# Version: 9.4.5 (RPM) on RHEL 8.10
# ----------------------------------------------------------------------

# --- Configuration Variables ---
UF_RPM_NAME="splunkforwarder-9.4.5-*.x86_64.rpm" # Adjust if necessary
SPLUNK_HOME="/opt/splunkforwarder"
SPLUNK_DS_IP="YOUR_DS_IP_HERE"        # <--- **UPDATE THIS**
SPLUNK_INDEXER_IP="YOUR_INDEXER_IP_HERE"  # <--- **UPDATE THIS**

# Ports
SPLUNK_RECEIVER_PORT="9997"
SPLUNK_DS_PORT="8089"

# Logging
LOG_FILE="/var/log/UFBootstrap.sh.log"

# Exit immediately if a command exits with a non-zero status.
set -e

# --- Logging Setup ---
# Redirect all future output (stdout and stderr) to the log file.
# The 'tee' command is used to display output to the screen AND write to the log file.
exec > >(tee -a ${LOG_FILE}) 2>&1
echo "----------------------------------------------------------------------"
echo "Starting Splunk UF Installation: $(date)"
echo "Log output is being saved to: ${LOG_FILE}"
echo "----------------------------------------------------------------------"

# --- 1. System Prerequisite Checks and Firewall Configuration ---
echo "1. Configuring RHEL firewall for Splunk ports..."
# Note: RHEL 8 uses firewall-cmd
firewall-cmd --zone=public --add-port=${SPLUNK_RECEIVER_PORT}/tcp --permanent
firewall-cmd --zone=public --add-port=${SPLUNK_DS_PORT}/tcp --permanent
firewall-cmd --reload
echo "    Firewall configured: ports ${SPLUNK_RECEIVER_PORT} and ${SPLUNK_DS_PORT} opened."

# --- 2. Install Splunk Universal Forwarder RPM ---
echo "2. Installing Splunk Universal Forwarder RPM..."

# Find the RPM file in /opt and install it.
RPM_PATH=$(find /opt -name "${UF_RPM_NAME}" 2>/dev/null | head -n 1)

if [[ -z "$RPM_PATH" ]]; then
    echo "    ERROR: Splunk RPM file not found in /opt with name pattern: ${UF_RPM_NAME}"
    exit 1
fi

rpm -i "$RPM_PATH"
echo "   Splunk Universal Forwarder installed to ${SPLUNK_HOME}."

# --- 3. Initial Setup and Start (Accept License) ---
echo "3. Initializing and starting Splunk Forwarder..."

# Start to accept license and prompt for credentials.
# The --no-prompt flag is used to skip the web-access setup which isn't available on the UF anyway.
echo "Initializing Splunk. The start command will handle license acceptance."
$SPLUNK_HOME/bin/splunk start --accept-license --no-prompt

# Enable boot-start
$SPLUNK_HOME/bin/splunk enable boot-start -user splunkfwd
echo "   Splunk started and configured to start at boot."

# --- 4. Configure Deployment Client (Phone Home) ---
echo "4. Configuring Deployment Client (Deployment Server: ${SPLUNK_DS_IP}:${SPLUNK_DS_PORT})..."

# Create the application directory structure
DS_APP_DIR="$SPLUNK_HOME/etc/apps/deployment_client_config"
mkdir -p "$DS_APP_DIR/local"

# Create deploymentclient.conf
cat << EOF > "$DS_APP_DIR/local/deploymentclient.conf"
[target-broker:deploymentServer]
targetUri = https://${SPLUNK_DS_IP}:${SPLUNK_DS_PORT}

[general]
# Set the "phone home" interval to 10 minutes (600 seconds)
interval = 600

[sslConfig]
# Allow connection with the Splunk self-signed certificate
sslVerifyServerCert = false
EOF
echo "   Deployment Client configured to check in every 10 minutes."

# --- 5. Configure Outputs (Send Compressed Data to Indexer) ---
echo "5. Configuring Outputs (Indexer: ${SPLUNK_INDEXER_IP}:${SPLUNK_RECEIVER_PORT})..."

# Create the application directory structure
OUTPUTS_APP_DIR="$SPLUNK_HOME/etc/apps/indexer_outputs_config"
mkdir -p "$OUTPUTS_APP_DIR/local"

# Create outputs.conf
cat << EOF > "$OUTPUTS_APP_DIR/local/outputs.conf"
[tcpout]
defaultGroup = indexer_group
forwardedindex.filter.disable = true
# Enable compression for data transfer
compressed = true

[tcpout:indexer_group]
# SSL configuration for a self-signed cert
sslCertPath = \$SPLUNK_HOME/etc/auth/server.pem
sslRootCA = \$SPLUNK_HOME/etc/auth/cacert.pem
sslVerifyServerCert = false
server = ${SPLUNK_INDEXER_IP}:${SPLUNK_RECEIVER_PORT}
EOF
echo "   Outputs configured to send compressed data to indexer."

# --- 6. Apply Changes and Final Restart ---
echo "6. Applying configuration changes and restarting Splunk Forwarder..."

# Restart to load the new deploymentclient.conf and outputs.conf
$SPLUNK_HOME/bin/splunk restart
echo "   Splunk Forwarder restart complete."

echo "----------------------------------------------------------------------"
echo "  Splunk UF ${SPLUNK_HOME} is running and phoning home to ${SPLUNK_DS_IP}:${SPLUNK_DS_PORT}"
echo "  Installation Script Finished: $(date)"
echo "----------------------------------------------------------------------"