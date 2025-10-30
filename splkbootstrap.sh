#!/usr/bin/env bash
# Splunk All-in-One Bootstrap for RHEL 8.10 (Air-gapped) no server.conf
# Focus: Install + configure Splunk and enable Deployment Server/Forwarder Mgmt.
# Continues even if previous phases fail; final summary reports failures.
# System prep (deps, ulimits, THP, firewall/SELinux, cron) should be handled by prepSplunk.sh

# ---- Shell safety: no errexit so phases continue; keep nounset + pipefail
set +e
set -u -o pipefail

# --------------------------
# LOGGING SETUP
# Log everything to a file and the console.
# --------------------------
LOGFILE="/var/log/splkbootstrap.log"
# Create directory and file, owned by root (as the script runs as root)
mkdir -p "$(dirname "$LOGFILE")"
touch "$LOGFILE"
# Redirect stdout and stderr to the logfile AND console (tee -a)
exec > >(tee -a "$LOGFILE") 2>&1
echo "=== Splunk Bootstrap starting at $(date -Is) ==="

# --------------------------
# Phase framework & helpers
# --------------------------
FAILED_PHASES=()

begin_phase() {
  PHASE_NUM="$1"; PHASE_NAME="$2"; PHASE_GOAL="$3"; PHASE_FAIL=0
  echo
  echo "#########################"
  echo "# Phase ${PHASE_NUM} ${PHASE_NAME}"
  echo "# Goal: ${PHASE_GOAL}"
  echo "#########################"
}

# step "desc" <command...>
step() {
  local desc="$1"; shift
  echo "-> ${desc}"
  # run the command; never exit the script on failure
  if "$@"; then
    echo "   [OK] ${desc}"
    return 0
  else
    local rc=$?
    echo "   [FAIL:${rc}] ${desc}"
    PHASE_FAIL=1
    return $rc
  fi
}

end_phase() {
  if [[ ${PHASE_FAIL} -eq 0 ]]; then
    echo "*** Phase ${PHASE_NUM} (${PHASE_NAME}): success"
  else
    echo "*** Phase ${PHASE_NUM} (${PHASE_NAME}): failed"
    FAILED_PHASES+=("Phase ${PHASE_NUM} - ${PHASE_NAME}")
  fi
  
  # --- ADDED: 3-second wait for stability and logging clarity ---
  # Only wait if not the final phase (Phase 7 is the last operational phase)
  if [[ "${PHASE_NUM}" -lt 7 ]]; then
    echo ""
    echo "--- Waiting 3 seconds before next phase ---"
    sleep 3
  fi
  # -----------------------------------------------------------
}

# Minimal compatibility shim if someone copied old code calling run "desc" cmd
if ! declare -F run >/dev/null 2>&1; then
  run() { local _d="$1"; shift; step "$_d" "$@"; }
fi

# ---- Readiness helpers (non-fatal; they set PHASE_FAIL but keep going) ----
# NEW/UPDATED: wait_for_port uses pure bash TCP connection for efficiency (like ncat)
wait_for_port() {
  local host="$1"
  local port="$2"
  local total_timeout="${3:-300}"
  local deadline=$((SECONDS + total_timeout))

  echo -n "[*] Waiting for ${host}:${port}"
  while (( SECONDS < deadline )); do
    # Use pure bash TCP connection test (equivalent to netcat)
    if bash -c "exec 3<>/dev/tcp/${host}/${port}" 2>/dev/null; then
      exec 3>&- 3<&-
      echo " - [OK] Port ${port} is open."
      return 0
    fi
    echo -n "."
    sleep 3
  done
  echo " - [FAIL] Port ${port} not reachable after $((SECONDS - (deadline - total_timeout)))s."
  return 1
}

# UPDATED: Simplified wait_for_8089 to use the new wait_for_port function
wait_for_8089() {
  local timeout="${1:-300}"
  if wait_for_port "127.0.0.1" "${MNGT_PORT}" "${timeout}"; then
    echo "[OK] Management port ${MNGT_PORT} is reachable."
    return 0
  fi
  echo "[FAIL] Management port ${MNGT_PORT} not ready after ${timeout}s."
  return 1
}

# --------------------------
# Bootstrap variables
# --------------------------
SPLUNK_USER="splunk"
SPLUNK_GROUP="splunk"
SPLUNK_HOME="/opt/splunk"
SPLUNK_ETC="$SPLUNK_HOME/etc"
SPLUNK_VAR="$SPLUNK_HOME/var"
SPLUNK_DB="$SPLUNK_VAR/lib/splunk"
DEPLOY="$SPLUNK_ETC/deployment-apps"
BUILD_DIR="/opt/build"
# UPDATED for Splunk 10.1
RPM_PATH="$(ls -1 ${BUILD_DIR}/splunk-10.*.x86_64.rpm 2>/dev/null | head -n1)"

ADMIN_USER="admin"
ADMIN_PASS="1qaz2wsx!QAZ@WSX"
WEB_PORT="8443"
S2S_PORT="9997"
MNGT_PORT="8089"
SYSLOG_SSL_PORT="6514"
AIO_IP="192.168.1.191"

AIRGAP=1
FROZEN_SECS=$((365*24*60*60)) # 365 days

# Ensure APP_DIR exists as a variable even if Phase 4 fails
APP_DIR="$SPLUNK_HOME/etc/apps/local_bootstrap"

# -------------------------------------------------
# Phase 1 — OS principals & base directories
# Goal: Ensure splunk user/group and required paths
# -------------------------------------------------
begin_phase 1 "OS principals & base dirs" "Ensure splunk user/group exist and base directories are ready"

if ! id -u "$SPLUNK_USER" &>/dev/null; then
  step "Create ${SPLUNK_USER} system user" \
    useradd --system --home-dir "${SPLUNK_HOME}" --shell /sbin/nologin --no-create-home "${SPLUNK_USER}"
else
  echo "   [INFO] ${SPLUNK_USER} already exists"
fi

step "Ensure ${SPLUNK_GROUP} group" bash -c "getent group '$SPLUNK_GROUP' >/dev/null || groupadd '$SPLUNK_GROUP'"
step "Add ${SPLUNK_USER} to ${SPLUNK_GROUP}" usermod -a -G "$SPLUNK_GROUP" "$SPLUNK_USER"
step "Create base directories" bash -c "mkdir -p '$BUILD_DIR' '$SPLUNK_HOME' '$SPLUNK_ETC' '$SPLUNK_VAR' '$SPLUNK_DB' '$DEPLOY'"
step "Set initial ownership on build/home dirs" chown -R ${SPLUNK_USER}:${SPLUNK_GROUP} "$BUILD_DIR" "$SPLUNK_HOME"

end_phase

# -------------------------------------------------
# Phase 2 — Install Splunk package (via dnf)
# Goal: Install Splunk 10.1.0 RPM
# -------------------------------------------------
begin_phase 2 "Install Splunk (dnf)" "Install Splunk Enterprise from local RPM using dnf"

if [[ -n "${RPM_PATH}" && -f "${RPM_PATH}" ]]; then
  # Message updated for Splunk 10.1
  step "Install with dnf: ${RPM_PATH}" dnf -y install --nogpgcheck "${RPM_PATH}"
else
  # Message updated for Splunk 10.1
  echo "   [ERROR] Splunk 10.1.0 RPM not found in ${BUILD_DIR}; skipping install commands."
  PHASE_FAIL=1
fi

end_phase

# -------------------------------------------------
# Phase 3 — Post-Install Ownership (CRITICAL)
# Goal: Fix file ownership after RPM install (which installs as root)
# -------------------------------------------------
begin_phase 3 "Post-Install Ownership" "Recursively chown /opt/splunk to splunk:splunk after RPM install"

if [[ -d "$SPLUNK_HOME" ]]; then
  # CRITICAL: Set ownership immediately after install, before writing configs
  step "Chown ${SPLUNK_HOME} to ${SPLUNK_USER}:${SPLUNK_GROUP}" chown -R ${SPLUNK_USER}:${SPLUNK_GROUP} "$SPLUNK_HOME"
else
  echo "   [WARN] ${SPLUNK_HOME} not found; skipping post-install chown."
fi

end_phase

# -------------------------------------------------
# Phase 4 — Core configuration (Written as ROOT user)
# Goal: Admin seed, web.conf, inputs.conf, indexes, email policy, air-gap
# -------------------------------------------------
begin_phase 4 "Core configuration" "Seed admin, write core .conf files as ROOT"

step "Ensure system/local exists" mkdir -p "$SPLUNK_ETC/system/local"

# Admin seed
# WRITTEN AS ROOT
step "Write user-seed.conf" bash -c "cat > '$SPLUNK_ETC/system/local/user-seed.conf' <<EOF
[user_info]
USERNAME = ${ADMIN_USER}
PASSWORD = ${ADMIN_PASS}
EOF"
# CHOWN/CHMOD FIXED: Using double quotes to allow $SPLUNK_ETC variable expansion.
step "Secure user-seed.conf" chown ${SPLUNK_USER}:${SPLUNK_GROUP} "$SPLUNK_ETC/system/local/user-seed.conf"
step "Set user-seed.conf permissions" chmod 600 "$SPLUNK_ETC/system/local/user-seed.conf"

# web.conf
# WRITTEN AS ROOT
step "Write web.conf" bash -c "cat > '$SPLUNK_ETC/system/local/web.conf' <<EOF
[settings]
enableSplunkWebSSL = true
httpport = ${WEB_PORT}
loginFooterText = <span style='color:red;font-weight:bold'>UNCLASSIFIED FOUO</span>
updateCheckerBaseURL = 0
EOF"

# inputs.conf - MODIFIED TO REVERT TO PLAIN TCP ON 9997 (S2S)
# WRITTEN AS ROOT
step "Write inputs.conf (Plain TCP Receiver 9997 & TLS Syslog 6514)" bash -c "cat > '$SPLUNK_ETC/system/local/inputs.conf' <<EOF
# Plain TCP receiver for Universal Forwarders (reverted from SSL)
[splunktcp://${S2S_PORT}]
disabled = 0
# Set the default index for incoming data if not specified by the forwarder
_TCP_ROUTING = *

# SSL Receiver for Syslog over TLS (retained for security compliance if needed)
[splunktcp-ssl://${SYSLOG_SSL_PORT}]
disabled = 0
requireClientCert = false
index = cisco
EOF"

# REMOVED: Custom server.conf block. Relying on Splunk's default server.conf.
# The server.conf configuration (sslConfig, httpServer) is now handled by Splunk's default files.

# indexes.conf — explicit index paths (no $_index_name), adds linux,cisco,nas,nessus, SOLARWINDS
# WRITTEN AS ROOT
step "Create indexes.conf file" bash -c "cat > '$SPLUNK_ETC/system/local/indexes.conf' <<'EOF'
[default]
frozenTimePeriodInSecs = 31536000

[linux]
homePath   = volume:primary/linux/db
coldPath   = volume:primary/linux/colddb
thawedPath = \$SPLUNK_DB/linux/thaweddb

[cisco]
homePath   = volume:primary/cisco/db
coldPath   = volume:primary/cisco/colddb
thawedPath = \$SPLUNK_DB/cisco/thaweddb

[nas]
homePath   = volume:primary/nas/db
coldPath   = volume:primary/nas/colddb
thawedPath = \$SPLUNK_DB/nas/thaweddb

[nessus]
homePath   = volume:primary/nessus/db
coldPath   = volume:primary/nessus/colddb
thawedPath = \$SPLUNK_DB/nessus/thaweddb

[solarwinds]
homePath   = volume:primary/solarwinds/db
coldPath   = volume:primary/solarwinds/colddb
thawedPath = \$SPLUNK_DB/solarwinds/thaweddb

[windows]
homePath   = volume:primary/windows/db
coldPath   = volume:primary/windows/colddb
thawedPath = \$SPLUNK_DB/windows/thaweddb

[volume:primary]
path = \$SPLUNK_DB
EOF"

# email policy
# WRITTEN AS ROOT
step "Restrict alert email domain" bash -c "cat > '$SPLUNK_ETC/system/local/alert_actions.conf' <<'EOF'
[email]
allowedDomainList = mail.mil
EOF"

# air-gap toggles
step "Disable splunk_instrumentation app directory" mkdir -p '$SPLUNK_ETC/apps/splunk_instrumentation/local'
if [[ "$AIRGAP" -eq 1 ]]; then
  # WRITTEN AS ROOT
  step "Disable splunk_instrumentation app.conf" bash -c "cat > '$SPLUNK_ETC/apps/splunk_instrumentation/local/app.conf' <<'EOF'
[install]
state = disabled
[ui]
is_visible = false
EOF"
fi

end_phase

# -------------------------------------------------
# Phase 5 — Deployment Server config & Ownership Sweep
# Goal: serverclass.conf, deployment apps, banner app, and final config chown
# -------------------------------------------------
begin_phase 5 "Deployment Server config & Ownership Sweep" "Create deployment config and apps as ROOT, then sweep ownership"

# serverclass
# WRITTEN AS ROOT
step "Write serverclass.conf" bash -c "cat > '$SPLUNK_ETC/system/local/serverclass.conf' <<'EOF'
[serverClass:All_agents]
whitelist.0 = .*
[serverClass:All_agents:app:Splunk_TA_base]
restartSplunkd = true
[serverClass:All_agents:app:all_deployment_client]
restartSplunkd = true
[serverClass:All_agents:app:all_outputs]
restartSplunkd = true

[serverClass:All_Linux]
whitelist.0 = .*linux.*
[serverClass:All_Linux:app:Splunk_TA_nix]
restartSplunkd = true

[serverClass:All_Windows]
whitelist.0 = .*win.*
[serverClass:All_Windows:app:Splunk_TA_windows]
restartSplunkd = true
[serverClass:All_Windows:app:Splunk_TA_microsoft_sysmon]
restartSplunkd = true

[serverClass:All_Syslog]
whitelist.0 = .*syslog.*
[serverClass:All_Syslog:app:Splunk_TA_syslog]
restartSplunkd = false

[serverClass:All_Domain_Controls]
whitelist.0 = .*dc.*|.*domain.*|.*ad.*
[serverClass:All_Domain_Controls:app:Splunk_TA_windows]
restartSplunkd = true
EOF"

# banner app
APP_DIR="$SPLUNK_HOME/etc/apps/local_bootstrap"
step "Create banner app directories" mkdir -p "$APP_DIR/appserver/static" "$APP_DIR/default"
# WRITTEN AS ROOT
step "Write banner app.conf" bash -c "cat > '$APP_DIR/default/app.conf' <<'EOF'
[ui]
is_visible = false
label = Local Bootstrap
[install]
state = enabled
EOF"
# WRITTEN AS ROOT
step "Write banner CSS" bash -c "cat > '$APP_DIR/appserver/static/bootstrap-banner.css' <<'EOF'
.splunk-header .AppBar { border-bottom: 3px solid #cc0000; }
.splunk-header:after {
  content: "UNCLASSIFIED FOUO";
  display: block;
  color: #cc0000;
  font-weight: 700;
  text-align: center;
  padding: 4px 0;
}
EOF"

# deployment apps
step "Ensure deployment-apps root" mkdir -p "${DEPLOY}"

# all_deployment_client
step "Create all_deployment_client dirs" mkdir -p "${DEPLOY}/all_deployment_client"/{default,local,metadata}
# WRITTEN AS ROOT
step "Write all_deployment_client/local/deploymentclient.conf" bash -c "cat > '${DEPLOY}/all_deployment_client/local/deploymentclient.conf' <<EOF
[deployment-client]
clientName = default-client
phoneHomeIntervalInSecs = 600

[target-broker:deploymentServer]
targetUri = ${AIO_IP}:${MNGT_PORT}
EOF"
# WRITTEN AS ROOT
step "Write all_deployment_client/default/app.conf" bash -c "cat > '${DEPLOY}/all_deployment_client/default/app.conf' <<'EOF'
[install]
state = enabled
[ui]
is_visible = false
EOF"
# WRITTEN AS ROOT
step "Write all_deployment_client/metadata/default.meta" bash -c "cat > '${DEPLOY}/all_deployment_client/metadata/default.meta' <<'EOF'
[]
access = read : [ user ], write : [ admin, power ]
export = system
EOF"

# all_outputs - REVERTED TO PLAIN TCP
step "Create all_outputs dirs" mkdir -p "${DEPLOY}/all_outputs"/{default,local,metadata}
# WRITTEN AS ROOT
step "Write all_outputs/local/outputs.conf" bash -c "cat > '${DEPLOY}/all_outputs/local/outputs.conf' <<EOF
[tcpout]
defaultGroup = main
autoLB = true
useACK = true

[tcpout:main]
server = ${AIO_IP}:${S2S_PORT}
compressed = true
forceTimebasedAutoLB = true
EOF"
# WRITTEN AS ROOT
step "Write all_outputs/default/app.conf" bash -c "cat > '${DEPLOY}/all_outputs/default/app.conf' <<'EOF'
[install]
state = enabled
[ui]
is_visible = false
EOF"
# WRITTEN AS ROOT
step "Write all_outputs/metadata/default.meta" bash -c "cat > '${DEPLOY}/all_outputs/metadata/default.meta' <<'EOF'
[]
access = read : [ user ], write : [ admin, power ]
export = system
EOF"

# TAs default index routing
step "TA_nix index=linux" mkdir -p '${DEPLOY}/Splunk_TA_nix/local'
# WRITTEN AS ROOT
step "Write TA_nix inputs.conf" bash -c "cat > '${DEPLOY}/Splunk_TA_nix/local/inputs.conf' <<'EOF'
[default]
index = linux
EOF"

step "TA_windows index=windows" mkdir -p '${DEPLOY}/Splunk_TA_windows/local'
# WRITTEN AS ROOT
step "Write TA_windows inputs.conf" bash -c "cat > '${DEPLOY}/Splunk_TA_windows/local/inputs.conf' <<'EOF'
[default]
index = windows
EOF"

step "TA_sysmon index=windows" mkdir -p '${DEPLOY}/Splunk_TA_microsoft_sysmon/local'
# WRITTEN AS ROOT
step "Write TA_sysmon inputs.conf" bash -c "cat > '${DEPLOY}/Splunk_TA_microsoft_sysmon/local/inputs.conf' <<'EOF'
[default]
index = windows
EOF"
step "Placeholder TA_syslog" mkdir -p "${DEPLOY}/Splunk_TA_syslog/local}"

# --- Targeted Ownership Sweep (Mandatory after writing config as root) ---
step "Chown newly created configs/apps to splunk" chown -R ${SPLUNK_USER}:${SPLUNK_GROUP} "$SPLUNK_ETC" "$APP_DIR" "$DEPLOY"
# --- End Targeted Ownership Sweep ---

end_phase

# -------------------------------------------------
# Phase 6 — Services & Start Splunk
# Goal: Enable boot-start and unconditionally start splunk as the splunk user.
# -------------------------------------------------
begin_phase 6 "Services & Start Splunk" "Enable boot-start and start Splunk service as user ${SPLUNK_USER}"

if [[ -x "${SPLUNK_HOME}/bin/splunk" ]]; then
  
  # 1. Enable boot-start (This command is critical for systemd/init)
  step "Enable boot-start for user ${SPLUNK_USER}" \
    runuser -u ${SPLUNK_USER} -- ${SPLUNK_HOME}/bin/splunk enable boot-start -user ${SPLUNK_USER} --accept-license --answer-yes

  # 2. Start Splunk as the splunk user
  step "Start Splunk service as user ${SPLUNK_USER}" \
    runuser -u ${SPLUNK_USER} -- ${SPLUNK_HOME}/bin/splunk start --accept-license --answer-yes
    
else
  echo "   [ERROR] Splunk binary not found at ${SPLUNK_HOME}/bin/splunk; skipping service enable/start."
  PHASE_FAIL=1
fi

end_phase

# -------------------------------------------------
# Phase 7 — Final ownership sweep
# Goal: Ensure entire /opt/splunk is owned by splunk user, capturing new files
# -------------------------------------------------
begin_phase 7 "Final ownership sweep" "Recursively chown /opt/splunk to splunk:splunk to clean up any root-created service files"
step "chown -R splunk:splunk /opt/splunk" chown -R ${SPLUNK_USER}:${SPLUNK_GROUP} "/opt/splunk"
end_phase

# --------------------------
# Final Phase Summary
# --------------------------
echo
echo "===== PHASE SUMMARY ====="
if [[ ${#FAILED_PHASES[@]} -eq 0 ]]; then
  echo "All phases completed: success"
  echo "========================="
  echo "Review ${LOGFILE} for full script output."
  exit 0
else
  echo "The following phases reported failures:"
  for p in "${FAILED_PHASES[@]}"; do echo "  - $p"; done
  echo "========================="
  echo "Review ${LOGFILE} for full script output."
  exit 1
fi
