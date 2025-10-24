#!/usr/bin/env bash
# Splunk All-in-One Bootstrap for RHEL 8.10 (Air-gapped)
# Focus: Install + configure Splunk and enable Deployment Server/Forwarder Mgmt.
# Continues even if previous phases fail; final summary reports failures.
# System prep (deps, ulimits, THP, firewall/SELinux, cron) should be handled by prepSplunk.sh

# ---- Shell safety: no errexit so phases continue; keep nounset + pipefail
set +e
set -u -o pipefail

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
}

# Minimal compatibility shim if someone copied old code calling run "desc" cmd
if ! declare -F run >/dev/null 2>&1; then
  run() { local _d="$1"; shift; step "$_d" "$@"; }
fi

# ---- Readiness helpers (non-fatal; they set PHASE_FAIL but keep going) ----
# Wait for Splunk management API on 8089 to respond (HTTP 200/401/403 or TCP open)
wait_for_8089() {
  local timeout="${1:-300}"
  local deadline=$((SECONDS + timeout))
  while (( SECONDS < deadline )); do
    if command -v curl >/dev/null 2>&1; then
      local code
      code="$(curl -sk -o /dev/null -w '%{http_code}' "https://127.0.0.1:${MNGT_PORT}/services/server/info?count=1" || true)"
      if [[ "$code" =~ ^(200|401|403)$ ]]; then
        echo "[OK] Management API on ${MNGT_PORT} is responding (HTTP ${code})."
        return 0
      fi
    else
      if bash -lc "exec 3<>/dev/tcp/127.0.0.1/${MNGT_PORT}" 2>/dev/null; then
        exec 3>&- 3<&-
        echo "[OK] TCP ${MNGT_PORT} reachable (no curl)."
        return 0
      fi
    fi>
    sleep 3
  done
  echo "[FAIL] Management API not ready on ${MNGT_PORT} after ${timeout}s."
  return 1
}

# Wait for Deployment Server REST to respond (HTTP 200/401/403 acceptable)
wait_for_deploy_server() {
  local timeout="${1:-180}"
  local deadline=$((SECONDS + timeout))
  while (( SECONDS < deadline )); do
    if command -v curl >/dev/null 2>&1; then
      local code
      code="$(curl -sk -o /dev/null -w '%{http_code}' "https://127.0.0.1:${MNGT_PORT}/services/deployment/server/clients?count=1" || true)"
      if [[ "$code" =~ ^(200|401|403)$ ]]; then
        echo "[OK] Deployment Server REST is responding (HTTP ${code})."
        return 0
      fi
    else
      if bash -lc "exec 3<>/dev/tcp/127.0.0.1/${MNGT_PORT}" 2>/dev/null; then
        exec 3>&- 3<&-
        echo "[OK] TCP ${MNGT_PORT} reachable (no curl)."
        return 0
      fi
    fi
    sleep 3
  done
  echo "[WARN] Deployment Server REST not responding after ${timeout}s."
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
RPM_PATH="$(ls -1 ${BUILD_DIR}/splunk-9.4.5-*.x86_64.rpm 2>/dev/null | head -n1)"

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

echo "=== Splunk Bootstrap starting at $(date -Is) ==="

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
step "Set ownership on base directories" chown -R ${SPLUNK_USER}:${SPLUNK_GROUP} "$BUILD_DIR" "$SPLUNK_HOME"

end_phase

# -------------------------------------------------
# Phase 2 — Install/upgrade Splunk package (via dnf)
# Goal: Install Splunk 9.4.5 RPM without auto-start
# -------------------------------------------------
begin_phase 2 "Install/upgrade Splunk (dnf)" "Install or upgrade Splunk Enterprise from local RPM using dnf"

if [[ -n "${RPM_PATH}" && -f "${RPM_PATH}" ]]; then
  step "Install/upgrade with dnf: ${RPM_PATH}" dnf -y install --nogpgcheck "${RPM_PATH}"
  step "Chown ${SPLUNK_HOME} after install" chown -R ${SPLUNK_USER}:${SPLUNK_GROUP} "$SPLUNK_HOME"
else
  echo "   [ERROR] Splunk 9.4.5 RPM not found in ${BUILD_DIR}; skipping install commands."
  PHASE_FAIL=1
fi

end_phase

# -------------------------------------------------
# Phase 3 — Core configuration
# Goal: Admin seed, web.conf, inputs.conf, indexes, email policy, air-gap
# -------------------------------------------------
begin_phase 3 "Core configuration" "Seed admin, write core .conf files, and apply air-gap settings"

step "Ensure system/local exists" mkdir -p "$SPLUNK_ETC/system/local"

# Admin seed
step "Write user-seed.conf" bash -c "cat > '$SPLUNK_ETC/system/local/user-seed.conf' <<EOF
[user_info]
USERNAME = ${ADMIN_USER}
PASSWORD = ${ADMIN_PASS}
EOF"
step "Secure user-seed.conf" bash -c "chown ${SPLUNK_USER}:${SPLUNK_GROUP} '$SPLUNK_ETC/system/local/user-seed.conf' && chmod 600 '$SPLUNK_ETC/system/local/user-seed.conf'"

# web.conf
step "Write web.conf" bash -c "cat > '$SPLUNK_ETC/system/local/web.conf' <<EOF
[settings]
enableSplunkWebSSL = true
httpport = ${WEB_PORT}
loginFooterText = <span style='color:red;font-weight:bold'>UNCLASSIFIED FOUO</span>
updateCheckerBaseURL = 0
EOF"

# inputs.conf
step "Write inputs.conf (UF 9997 + syslog TLS 6514→cisco)" bash -c "cat > '$SPLUNK_ETC/system/local/inputs.conf' <<EOF
[splunktcp://${S2S_PORT}]
disabled = 0

[splunktcp-ssl://${SYSLOG_SSL_PORT}]
disabled = 0
requireClientCert = false
index = cisco
EOF"

# indexes.conf — explicit index paths (no $_index_name), adds linux,cisco,nas,nessus
step "Create indexes.conf file" bash -c "cat > '$SPLUNK_ETC/system/local/indexes.conf' <<'EOF'
[default]
frozenTimePeriodInSecs = 31536000

[linux]
homePath   = volume:primary/linux/db
coldPath   = volume:primary/linux/colddb
thawedPath = $SPLUNK_DB/linux/thaweddb

[cisco]
homePath   = volume:primary/cisco/db
coldPath   = volume:primary/cisco/colddb
thawedPath = $SPLUNK_DB/cisco/thaweddb

[nas]
homePath   = volume:primary/nas/db
coldPath   = volume:primary/nas/colddb
thawedPath = $SPLUNK_DB/nas/thaweddb

[nessus]
homePath   = volume:primary/nessus/db
coldPath   = volume:primary/nessus/colddb
thawedPath = $SPLUNK_DB/nessus/thaweddb

[volume:primary]
path = $SPLUNK_DB
EOF"

# email policy
step "Restrict alert email domain" bash -c "cat > '$SPLUNK_ETC/system/local/alert_actions.conf' <<'EOF'
[email]
allowedDomainList = mail.mil
EOF"

# air-gap toggles
if [[ "$AIRGAP" -eq 1 ]]; then
  step "Disable splunk_instrumentation app" bash -c "mkdir -p '$SPLUNK_ETC/apps/splunk_instrumentation/local' && cat > '$SPLUNK_ETC/apps/splunk_instrumentation/local/app.conf' <<'EOF'
[install]
state = disabled
[ui]
is_visible = false
EOF"
fi

end_phase

# -------------------------------------------------
# Phase 4 — Deployment Server config
# Goal: serverclass.conf, deployment apps, and banner app
# -------------------------------------------------
begin_phase 4 "Deployment Server config" "Create serverclass, deployment apps, and banner styling"

# serverclass
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
step "Write banner app.conf" bash -c "cat > '$APP_DIR/default/app.conf' <<'EOF'
[ui]
is_visible = false
label = Local Bootstrap
[install]
state = enabled
EOF"
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
step "Write all_deployment_client/local/deploymentclient.conf" bash -c "cat > '${DEPLOY}/all_deployment_client/local/deploymentclient.conf' <<EOF
[deployment-client]
clientName = default-client
phoneHomeIntervalInSecs = 600

[target-broker:deploymentServer]
targetUri = ${AIO_IP}:${MNGT_PORT}
EOF"
step "Write all_deployment_client/default/app.conf" bash -c "cat > '${DEPLOY}/all_deployment_client/default/app.conf' <<'EOF'
[install]
state = enabled
[ui]
is_visible = false
EOF"
step "Write all_deployment_client/metadata/default.meta" bash -c "cat > '${DEPLOY}/all_deployment_client/metadata/default.meta' <<'EOF'
[]
access = read : [ user ], write : [ admin, power ]
export = system
EOF"

# all_outputs
step "Create all_outputs dirs" mkdir -p "${DEPLOY}/all_outputs"/{default,local,metadata}
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
step "Write all_outputs/default/app.conf" bash -c "cat > '${DEPLOY}/all_outputs/default/app.conf' <<'EOF'
[install]
state = enabled
[ui]
is_visible = false
EOF"
step "Write all_outputs/metadata/default.meta" bash -c "cat > '${DEPLOY}/all_outputs/metadata/default.meta' <<'EOF'
[]
access = read : [ user ], write : [ admin, power ]
export = system
EOF"

# TAs default index routing
step "TA_nix index=linux" bash -c "mkdir -p '${DEPLOY}/Splunk_TA_nix/local' && cat > '${DEPLOY}/Splunk_TA_nix/local/inputs.conf' <<'EOF'
[default]
index = linux
EOF"
step "TA_windows index=windows" bash -c "mkdir -p '${DEPLOY}/Splunk_TA_windows/local' && cat > '${DEPLOY}/Splunk_TA_windows/local/inputs.conf' <<'EOF'
[default]
index = windows
EOF"
step "TA_sysmon index=windows" bash -c "mkdir -p '${DEPLOY}/Splunk_TA_microsoft_sysmon/local' && cat > '${DEPLOY}/Splunk_TA_microsoft_sysmon/local/inputs.conf' <<'EOF'
[default]
index = windows
EOF"
step "Placeholder TA_syslog" mkdir -p "${DEPLOY}/Splunk_TA_syslog/local}"

end_phase

# -------------------------------------------------
# Phase 5 — Ownership/permissions
# Goal: Ensure Splunk owns all written configs/apps
# -------------------------------------------------
begin_phase 5 "Ownership & permissions" "Set splunk ownership on configs and deployment apps"
step "Chown configs/apps to splunk" chown -R ${SPLUNK_USER}:${SPLUNK_GROUP} "$SPLUNK_ETC" "$APP_DIR" "$DEPLOY"
end_phase

# -------------------------------------------------
# Phase 6 — Services & Deployment Server enablement
# Goal: Enable boot-start, start splunk, wait 8089, enable DS, wait DS (retry if needed)
# -------------------------------------------------
begin_phase 6 "Services & DS enablement" "Enable boot-start, start Splunk, verify 8089, enable & verify Deployment Server"

if [[ -x "${SPLUNK_HOME}/bin/splunk" ]]; then
  step "Enable boot-start" \
    runuser -u ${SPLUNK_USER} -- ${SPLUNK_HOME}/bin/splunk enable boot-start -user ${SPLUNK_USER} --accept-license --answer-yes

  step "Start Splunk" \
    runuser -u ${SPLUNK_USER} -- ${SPLUNK_HOME}/bin/splunk start --accept-license --answer-yes

  step "Wait for management API (8089)" wait_for_8089 300

  # Ensure minimal serverclass for DS UI if none
  if [ ! -s "$SPLUNK_ETC/system/local/serverclass.conf" ]; then
    echo "   [INFO] serverclass.conf missing; creating minimal baseline for DS UI"
    cat > "$SPLUNK_ETC/system/local/serverclass.conf" <<'EOF'
# Minimal baseline so Forwarder Management UI can initialize
[serverClass:All_agents]
whitelist.0 = .*
EOF
    chown ${SPLUNK_USER}:${SPLUNK_GROUP} "$SPLUNK_ETC/system/local/serverclass.conf" || true
  fi

  step "Enable Deployment Server (Forwarder Management)" \
    runuser -u ${SPLUNK_USER} -- ${SPLUNK_HOME}/bin/splunk enable deploy-server --accept-license --answer-yes

  if ! step "Wait for Deployment Server REST" wait_for_deploy_server 180; then
    step "Restart Splunk (retry DS init)" \
      runuser -u ${SPLUNK_USER} -- ${SPLUNK_HOME}/bin/splunk restart
    step "Wait for management API (8089) after restart" wait_for_8089 300
    step "Re-check Deployment Server REST" wait_for_deploy_server 180
  fi
else
  echo "   [ERROR] Splunk binary not found at ${SPLUNK_HOME}/bin/splunk; skipping service enable/start."
  PHASE_FAIL=1
fi

end_phase

# -------------------------------------------------
# Phase 7 — Final ownership sweep
# Goal: Ensure entire /opt/splunk is owned by splunk user
# -------------------------------------------------
begin_phase 7 "Final ownership sweep" "Recursively chown /opt/splunk to splunk:splunk"
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
  exit 0
else
  echo "The following phases reported failures:"
  for p in "${FAILED_PHASES[@]}"; do echo "  - $p"; done
  echo "========================="
  exit 1
fi
