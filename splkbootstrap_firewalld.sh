#!/usr/bin/env bash
# Splunk All-in-One Bootstrap for RHEL 8.10 (Air-gapped)
# Version: 2025-10-01 (root-run, no sudo prompts; continues on errors; deps pre-check)
# - Installs Splunk Enterprise 9.4.4 from /opt/build RPM
# - Web on 8443 HTTPS, UF on 9997, TLS syslog on 6514
# - Creates windows/linux/cisco/nas indexes (365d frozen)
# - Banner: "UNCLASSIFIED FOUO" (red)
# - Air-gap hardening (no internet/update checks); email allowedDomainList=mail.mil
# - Deployment Server + server classes + Forwarder Management UI enablement
# - Deployment apps: all_deployment_client & all_outputs (with metadata + compression)
# - Per-TA default index routing for nix/windows/sysmon
# - Inputs: :6514 -> index=cisco
# - Daily chown cron, weekly backup of /opt/splunk
# - THP disabled (runtime + systemd + kernel arg), ulimits via PAM + systemd
# - No NAS mounting (scripts only act if path exists)
# - Resilient: continues on errors, logs to /var/log/splkbootstrap.log

set -uo pipefail
LOGFILE="/var/log/splkbootstrap.log"
exec > >(tee -a "$LOGFILE") 2>&1

# Helper: run a command, log failures, keep going
run() {
  local desc="$1"; shift
  echo "[*] ${desc}..."
  if "$@"; then
    echo "[OK] ${desc}"
  else
    local rc=$?
    echo "[WARN] ${desc} failed with rc=${rc} — continuing."
    return $rc
  fi
}

SPLUNK_USER="splunk"
SPLUNK_GROUP="splunk"
SPLUNK_HOME="/opt/splunk"
SPLUNK_ETC="$SPLUNK_HOME/etc"
SPLUNK_VAR="$SPLUNK_HOME/var"
SPLUNK_DB="$SPLUNK_VAR/lib/splunk"
DEPLOY="$SPLUNK_ETC/deployment-apps"
BUILD_DIR="/opt/build"
RPM_PATH="$(ls -1 ${BUILD_DIR}/splunk-9.4.4-*.x86_64.rpm 2>/dev/null | head -n1)"

ADMIN_USER="admin"
ADMIN_PASS="1qaz2wsx!QAZ@WSX"
WEB_PORT="8443"
S2S_PORT="9997"
MNGT_PORT="8089"
SHC_PORT="8065"
LOCAL_KV_STORE_PORT="8191"
SYSLOG_SSL_PORT="6514"
AIO_IP="192.168.1.191"

NAS_MOUNT="/mnt/splunk_nas"
ARCHIVE_DIR="${NAS_MOUNT}/splunk_archive"
AIRGAP=1
FROZEN_SECS=$((365*24*60*60)) # 365 days

require_root() { [ "${EUID:-$(id -u)}" -eq 0 ] || { echo "Run as root."; exit 1; }; }
require_root

echo "=== Splunk Bootstrap starting at $(date -Is) ==="

# -----------------------------------------------------------------------------
# Minimal dependencies (only install missing)
# -----------------------------------------------------------------------------
pkgs=(curl policycoreutils-python-utils jq lsof rsync tar gzip logrotate)
for pkg in "${pkgs[@]}"; do
  if rpm -q "$pkg" >/dev/null 2>&1; then
    echo "[OK] $pkg already installed"
  else
    run "Install $pkg" dnf -y install "$pkg"
  fi
done

# -----------------------------------------------------------------------------
# OS principals & base dirs
# -----------------------------------------------------------------------------
if ! id -u "$SPLUNK_USER" &>/dev/null; then
  run "Create ${SPLUNK_USER} user (home=${SPLUNK_HOME}, no /home)" \
    useradd --system --home-dir "${SPLUNK_HOME}" --shell /sbin/nologin --no-create-home "${SPLUNK_USER}"
fi
run "Ensure ${SPLUNK_GROUP} group" bash -c "getent group '$SPLUNK_GROUP' >/dev/null || groupadd '$SPLUNK_GROUP'"
run "Add ${SPLUNK_USER} to ${SPLUNK_GROUP}" usermod -a -G "$SPLUNK_GROUP" "$SPLUNK_USER"

run "Ensure base directories" bash -c "mkdir -p '$BUILD_DIR' '$SPLUNK_HOME' '$SPLUNK_ETC' '$SPLUNK_VAR' '$SPLUNK_DB' '$DEPLOY'"
run "Chown base directories to splunk" chown -R ${SPLUNK_USER}:${SPLUNK_GROUP} "$BUILD_DIR" "$SPLUNK_HOME"

# -----------------------------------------------------------------------------
# Install/upgrade Splunk (soft guard)
# -----------------------------------------------------------------------------
if [ -n "${RPM_PATH}" ] && [ -f "${RPM_PATH}" ]; then
  run "Install/upgrade Splunk from ${RPM_PATH} (no auto-start)" rpm -Uvh --replacepkgs --nopost "${RPM_PATH}"
  run "Chown ${SPLUNK_HOME} post-install" chown -R ${SPLUNK_USER}:${SPLUNK_GROUP} "$SPLUNK_HOME"
else
  echo "[ERROR] Splunk 9.4.4 RPM not found in ${BUILD_DIR}. Skipping install section and continuing."
fi

# -----------------------------------------------------------------------------
# Splunk-recommended ULIMITS (PAM + systemd)
# -----------------------------------------------------------------------------
run "Configure PAM limits for splunk user" bash -c "cat > /etc/security/limits.d/99-splunk.conf <<'EOF'
# Splunk recommended ulimits
splunk soft nofile 65535
splunk hard nofile 131072
splunk soft nproc  8192
splunk hard nproc  16384
splunk soft fsize  unlimited
splunk hard fsize  unlimited
EOF"
run "Create systemd drop-in for Splunkd.service" bash -c "mkdir -p /etc/systemd/system/Splunkd.service.d && cat > /etc/systemd/system/Splunkd.service.d/limits.conf <<'EOF'
[Service]
LimitNOFILE=131072
LimitNPROC=16384
LimitFSIZE=infinity
EOF"
run "Create systemd drop-in for splunk.service" bash -c "mkdir -p /etc/systemd/system/splunk.service.d && cat > /etc/systemd/system/splunk.service.d/limits.conf <<'EOF'
[Service]
LimitNOFILE=131072
LimitNPROC=16384
LimitFSIZE=infinity
EOF"
run "systemd daemon-reload" systemctl daemon-reload

# -----------------------------------------------------------------------------
# Core configuration
# -----------------------------------------------------------------------------
run "Ensure system/local directory" mkdir -p "$SPLUNK_ETC/system/local"

# Seed admin creds
run "Seed admin credentials" bash -c "cat > '$SPLUNK_ETC/system/local/user-seed.conf' <<EOF
[user_info]
USERNAME = ${ADMIN_USER}
PASSWORD = ${ADMIN_PASS}
EOF"
run "Secure user-seed.conf" bash -c "chown ${SPLUNK_USER}:${SPLUNK_GROUP} '$SPLUNK_ETC/system/local/user-seed.conf' && chmod 600 '$SPLUNK_ETC/system/local/user-seed.conf'"


[sslConfig]
enableSplunkdSSL = true
EOF"

# web.conf
run "Write web.conf" bash -c "cat > '$SPLUNK_ETC/system/local/web.conf' <<EOF
[settings]
enableSplunkWebSSL = true
httpport = ${WEB_PORT}
loginFooterText = <span style='color:red;font-weight:bold'>UNCLASSIFIED FOUO</span>
updateCheckerBaseURL = 0
EOF"

# inputs.conf
run "Write inputs.conf (9997 UF, 6514 Cisco→cisco index)" bash -c "cat > '$SPLUNK_ETC/system/local/inputs.conf' <<EOF
[splunktcp://${S2S_PORT}]
disabled = 0

[splunktcp-ssl://${SYSLOG_SSL_PORT}]
disabled = 0
requireClientCert = false
index = cisco
EOF"

# -----------------------------------------------------------------------------
# indexes.conf
# FIX: Top-level single-quoted heredoc so Bash never expands Splunk placeholders
#      like $_index_name and $SPLUNK_DB (avoids 'unbound variable' under set -u)
# -----------------------------------------------------------------------------
cat > "$SPLUNK_ETC/system/local/indexes.conf" <<'EOF'
[default]
frozenTimePeriodInSecs = 31536000

[windows]
homePath   = volume:primary/$_index_name/db
coldPath   = volume:primary/$_index_name/colddb
thawedPath = $SPLUNK_DB/$_index_name/thaweddb

[linux]
homePath   = volume:primary/$_index_name/db
coldPath   = volume:primary/$_index_name/colddb
thawedPath = $SPLUNK_DB/$_index_name/thaweddb

[cisco]
homePath   = volume:primary/$_index_name/db
coldPath   = volume:primary/$_index_name/colddb
thawedPath = $SPLUNK_DB/$_index_name/thaweddb

[nas]
homePath   = volume:primary/$_index_name/db
coldPath   = volume:primary/$_index_name/colddb
thawedPath = $SPLUNK_DB/$_index_name/thaweddb

[volume:primary]
path = $SPLUNK_DB
EOF
echo "[OK] Wrote indexes.conf (protected heredoc)"

# -----------------------------------------------------------------------------
# Email domain allowlist (restrict alert emails)
# -----------------------------------------------------------------------------
run "Configure alert_actions email allowedDomainList" bash -c "cat > '$SPLUNK_ETC/system/local/alert_actions.conf' <<'EOF'
[email]
allowedDomainList = mail.mil
EOF"

# -----------------------------------------------------------------------------
# Air-gap hardening
# -----------------------------------------------------------------------------
if [[ "$AIRGAP" -eq 1 ]]; then
  run "Disable splunk_instrumentation app" bash -c "mkdir -p '$SPLUNK_ETC/apps/splunk_instrumentation/local' && cat > '$SPLUNK_ETC/apps/splunk_instrumentation/local/app.conf' <<'EOF'
[install]
state = disabled
[ui]
is_visible = false
EOF"
fi

# -----------------------------------------------------------------------------
# Deployment Server serverclasses
# -----------------------------------------------------------------------------
run "Write serverclass.conf" bash -c "cat > '$SPLUNK_ETC/system/local/serverclass.conf' <<'EOF'
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
# -----------------------------------------------------------------------------
# Banner app (CSS)
# -----------------------------------------------------------------------------
APP_DIR="$SPLUNK_HOME/etc/apps/local_bootstrap"
run "Create banner app directories" mkdir -p "$APP_DIR/appserver/static" "$APP_DIR/default"
run "Write banner app.conf" bash -c "cat > '$APP_DIR/default/app.conf' <<'EOF'
[ui]
is_visible = false
label = Local Bootstrap
[install]
state = enabled
EOF"
run "Write banner CSS" bash -c "cat > '$APP_DIR/appserver/static/bootstrap-banner.css' <<'EOF'
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

# -----------------------------------------------------------------------------
# Deployment Apps for UFs (guaranteed even if RPM step failed)
# -----------------------------------------------------------------------------
run "Ensure deployment-apps root exists" mkdir -p "${DEPLOY}"

# all_deployment_client
run "Create all_deployment_client dirs" mkdir -p "${DEPLOY}/all_deployment_client"/{default,local,metadata}
run "Write all_deployment_client/local/deploymentclient.conf" bash -c "cat > '${DEPLOY}/all_deployment_client/local/deploymentclient.conf' <<EOF
[deployment-client]
clientName = default-client
phoneHomeIntervalInSecs = 600

[target-broker:deploymentServer]
targetUri = ${AIO_IP}:8089
EOF"
run "Write all_deployment_client/default/app.conf" bash -c "cat > '${DEPLOY}/all_deployment_client/default/app.conf' <<'EOF'
[install]
state = enabled
[ui]
is_visible = false
EOF"
run "Write all_deployment_client/metadata/default.meta" bash -c "cat > '${DEPLOY}/all_deployment_client/metadata/default.meta' <<'EOF'
[]
access = read : [ user ], write : [ admin, power ]
export = system
EOF"

# all_outputs
run "Create all_outputs dirs" mkdir -p "${DEPLOY}/all_outputs"/{default,local,metadata}
run "Write all_outputs/local/outputs.conf" bash -c "cat > '${DEPLOY}/all_outputs/local/outputs.conf' <<EOF
[tcpout]
defaultGroup = main
autoLB = true
useACK = true

[tcpout:main]
server = ${AIO_IP}:${S2S_PORT}
compressed = true
forceTimebasedAutoLB = true
EOF"
run "Write all_outputs/default/app.conf" bash -c "cat > '${DEPLOY}/all_outputs/default/app.conf' <<'EOF'
[install]
state = enabled
[ui]
is_visible = false
EOF"
run "Write all_outputs/metadata/default.meta" bash -c "cat > '${DEPLOY}/all_outputs/metadata/default.meta' <<'EOF'
[]
access = read : [ user ], write : [ admin, power ]
export = system
EOF"

# Per-TA default index routing
run "TA_nix default index=linux" bash -c "mkdir -p '${DEPLOY}/Splunk_TA_nix/local' && cat > '${DEPLOY}/Splunk_TA_nix/local/inputs.conf' <<'EOF'
[default]
index = linux
EOF"
run "TA_windows default index=windows" bash -c "mkdir -p '${DEPLOY}/Splunk_TA_windows/local' && cat > '${DEPLOY}/Splunk_TA_windows/local/inputs.conf' <<'EOF'
[default]
index = windows
EOF"
run "TA_sysmon default index=windows" bash -c "mkdir -p '${DEPLOY}/Splunk_TA_microsoft_sysmon/local' && cat > '${DEPLOY}/Splunk_TA_microsoft_sysmon/local/inputs.conf' <<'EOF'
[default]
index = windows
EOF"

# Placeholder TA_syslog
run "Placeholder TA_syslog" mkdir -p "${DEPLOY}/Splunk_TA_syslog/local"

# Ownership
run "Chown configs/apps to splunk" chown -R ${SPLUNK_USER}:${SPLUNK_GROUP} "$SPLUNK_ETC" "$APP_DIR" "$DEPLOY"

# -----------------------------------------------------------------------------
# Service enable/start (systemd-managed is best practice on RHEL 8+) The ds UI issue might be cause by this!
# -----------------------------------------------------------------------------
# NOTE: Changed from systemd-managed to init-style to avoid interfering with Deployment Server UI on some hardened hosts.
run "Enable boot-start (init-style, user=splunk)" \
  runuser -u ${SPLUNK_USER} -- ${SPLUNK_HOME}/bin/splunk enable boot-start -user ${SPLUNK_USER} --accept-license --answer-yes

run "Start Splunk" \
  runuser -u ${SPLUNK_USER} -- ${SPLUNK_HOME}/bin/splunk start --accept-license --answer-yes

# Optional: log Splunkd limits as sanity check (if running)
if [ -f "$SPLUNK_HOME/var/run/splunk/splunkd.pid" ]; then
  spid="$(head -1 "$SPLUNK_HOME/var/run/splunk/splunkd.pid" 2>/dev/null || true)"
  if [ -n "${spid:-}" ] && [ -r "/proc/$spid/limits" ]; then
    echo "[INFO] Current Splunkd /proc/$spid/limits:"
    sed 's/^/  /' "/proc/$spid/limits" || true
  fi
fi
# -----------------------------------------------------------------------------
# Ensure Deployment Server (Forwarder Management UI) is enabled and reachable
# -----------------------------------------------------------------------------
# Create a minimal serverclass.conf if missing (UI expects a valid file)
if [ ! -s "$SPLUNK_ETC/system/local/serverclass.conf" ]; then
  echo "[INFO] serverclass.conf missing; creating a minimal baseline." | tee -a "$LOGFILE"
  cat > "$SPLUNK_ETC/system/local/serverclass.conf" <<'EOF'
# Minimal baseline so Forwarder Management UI can initialize
[serverClass:All_agents]
whitelist.0 = .*
EOF
  chown ${SPLUNK_USER}:${SPLUNK_GROUP} "$SPLUNK_ETC/system/local/serverclass.conf" || true
fi
# Enable the deployment server (idempotent; safe to rerun)
run "Enable Deployment Server (Forwarder Management)" \
  runuser -u ${SPLUNK_USER} -- ${SPLUNK_HOME}/bin/splunk enable deploy-server --accept-license --answer-yes
# Reload the DS to pick up any changes
run "Reload Deployment Server" \
  runuser -u ${SPLUNK_USER} -- ${SPLUNK_HOME}/bin/splunk reload deploy-server
# Operator visibility
echo "Splunk Deployment Server UI is up" | tee -a "$LOGFILE"
#
# -----------------------------------------------------------------------------
# Firewalld (optional)
# -----------------------------------------------------------------------------
if command -v firewall-cmd >/dev/null 2>&1; then
  run "Open firewall port ${WEB_PORT}" firewall-cmd --permanent --add-port=${WEB_PORT}/tcp
  run "Open firewall port ${S2S_PORT}" firewall-cmd --permanent --add-port=${S2S_PORT}/tcp
  run "Open firewall port ${SYSLOG_SSL_PORT}" firewall-cmd --permanent --add-port=${SYSLOG_SSL_PORT}/tcp
  run "Reload firewalld" firewall-cmd --reload
  # Additional Splunk ports (SHC 8065, Mgmt 8089, custom 8189)
  run "Open firewall port ${SHC_PORT}" firewall-cmd --permanent --add-port=${SHC_PORT}/tcp
  run "Open firewall port ${MNGT_PORT}" firewall-cmd --permanent --add-port=${MNGT_PORT}/tcp
  run "Open firewall port 8189" firewall-cmd --permanent --add-port=8189/tcp
  run "Reload firewalld (post-extra-ports)" firewall-cmd --reload
  # Verify ports are open
  if firewall-cmd --list-ports | grep -q ${WEB_PORT}/tcp; then
    echo "[OK] Firewall port ${WEB_PORT} is open"
  else
    echo "[WARN] Firewall port ${WEB_PORT} not open"
  fi
  if firewall-cmd --list-ports | grep -q ${S2S_PORT}/tcp; then
    echo "[OK] Firewall port ${S2S_PORT} is open"
  else
    echo "[WARN] Firewall port ${S2S_PORT} not open"
  fi
  if firewall-cmd --list-ports | grep -q ${SYSLOG_SSL_PORT}/tcp; then
    echo "[OK] Firewall port ${SYSLOG_SSL_PORT} is open"
  else
    echo "[WARN] Firewall port ${SYSLOG_SSL_PORT} not open"
  fi
  if firewall-cmd --list-ports | grep -q ${SHC_PORT}/tcp; then
    echo "[OK] Firewall port ${SHC_PORT} is open"
  else
    echo "[WARN] Firewall port ${SHC_PORT} not open"
  fi
  if firewall-cmd --list-ports | grep -q ${MNGT_PORT}/tcp; then
    echo "[OK] Firewall port ${MNGT_PORT} is open"
  else
    echo "[WARN] Firewall port ${MNGT_PORT} not open"
  fi
  if firewall-cmd --list-ports | grep -q 8189/tcp; then
    echo "[OK] Firewall port 8189 is open"
  else
    echo "[WARN] Firewall port 8189 not open"
  fi
fi
# -----------------------------------------------------------------------------
# Maintenance & retention sidecars
# -----------------------------------------------------------------------------
run "Install daily chown cron" bash -c "cat > /etc/cron.daily/splunk-ownership <<'EOF'
#!/usr/bin/env bash
chown -R splunk:splunk /opt/splunk
EOF
chmod 755 /etc/cron.daily/splunk-ownership"

run "Install logrotate for bootstrap log" bash -c "cat > /etc/logrotate.d/splkbootstrap <<'EOF'
/var/log/splkbootstrap.log {
  weekly
  rotate 8
  compress
  missingok
  notifempty
  copytruncate
}
EOF"

run "Install daily 365d mover (no-op without NAS)" bash -c "cat > /etc/cron.daily/splunk-365d-mover <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
NAS_DIR="/mnt/splunk_nas/splunk_archive"
SRC_DIR="/opt/splunk/var/log"
[ -d "$NAS_DIR" ] || exit 0
[ -d "$SRC_DIR" ] || exit 0
find "$SRC_DIR" -type f -mtime +365 -print0 | xargs -0 -I{} rsync -a "{}" "$NAS_DIR"/
find "$SRC_DIR" -type f -mtime +365 -delete
EOF
chmod 755 /etc/cron.daily/splunk-365d-mover"

run "Install weekly /opt/splunk backup" bash -c "mkdir -p /opt/build/backups && chown -R ${SPLUNK_USER}:${SPLUNK_GROUP} /opt/build/backups && cat > /etc/cron.weekly/splunk-weekly-backup <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
BACKUP_ROOT="/opt/build/backups"
SRC="/opt/splunk"
STAMP="$(date +%Y%m%d)"
OUT="${BACKUP_ROOT}/splunk-${STAMP}.tgz"
mkdir -p "$BACKUP_ROOT"
tar -czf "$OUT" -C / opt/splunk
ls -1t ${BACKUP_ROOT}/splunk-*.tgz | tail -n +7 | xargs -r rm -f
chown splunk:splunk "$OUT" || true
EOF
chmod 755 /etc/cron.weekly/splunk-weekly-backup"

# -----------------------------------------------------------------------------
# THP — Recommended persistence (kernel arg) + fallback + runtime
# -----------------------------------------------------------------------------
echo "[*] THP hardening: checking current state and persistence..."
for f in /sys/kernel/mm/transparent_hugepage/enabled /sys/kernel/mm/transparent_hugepage/defrag; do
  if [ -r "$f" ]; then
    state="$(cat "$f" 2>/dev/null || true)"
    if [[ "$state" != *"[never]"* ]]; then
      run "Set THP $(basename "$f") to 'never' (runtime)" bash -c "echo never > '$f'"
    else
      echo "[OK] THP $(basename "$f") already set to 'never' at runtime"
    fi
  else
    echo "[INFO] THP control $f not present on this kernel — skipping runtime set."
  fi
done

THP_UNIT="/etc/systemd/system/disable-thp.service"
if [ ! -f "$THP_UNIT" ]; then
  run "Install systemd disable-thp.service" bash -c "cat > '$THP_UNIT' <<'EOF'
[Unit]
Description=Disable Transparent Huge Pages (THP) at boot
After=multi-user.target

[Service]
Type=oneshot
ExecStart=/usr/bin/bash -lc 'for f in /sys/kernel/mm/transparent_hugepage/enabled /sys/kernel/mm/transparent_hugepage/defrag; do [ -w \"$f\" ] && echo never > \"$f\" || true; done'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF"
  run "Reload systemd for THP unit" systemctl daemon-reload
  run "Enable & start THP unit now" systemctl enable --now disable-thp.service
else
  echo "[OK] THP systemd unit already present"
  run "Ensure THP unit enabled" systemctl enable --now disable-thp.service
fi

if grep -qw "transparent_hugepage=never" /proc/cmdline 2>/dev/null; then
  echo "[OK] Kernel cmdline already has transparent_hugepage=never (active after next reboot)"
else
  if command -v grubby >/dev/null 2>&1; then
    if ! grubby --info=ALL 2>/dev/null | grep -qw "transparent_hugepage=never"; then
      run "Persist THP=never via grubby (all kernels)" grubby --update-kernel=ALL --args="transparent_hugepage=never"
    else
      echo "[OK] grubby shows transparent_hugepage=never already configured for kernels"
    fi
  else
    echo "[INFO] grubby not found; using /etc/default/grub fallback."
    GRUB_DEFAULT="/etc/default/grub"
    if [ -f "$GRUB_DEFAULT" ]; then
      if ! grep -q 'transparent_hugepage=never' "$GRUB_DEFAULT"; then
        run "Add THP=never to GRUB_CMDLINE_LINUX" \
          bash -c "sed -i 's/^GRUB_CMDLINE_LINUX=\"/&transparent_hugepage=never /' '$GRUB_DEFAULT'"
        if [ -d /sys/firmware/efi ]; then
          run "Rebuild GRUB (UEFI)" grub2-mkconfig -o /boot/efi/EFI/redhat/grub.cfg
        fi
        if [ -d /boot/grub2 ] || [ -f /boot/grub2/grub.cfg ]; then
          run "Rebuild GRUB (BIOS)" grub2-mkconfig -o /boot/grub2/grub.cfg
        fi
      else
        echo "[OK] /etc/default/grub already contains transparent_hugepage=never"
      fi
    else
      echo "[WARN] /etc/default/grub not found; cannot set kernel arg via fallback."
    fi
  fi
fi

# -----------------------------------------------------------------------------
# Publish DS content & final restart
# -----------------------------------------------------------------------------
run "Reload Deployment Server" runuser -u ${SPLUNK_USER} -- ${SPLUNK_HOME}/bin/splunk reload deploy-server
run "Restart Splunk" runuser -u ${SPLUNK_USER} -- ${SPLUNK_HOME}/bin/splunk restart

echo "=== Splunk Bootstrap finished at $(date -Is). Review ${LOGFILE} for any WARN entries. ==="
