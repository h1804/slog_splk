#!/usr/bin/env bash
# Splunk Prep Script for RHEL 8.10
# -----------------------------------------------------------------------------
# Minimal dependencies (only install missing)
# -----------------------------------------------------------------------------

# ===== runtime + logging helpers =====
set -uo pipefail

# Log everything to a file and the console
LOGFILE="/var/log/prepsplk.log"
mkdir -p "$(dirname "$LOGFILE")"
touch "$LOGFILE"
exec > >(tee -a "$LOGFILE") 2>&1

# Require root (dnf, systemd, etc. need it)
if [[ $EUID -ne 0 ]]; then
  echo "[ERROR] Please run as root (sudo)."
  exit 1
fi

# run "Description" <command> [args...]
# - Captures stdout+stderr
# - Prints [OK]/[FAIL]
# - Shows full command output between markers
# - Returns the command's exit code (script keeps going since we don't use `set -e`)
run() {
  local desc="$1"; shift
  echo "[*] ${desc}..."
  local tmp rc
  tmp="$(mktemp /tmp/run.$$.XXXX)"
  if "$@" >"$tmp" 2>&1; then
    rc=0
    echo "[OK] ${desc}"
  else
    rc=$?
    echo "[FAIL] ${desc} (rc=${rc})"
  fi
  echo "--- BEGIN OUTPUT: ${desc} ---"
  sed -e 's/\x1b\[[0-9;]*[A-Za-z]//g' "$tmp"
  echo "--- END OUTPUT: ${desc} ---"
  rm -f "$tmp"
  return "$rc"
}

# ===== variables =====
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
SHC_PORT="8065"
LOCAL_KV_STORE_PORT="8191"
SYSLOG_SSL_PORT="6514"
AIO_IP="192.168.1.191"

NAS_MOUNT="/mnt/splunk_nas"
ARCHIVE_DIR="${NAS_MOUNT}/splunk_archive"
AIRGAP=1
FROZEN_SECS=$((365*24*60*60)) # 365 days

# -----------------------------------------------------------------------------
# Minimal deps
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
# Firewall & SELinux exceptions for Splunk / Syslog ports
# -----------------------------------------------------------------------------
# Open ports in firewalld (ingress). If egress filtering is enabled in your env,
# handle that separately with your network policy.
if command -v firewall-cmd >/dev/null 2>&1; then
  run "Open firewall ports 9997, 8443, 8056, 6514, 8191, 8089, 514/tcp and 514/udp" bash -lc '
    for p in 9997 8443 8056 6514 8191 8089 514; do
      firewall-cmd --permanent --add-port=${p}/tcp || true
    done
    firewall-cmd --permanent --add-port=514/udp || true
    firewall-cmd --reload
  '
else
  echo "[WARN] firewalld not found; skipping firewall rules."
fi

# Allow SELinux to treat these ports as acceptable bindings for Splunk/syslog.
# (This does not weaken SELinux; it just labels the ports appropriately.)
if command -v semanage >/dev/null 2>&1 && selinuxenabled; then
  run "SELinux: allow Splunk Web/UI on 8443, 8056, 8089" bash -lc '
    for p in 8443 8056 8089; do
      semanage port -a -t http_port_t -p tcp $p 2>/dev/null || semanage port -m -t http_port_t -p tcp $p || true
    done
  '
  run "SELinux: allow syslog on 514/tcp, 514/udp, 6514/tcp" bash -lc '
    semanage port -a -t syslogd_port_t -p tcp 514  2>/dev/null || semanage port -m -t syslogd_port_t -p tcp 514  || true
    semanage port -a -t syslogd_port_t -p udp 514  2>/dev/null || semanage port -m -t syslogd_port_t -p udp 514  || true
    semanage port -a -t syslogd_port_t -p tcp 6514 2>/dev/null || semanage port -m -t syslogd_port_t -p tcp 6514 || true
  '
  run "SELinux: allow Splunk services on 9997 (S2S), 8191 (KV)" bash -lc '
    for p in 9997 8191; do
      # If a Splunk-specific port type exists on your system, use that instead.
      semanage port -a -t unreserved_port_t -p tcp $p 2>/dev/null || semanage port -m -t unreserved_port_t -p tcp $p || true
    done
  '
else
  echo "[WARN] SELinux tools not available or SELinux disabled; skipping SELinux port labeling."
fi

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
ExecStart=/usr/bin/bash -lc 'for f in /sys/kernel/mm/transparent_hugepage/enabled /sys/kernel/mm/transparent_hugepage/defrag; do [ -w "$f" ] && echo never > "$f" || true; done'
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

echo "[OK] THP hardening complete."

# -----------------------------------------------------------------------------
# Maintenance & retention sidecars
# -----------------------------------------------------------------------------
run "Install daily chown cron" bash -c "cat > /etc/cron.daily/splunk-ownership <<'EOF'
#!/usr/bin/env bash
chown -R splunk:splunk /opt/splunk
EOF"
run "chmod daily chown cron" chmod 755 /etc/cron.daily/splunk-ownership

run "Install logrotate for prep log" bash -c "cat > /etc/logrotate.d/prepsplk <<'EOF'
/var/log/prepsplk.log {
  weekly
  rotate 8
  compress
  missingok
  notifempty
  copytruncate
}
EOF"

echo "=== Splunk Prep finished at $(date -Is). Review ${LOGFILE} for any WARN entries. ==="
