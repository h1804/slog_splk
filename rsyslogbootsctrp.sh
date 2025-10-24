#!/usr/bin/env bash
# rsyslogbootscript.sh
# Bootstrap rsyslog on RHEL 8.10 for Cisco + NAS logging
# - Collect Cisco logs (UDP 514, TCP 514, TLS 6514)
# - Collect NAS logs (from 1.1.1.45) separately
# - Create dedicated rsyslog error/run logs
# - Setup ACLs so logreader + splunkfwd can access logs
# - Configure SELinux + firewalld for ports

set -euo pipefail

echo "[*] Starting rsyslog bootstrap on $(date -Is)"

# -------------------------------------------------------------------
# Install rsyslog if missing
# -------------------------------------------------------------------
if ! rpm -q rsyslog >/dev/null 2>&1; then
  echo "[*] Installing rsyslog..."
  dnf -y install rsyslog
fi

systemctl enable rsyslog

# -------------------------------------------------------------------
# Directories for Cisco + NAS logs
# -------------------------------------------------------------------
mkdir -p /var/log/cisco /var/log/nas /var/spool/rsyslog/queues
chown root:root /var/log/cisco /var/log/nas
chmod 750 /var/log/cisco /var/log/nas

# -------------------------------------------------------------------
# Rsyslog configuration (Cisco + NAS + TLS)
# -------------------------------------------------------------------
cat > /etc/rsyslog.d/10-cisco-nas.conf <<'EOF'
global(workDirectory="/var/spool/rsyslog")

module(load="imudp")
module(load="imtcp")

# Templates
template(name="ciscoFile" type="string"
         string="/var/log/cisco/%HOSTNAME%/cisco.log")
template(name="nasFile" type="string"
         string="/var/log/nas/%HOSTNAME%/nas.log")

# Rulesets
ruleset(name="rsCisco") {
  action(type="omfile"
         dynaFile="ciscoFile"
         DirCreateMode="0750"
         FileCreateMode="0640"
         FileOwner="root"
         FileGroup="root"
         queue.type="LinkedList"
         queue.filename="cisco"
         queue.spoolDirectory="/var/spool/rsyslog"
         queue.maxdiskspace="1g"
         queue.size="20000"
         action.resumeRetryCount="-1")
}

ruleset(name="rsNAS") {
  action(type="omfile"
         dynaFile="nasFile"
         DirCreateMode="0750"
         FileCreateMode="0640"
         FileOwner="root"
         FileGroup="root"
         queue.type="LinkedList"
         queue.filename="nas"
         queue.spoolDirectory="/var/spool/rsyslog"
         queue.maxdiskspace="1g"
         queue.size="20000"
         action.resumeRetryCount="-1")
}

# Inputs
input(type="imudp" port="514" ruleset="rsCisco"
      rateLimit.Interval="1" rateLimit.Burst="20000")

input(type="imtcp" port="514" ruleset="rsCisco" MaxSessions="1000")

# TLS 6514
global(
  defaultNetstreamDriverCAFile="/etc/pki/tls/certs/ca-bundle.crt"
  defaultNetstreamDriverCertFile="/etc/rsyslog.d/tls/server.crt"
  defaultNetstreamDriverKeyFile="/etc/rsyslog.d/tls/server.key"
)

input(type="imtcp"
      port="6514"
      ruleset="rsCisco"
      StreamDriver.Name="gtls"
      StreamDriver.Mode="1"
      StreamDriver.AuthMode="anon"
      MaxSessions="2000")

# NAS IP filter
if ($fromhost-ip == "1.1.1.45") then {
  call rsNAS
  stop
}
EOF

# -------------------------------------------------------------------
# Internal rsyslog error/run separation
# -------------------------------------------------------------------
cat > /etc/rsyslog.d/00-rsyslog-internal.conf <<'EOF'
# Rsyslog internal diagnostics
syslog.err;syslog.warning    /var/log/Rsyslog_Error.log
syslog.info;syslog.notice;syslog.debug    /var/log/Rsyslog_run.log
& stop
EOF

# Create error/run logs with correct perms
touch /var/log/Rsyslog_Error.log /var/log/Rsyslog_run.log
chown root:root /var/log/Rsyslog_*.log
chmod 0640 /var/log/Rsyslog_*.log

# -------------------------------------------------------------------
# Cron.daily ACL updater
# -------------------------------------------------------------------
cat > /etc/cron.daily/log-acl-update <<'EOF'
#!/usr/bin/env bash
# Daily ACL updater for /var/log/*
# Grants logreader and splunkfwd RWX permissions
# Success → /var/log/Rsyslog_run.log
# Failure → /var/log/Rsyslog_Error.log

set -euo pipefail
RUN_LOG="/var/log/Rsyslog_run.log"
ERR_LOG="/var/log/Rsyslog_Error.log"

{
    echo "[INFO] $(date -Is) Applying ACLs to /var/log"

    setfacl -R -m u:logreader:rwX /var/log
    setfacl -R -m u:splunkfwd:rwX /var/log
    setfacl -R -d -m u:logreader:rwX /var/log
    setfacl -R -d -m u:splunkfwd:rwX /var/log

    echo "[OK] $(date -Is) ACLs applied successfully"
} >>"$RUN_LOG" 2>>"$ERR_LOG"
EOF
chmod 755 /etc/cron.daily/log-acl-update

# -------------------------------------------------------------------
# SELinux + Firewall
# -------------------------------------------------------------------
semanage port -a -t syslogd_port_t -p tcp 6514 2>/dev/null || \
semanage port -m -t syslogd_port_t -p tcp 6514

firewall-cmd --permanent --add-port=514/udp
firewall-cmd --permanent --add-port=514/tcp
firewall-cmd --permanent --add-port=6514/tcp
firewall-cmd --reload

# -------------------------------------------------------------------
# Restart rsyslog
# -------------------------------------------------------------------
systemctl restart rsyslog
systemctl status rsyslog --no-pager || true # Ignore errors

echo "[OK] rsyslog bootstrap completed."
