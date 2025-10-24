#!/usr/bin/env bash
# rsyslogbootscript.sh
# Bootstrap rsyslog on RHEL 8.10 for centralized logging
# *** CONFIGURED FOR CLEARTEXT UDP 514 ONLY ***

set -euo pipefail

echo "[*] Starting rsyslog bootstrap on $(date -Is)"

# Variable for main config file
CONFIG_FILE="/etc/rsyslog.conf"

# -------------------------------------------------------------------
# Install rsyslog if missing
# -------------------------------------------------------------------
if ! rpm -q rsyslog >/dev/null 2>&1; then
  echo "[*] Installing rsyslog..."
  # dnf install is critical, so we allow termination if this fails
  dnf -y install rsyslog policycoreutils-python-utils
fi

systemctl enable rsyslog

# -------------------------------------------------------------------
# Directories for Logs and Queues
# -------------------------------------------------------------------
# Create standard directories
mkdir -p /var/log/cisco /var/log/nas /var/log/misc /var/spool/rsyslog/queues
chown root:root /var/log/cisco /var/log/nas /var/log/misc
chmod 750 /var/log/cisco /var/log/nas /var/log/misc

# FIX: Set SELinux context for custom log directories (Script-managed)
echo "[*] Setting SELinux contexts for custom log directories..."
semanage fcontext -a -t var_log_t "/var/log/(cisco|nas|misc)(/.*)?" || true
restorecon -R -v /var/log/ || true

# FIX: Set SELinux context for the problematic external logging path
echo "[*] Setting SELinux contexts for external log path /opt/data/syslog..."
mkdir -p /opt/data/syslog || true # Ensure the parent directory exists
semanage fcontext -a -t var_log_t "/opt/data/syslog(/.*)?" || true
restorecon -R -v /opt/data/syslog || true

# -------------------------------------------------------------------
# User Creation for ACLs
# -------------------------------------------------------------------
echo "[*] Creating splunkfwd user for ACLs..."
useradd -r -s /sbin/nologin splunkfwd 2>/dev/null || true

# -------------------------------------------------------------------
# 1. Rsyslog configuration - Internal Logs (Priority 00)
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
# Restore context for these specific files as well
restorecon -v /var/log/Rsyslog_*.log || true

# -------------------------------------------------------------------
# 2. Rsyslog configuration - NAS (Priority 10)
# -------------------------------------------------------------------
cat > /etc/rsyslog.d/10-nas-only.conf <<'EOF'
# Template for NAS logs
template(name="nasFile" type="string"
         string="/var/log/nas/%HOSTNAME%/nas.log")

# Ruleset for NAS logs
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

# NAS IP filter: If a message is from 38.38.1.2, call the NAS ruleset and STOP further processing.
if ($fromhost-ip == "38.38.1.2") then {
  call rsNAS
  stop
}
EOF

# -------------------------------------------------------------------
# 3. Rsyslog configuration - Cisco Inputs (Priority 20)
# -------------------------------------------------------------------
# This file handles all network inputs and the Cisco processing logic
cat > /etc/rsyslog.d/20-cisco-inputs.conf <<'EOF'
# Load only imudp module for UDP reception
module(load="imudp")

# REMOVED: $workingDirectory directive from here. It will be added to /etc/rsyslog.conf

# Template for Cisco logs
template(name="ciscoFile" type="string"
         string="/var/log/cisco/%HOSTNAME%/cisco.log")

# Ruleset for Cisco logs
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

# --- Network Inputs ---

# UDP 514
input(type="imudp" port="514" ruleset="rsCisco"
      rateLimit.Interval="1" rateLimit.Burst="20000")

# REMOVED: TCP 514 and TLS 6514 configuration blocks
EOF

# -------------------------------------------------------------------
# 4. Rsyslog configuration - Miscellaneous Catch-All (Priority 99)
# -------------------------------------------------------------------
cat > /etc/rsyslog.d/99-misc-catchall.conf <<'EOF'
# -------------------------------------------------------------------
# Miscellaneous/Catch-All Configuration
# This file processes logs that are NOT NAS (38.38.1.2 is stopped in 10-nas-only.conf).
# -------------------------------------------------------------------

# Template for Miscellaneous logs
template(name="miscFile" type="string"
         string="/var/log/misc/%HOSTNAME%/misc.log")

# Ruleset for Miscellaneous logs
ruleset(name="rsMisc") {
  action(type="omfile"
         dynaFile="miscFile"
         DirCreateMode="0750"
         FileCreateMode="0640"
         FileOwner="root"
         FileGroup="root"
         queue.type="LinkedList"
         queue.filename="misc"
         queue.spoolDirectory="/var/spool/rsyslog"
         queue.maxdiskspace="1g"
         queue.size="20000"
         action.resumeRetryCount="-1")
}

# The NAS traffic (38.38.1.2) is already stopped in 10-nas-only.conf.
# Check if the IP address DOES NOT start with "1.1." (Cisco network)
if not ($fromhost-ip startswith "1.1.") then {
  call rsMisc
  stop # Stop processing this message after it's logged by misc ruleset
}
EOF

# -------------------------------------------------------------------
# 5. Global Fix: Insert $workingDirectory into Main Config
# -------------------------------------------------------------------
echo "[*] Inserting \$workingDirectory directive into ${CONFIG_FILE}..."
# Use sed to insert the line after the standard RHEL 8 boilerplate config
# This ensures it's parsed before any other module loads or rulesets.
sed -i '/$IncludeConfig/i$workingDirectory /var/spool/rsyslog' "$CONFIG_FILE"

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
# SELinux + Firewall (Rerun SELinux port config for safety)
# -------------------------------------------------------------------
# Firewall commands are typically safe, but use || true just in case
firewall-cmd --permanent --add-port=514/udp || true
firewall-cmd --reload || true

# -------------------------------------------------------------------
# AIDE Configuration Exceptions (Wrap block in condition)
# -------------------------------------------------------------------
if [ -f /etc/aide.conf ]; then
    echo "[*] Adding AIDE configuration exceptions for rsyslog directories..."

    # Define a rule for logs: Only monitor metadata/permissions, ignore content/size changes
    AIDE_RULES_TO_ADD=$(cat <<'EOF'
# -------------------------------------------------------------------
# Custom Rsyslog Rules (Added by Bootstrap Script)
# -------------------------------------------------------------------
# PermsOnly: Only check permissions, owner, group, inode, SELinux context.
# Ignores content, size, and time changes for frequently written log files.
PermsOnly = p+i+u+g+selinux+!n+!s+!b+!m+!c+!a+!sha512

# Apply PermsOnly rule to the log directories and files
/var/log/cisco$   PermsOnly
/var/log/nas$     PermsOnly
/var/log/misc$    PermsOnly
/var/log/Rsyslog_Error\.log$ PermsOnly
/var/log/Rsyslog_run\.log$   PermsOnly

# Apply PermsOnly rule to the dynamic log paths (subdirectories)
/var/log/cisco/.* PermsOnly
/var/log/nas/.* PermsOnly
/var/log/misc/.* PermsOnly

# Exclude the rsyslog spool/queue directory entirely, as it holds high-churn temporary queue files
!/var/spool/rsyslog$
!/var/spool/rsyslog/.*
EOF
)
    # Append the rules
    echo "$AIDE_RULES_TO_ADD" >> /etc/aide.conf
    
    # Update the AIDE database if it exists
    if command -v aide >/dev/null 2>&1; then
        echo "[*] Updating AIDE database with new configuration..."
        
        /usr/sbin/aide --update || true # Allow initial update to fail gracefully
        
        # Move the new database into place
        if [ -f /var/lib/aide/aide.db.new.gz ]; then
            mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
            echo "[*] AIDE database updated successfully."
        else
            echo "[!] AIDE database was not created/updated. Manual intervention may be required."
        fi
    fi
fi

# -------------------------------------------------------------------
# Restart rsyslog
# -------------------------------------------------------------------
systemctl restart rsyslog
systemctl status rsyslog --no-pager || true

echo "[OK] rsyslog bootstrap completed."