#!/usr/bin/env bash
# Daily ACL updater for /var/log/*
# Ensures logreader and splunkfwd can read/write logs
# Success → /var/log/Rsyslog_run.log
# Failure → /var/log/Rsyslog_Error.log

set -euo pipefail

RUN_LOG="/var/log/Rsyslog_run.log"
ERR_LOG="/var/log/Rsyslog_Error.log"

{
    echo "[INFO] $(date -Is) Starting ACL update for /var/log"

    # Apply ACLs
    setfacl -R -m u:logreader:rwX /var/log
    setfacl -R -m u:splunkfwd:rwX /var/log

    # Ensure defaults for new files
    setfacl -R -d -m u:logreader:rwX /var/log
    setfacl -R -d -m u:splunkfwd:rwX /var/log

    echo "[OK] $(date -Is) ACLs applied successfully to /var/log"
} >>"$RUN_LOG" 2>>"$ERR_LOG"
