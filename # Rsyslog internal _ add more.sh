# Rsyslog internal diagnostics
syslog.err;syslog.warning    /var/log/Rsyslog_Error.log
syslog.info;syslog.notice;syslog.debug    /var/log/Rsyslog_run.log
& stop

# 10-firewall.conf - Direct firewalld log entries containing "FIREWALL_ACCESS" to a separate file.
:msg, contains, "FIREWALL_ACCESS" /var/log/localfirewall.log
& stop

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



