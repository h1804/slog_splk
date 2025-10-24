#!/usr/bin/env bash
# syslog-senders.sh
# Show hosts sending logs to this rsyslog server.
# - Lists known senders from /var/log/{cisco,nas}/<hostname> directories
# - Shows recent senders (files written in the last N minutes; default 15)
# - Shows active TCP senders (currently connected to 514/6514)
#
# Usage:
#   syslog-senders.sh                 # default summary
#   syslog-senders.sh --recent 30     # change recent window (minutes)
#   syslog-senders.sh --known         # only known senders (ever wrote)
#   syslog-senders.sh --active        # only active TCP connections
#   syslog-senders.sh --all           # known + recent + active
#   syslog-senders.sh --help
#
# RHEL 8/9 compatible. Requires: find, awk, sort, uniq, ss (iproute).

set -euo pipefail

LOG_ROOTS=(/var/log/cisco /var/log/nas)
RECENT_MIN=15
MODE="default"  # default | known | active | all

while [[ $# -gt 0 ]]; do
  case "$1" in
    --recent) RECENT_MIN="${2:-15}"; shift 2 ;;
    --known)  MODE="known"; shift ;;
    --active) MODE="active"; shift ;;
    --all)    MODE="all"; shift ;;
    --help|-h)
      sed -n '1,40p' "$0" | sed -n '1,/^set -euo pipefail/p' | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

exists_any() {
  local found=1
  for d in "${LOG_ROOTS[@]}"; do
    [[ -d "$d" ]] && found=0 && break
  done
  return $found
}

print_header() {
  echo
  echo "===== $1 ====="
}

known_senders() {
  # Any host that has ever written a file (host dir exists)
  for root in "${LOG_ROOTS[@]}"; do
    [[ -d "$root" ]] || continue
    find "$root" -mindepth 1 -maxdepth 1 -type d -printf "%f\n"
  done | sort -u
}

recent_senders() {
  # Any host with files updated in the last RECENT_MIN minutes
  for root in "${LOG_ROOTS[@]}"; do
    [[ -d "$root" ]] || continue
    # Print the parent dir (host) of updated files
    find "$root" -type f -mmin "-${RECENT_MIN}" -printf "%h\n" 2>/dev/null \
      | awk -F'/' '{print $(NF-1)}'
  done | sort -u
}

active_tcp_senders() {
  # Current TCP connections to 514/6514
  if ! command -v ss >/dev/null 2>&1; then
    echo "(ss not found)" && return 0
  fi
  ss -tn state established '( sport = :514 or sport = :6514 )' \
    | awk 'NR>1 {split($5,a,":"); print a[1]}' | sort -u
}

show_list() {
  local title="$1"; shift
  local data
  data="$("$@")" || true
  print_header "$title"
  if [[ -n "${data//$'\n'/}" ]]; then
    echo "$data"
  else
    echo "(none)"
  fi
}

if ! exists_any; then
  echo "No log roots found: ${LOG_ROOTS[*]}"
  echo "Make sure rsyslog has created /var/log/cisco and/or /var/log/nas."
  exit 0
fi

case "$MODE" in
  default)
    show_list "Known senders (have written at least once)" known_senders
    show_list "Recent senders (last ${RECENT_MIN} minutes)" recent_senders
    show_list "Active TCP senders (connected now to 514/6514)" active_tcp_senders
    ;;
  known)
    show_list "Known senders (have written at least once)" known_senders
    ;;
  active)
    show_list "Active TCP senders (connected now to 514/6514)" active_tcp_senders
    ;;
  all)
    show_list "Known senders (have written at least once)" known_senders
    show_list "Recent senders (last ${RECENT_MIN} minutes)" recent_senders
    show_list "Active TCP senders (connected now to 514/6514)" active_tcp_senders
    ;;
esac

echo
echo "Tip: adjust the recent window:  syslog-senders.sh --recent 30"
