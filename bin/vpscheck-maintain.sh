#!/usr/bin/env bash
set -uo pipefail
umask 077
source /etc/vpscheckreport/config
exec 9>/run/vpscheckreport.lock
flock -n 9 || exit 0
mkdir -p /var/log/vpscheckreport
ROOT=/var/log/vpscheckreport
ST="$(date +%Y%m%d-%H%M%S)"
LOG="$ROOT/update-$ST.log";BODY="$ROOT/daily-$ST.txt"
UPDATE=SUCCESS
{
 echo "Ubuntu system updates: $(hostname)"
 if [[ "${RUN_UPDATES:-true}" == true ]];then
  export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a APT_LISTCHANGES_FRONTEND=none
  if apt-get -o DPkg::Lock::Timeout=1800 update;then
   apt-get -o DPkg::Lock::Timeout=1800 -o Dpkg::Options::='--force-confold' -y dist-upgrade || UPDATE=FAILED
  else UPDATE=FAILED;fi
  apt-get -o DPkg::Lock::Timeout=1800 -y autoremove || UPDATE=FAILED
  apt-get clean || UPDATE=FAILED
 else echo 'Updates disabled';fi
 echo "Update: $UPDATE"
 [[ -e /run/reboot-required ]] && echo 'Reboot: YES' || echo 'Reboot: NO'
} > "$LOG" 2>&1
/usr/local/sbin/vpscheck-audit >/dev/null 2>&1;AUDIT_RC=$?
{
 echo "VPSCheckReport: $(hostname)";echo "Beijing: $(TZ=Asia/Shanghai date '+%F %T')"
 echo "System update: $UPDATE";echo "Audit execution status: $AUDIT_RC"
 echo '===== UPDATE =====';cat "$LOG"
 echo '===== SECURITY ====='
 if [[ -r /var/lib/vpscheckreport/latest-audit.txt ]];then cat /var/lib/vpscheckreport/latest-audit.txt
 else echo 'AUDIT ERROR: no report';fi
} > "$BODY"
SUBJECT="Ubuntu daily maintenance - $(hostname) - $UPDATE"
/usr/local/lib/vpscheckreport/mail-send.py --subject "$SUBJECT" --body "$BODY"
MAIL_RC=$?
find "$ROOT" -type f -mtime +30 -delete 2>/dev/null || true
((MAIL_RC==0 && AUDIT_RC==0)) && [[ "$UPDATE" == SUCCESS ]]
