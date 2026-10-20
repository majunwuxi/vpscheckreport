#!/usr/bin/env bash
set -uo pipefail
umask 077
[[ -r /etc/vpscheckreport/config ]] && source /etc/vpscheckreport/config
[[ -r /etc/vpscheckreport/audit.conf ]] && source /etc/vpscheckreport/audit.conf

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a
export APT_LISTCHANGES_FRONTEND=none

HOST_NAME="$(hostname -f 2>/dev/null || hostname)"
DATE_CN="$(TZ=Asia/Shanghai date '+%F')"
TIME_CN="$(TZ=Asia/Shanghai date '+%H%M%S')"
LOG_DIR='/var/log/vpscheckreport'
UPDATE_LOG="$LOG_DIR/apt-upgrade-${DATE_CN}-${TIME_CN}.log"
MAIL_BODY="$LOG_DIR/daily-maintenance-${DATE_CN}-${TIME_CN}.mail.txt"
LOCK_FILE='/run/vpscheckreport.lock'
AUDIT_SCRIPT='/usr/local/sbin/vpscheck-audit'
AUDIT_ENV='/var/lib/vpscheckreport/audit/latest.env'
AUDIT_TIMEOUT_SECONDS="${AUDIT_TIMEOUT_SECONDS:-240}"
[[ "$AUDIT_TIMEOUT_SECONDS" =~ ^[0-9]+$ ]] || AUDIT_TIMEOUT_SECONDS=240
STATUS=0
REBOOT_REQUIRED=0
AUDIT_PROGRAM_ERROR=0
AUDIT_STATUS='UNKNOWN'
AUDIT_PASS=0
AUDIT_WARN=0
AUDIT_FAIL=0
AUDIT_CHANGES=0
AUDIT_MAIL=''
mkdir -p "$LOG_DIR"; chmod 700 "$LOG_DIR"

exec 9>"$LOCK_FILE"
if ! flock -n 9; then
    echo '另一个 daily-apt-upgrade 任务正在运行，本次退出。'
    exit 0
fi

get_public_ipv4() {
    local ip
    ip="$(curl -4fsS --max-time 8 https://api.ipify.org 2>/dev/null || true)"
    [[ -n "$ip" ]] || ip="$(curl -4fsS --max-time 8 https://ipv4.icanhazip.com 2>/dev/null | tr -d '\r\n' || true)"
    printf '%s' "${ip:-无法获取}"
}
get_public_ipv6() {
    local ip
    ip="$(curl -6fsS --max-time 8 https://api64.ipify.org 2>/dev/null || true)"
    printf '%s' "${ip:-未配置或无法获取}"
}
get_local_ipv4() {
    local value
    value="$(ip -o -4 addr show scope global 2>/dev/null | awk '{if(out!="")out=out", "; out=out $2"="$4} END{print out}')"
    printf '%s' "${value:-未检测到}"
}
encode_subject() {
    python3 - "$1" <<'PY'
from email.header import Header
import sys
print(Header(sys.argv[1], "utf-8").encode())
PY
}
run_command() {
    local title="$1" rc
    shift
    echo
    echo '============================================================'
    echo "$title"
    echo '============================================================'
    if "$@"; then
        echo; echo "[SUCCESS] $title"; return 0
    else
        rc=$?; echo; echo "[FAILED] $title"; echo "Exit code: $rc"; STATUS=1; return "$rc"
    fi
}

PUBLIC_IPV4="$(get_public_ipv4)"
PUBLIC_IPV6="$(get_public_ipv6)"
LOCAL_IPV4="$(get_local_ipv4)"

{
    echo '============================================================'
    echo 'Ubuntu Daily Upgrade Report'
    echo '============================================================'
    echo
    echo "Server hostname : $HOST_NAME"
    echo "Public IPv4     : $PUBLIC_IPV4"
    echo "Public IPv6     : $PUBLIC_IPV6"
    echo "Local IPv4      : $LOCAL_IPV4"
    echo "Start time      : $(TZ=Asia/Shanghai date '+%F %T') Beijing Time"
    echo "Kernel before   : $(uname -r)"

    if run_command '1. apt-get update' apt-get -o DPkg::Lock::Timeout=1800 update; then
        run_command '2. apt-get -y --no-remove upgrade' apt-get -o DPkg::Lock::Timeout=1800 -o Dpkg::Options::='--force-confold' -y --no-remove upgrade || true
    else
        echo; echo '[SKIPPED] apt-get update 失败，为避免错误升级，本次跳过 upgrade。'
    fi
    if [[ "${ALLOW_AUTOREMOVE:-false}" == true ]]; then
    run_command '3. apt-get -y autoremove' apt-get -o DPkg::Lock::Timeout=1800 -o Dpkg::Options::='--force-confold' -y autoremove || true
    else
        echo '[SKIPPED] autoremove (ALLOW_AUTOREMOVE=false)'
    fi
    run_command '4. apt-get clean' apt-get clean || true

    echo
    echo '============================================================'
    echo 'Reboot Status'
    echo '============================================================'
    if [[ -f /var/run/reboot-required ]]; then
        REBOOT_REQUIRED=1
        echo 'Reboot required : YES'
        echo '需要执行操作    : 重启服务器'
        [[ -f /var/run/reboot-required.pkgs ]] && { echo; echo 'Packages requesting reboot:'; cat /var/run/reboot-required.pkgs; }
    else
        echo 'Reboot required : NO'
    fi
    echo
    echo "Kernel after    : $(uname -r)"
    echo "Finish time     : $(TZ=Asia/Shanghai date '+%F %T') Beijing Time"
    [[ "$STATUS" -eq 0 ]] && echo 'Final result    : SUCCESS' || echo 'Final result    : FAILED'
} > "$UPDATE_LOG" 2>&1

if [[ -x "$AUDIT_SCRIPT" ]] && timeout "${AUDIT_TIMEOUT_SECONDS}s" "$AUDIT_SCRIPT" --quiet --exit-zero; then
    if [[ -r "$AUDIT_ENV" ]]; then
        source "$AUDIT_ENV"
        AUDIT_STATUS="${AUDIT_STATUS:-UNKNOWN}"
        AUDIT_PASS="${PASS_COUNT:-0}"
        AUDIT_WARN="${WARN_COUNT:-0}"
        AUDIT_FAIL="${FAIL_COUNT:-0}"
        AUDIT_CHANGES="${CHANGE_ALERTS:-0}"
        AUDIT_MAIL="${MAIL_FILE:-}"
        [[ "${REBOOT_REQUIRED:-0}" -eq 1 ]] && REBOOT_REQUIRED=1
    else
        AUDIT_PROGRAM_ERROR=1; AUDIT_STATUS='ERROR'
    fi
else
    AUDIT_PROGRAM_ERROR=1; AUDIT_STATUS='ERROR'
fi

{
    echo '============================================================'
    echo 'Ubuntu Daily Maintenance Report'
    echo 'System Update + VPS Security Audit'
    echo '============================================================'
    echo
    echo "Server hostname  : $HOST_NAME"
    echo "Public IPv4      : $PUBLIC_IPV4"
    echo "Public IPv6      : $PUBLIC_IPV6"
    echo "Local IPv4       : $LOCAL_IPV4"
    echo "Report time      : $(TZ=Asia/Shanghai date '+%F %T') Beijing Time"
    echo
    echo 'Overall Summary'
    echo '------------------------------------------------------------'
    [[ "$STATUS" -eq 0 ]] && echo 'System update    : SUCCESS' || echo 'System update    : FAILED'
    echo "Security audit   : $AUDIT_STATUS"
    echo "Audit PASS       : $AUDIT_PASS"
    echo "Audit WARN       : $AUDIT_WARN"
    echo "Audit FAIL       : $AUDIT_FAIL"
    echo "Baseline changes : $AUDIT_CHANGES"
    [[ "$REBOOT_REQUIRED" -eq 1 ]] && echo 'Reboot required  : YES' || echo 'Reboot required  : NO'
    echo
    echo '################################################################'
    echo '# 1. SYSTEM UPDATE REPORT'
    echo '################################################################'
    cat "$UPDATE_LOG"
    echo
    echo '################################################################'
    echo '# 2. VPS SECURITY AUDIT REPORT'
    echo '################################################################'
    if [[ "$AUDIT_PROGRAM_ERROR" -eq 1 ]]; then
        echo "[AUDIT ERROR] 安全巡检程序未能正常完成或超过 ${AUDIT_TIMEOUT_SECONDS} 秒。"
    elif [[ -n "$AUDIT_MAIL" && -r "$AUDIT_MAIL" ]]; then
        cat "$AUDIT_MAIL"
    else
        echo '[AUDIT ERROR] 未找到安全巡检邮件正文。'; AUDIT_PROGRAM_ERROR=1
    fi
    echo
    echo '################################################################'
    echo '# 3. SSH ATTACK & FAIL2BAN REPORT'
    echo '################################################################'
    if ! timeout 90 python3 /usr/local/lib/vpscheckreport/ssh-attack-report.py --json-output /var/lib/vpscheckreport/latest-attacks.json; then
        echo '[DATA WARNING] SSH attack data incomplete; review report above.'
    fi
} > "$MAIL_BODY"
chmod 600 "$MAIL_BODY"

[[ "$STATUS" -eq 0 ]] && UPDATE_TAG='[UPDATE SUCCESS]' || UPDATE_TAG='[UPDATE FAILED]'
case "$AUDIT_STATUS" in
    PASS) AUDIT_TAG='[SECURITY PASS]' ;;
    WARN) AUDIT_TAG='[SECURITY WARN]' ;;
    FAIL) AUDIT_TAG='[SECURITY FAIL]' ;;
    *) AUDIT_TAG='[AUDIT ERROR]' ;;
esac
IDENTITY="$HOST_NAME"
[[ "$PUBLIC_IPV4" != '无法获取' ]] && IDENTITY="$IDENTITY $PUBLIC_IPV4"
BASE_SUBJECT="${UPDATE_TAG}${AUDIT_TAG} Ubuntu daily maintenance - ${IDENTITY}"
if [[ "$REBOOT_REQUIRED" -eq 1 ]]; then RAW_SUBJECT="需要行动：重启 | $BASE_SUBJECT"
elif [[ "$STATUS" -ne 0 || "$AUDIT_PROGRAM_ERROR" -eq 1 || "$AUDIT_STATUS" == 'FAIL' ]]; then RAW_SUBJECT="需要行动 | $BASE_SUBJECT"
elif [[ "$AUDIT_STATUS" == 'WARN' ]]; then RAW_SUBJECT="警告 | $BASE_SUBJECT"
else RAW_SUBJECT="$BASE_SUBJECT"
fi
EMAIL_SUBJECT="$(encode_subject "$RAW_SUBJECT")"

if ! python3 /usr/local/lib/vpscheckreport/mail-send.py --subject "$RAW_SUBJECT" --body "$MAIL_BODY"; then
    echo 'ERROR: 维护完成，但邮件发送失败。' >&2
    STATUS=1
fi

cat "$MAIL_BODY"
find "$LOG_DIR" -type f \( -name 'apt-upgrade-*.log' -o -name 'daily-maintenance-*.mail.txt' \) -mtime +30 -delete 2>/dev/null || true
find /var/log/vpscheckreport/audit -type f -name 'audit-*.txt' -mtime +30 -delete 2>/dev/null || true
[[ "$AUDIT_PROGRAM_ERROR" -eq 1 ]] && STATUS=1
exit "$STATUS"