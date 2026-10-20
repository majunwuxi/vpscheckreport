#!/usr/bin/env bash
set -uo pipefail
umask 077

VERSION='3.0.0'
STATE_DIR='/var/lib/vpscheckreport/audit'
REPORT_DIR='/var/log/vpscheckreport/audit'
BASE_DIR="$STATE_DIR/baselines"
CONFIG='/etc/vpscheckreport/audit.conf'
ENV_FILE="$STATE_DIR/latest.env"
MAIL_FILE="$STATE_DIR/latest-mail.txt"

FIREWALL_POLICY='warn'
CHECK_DOCKER='auto'
CHECK_TLS='auto'
CHECK_SUID='true'
CHECK_CAPABILITIES='true'
CHECK_LISTENERS='true'
CHECK_AUTHORIZED_KEYS='true'
BACKUP_SENTINEL=''
BACKUP_MAX_AGE_HOURS='36'
IGNORE_FAILED_UNITS=''
IGNORE_LISTENER_REGEX=''
SUID_TIMEOUT_SECONDS='25'
CAP_TIMEOUT_SECONDS='20'

[[ -r "$CONFIG" ]] && source "$CONFIG"
[[ "$BACKUP_MAX_AGE_HOURS" =~ ^[0-9]+$ ]] || BACKUP_MAX_AGE_HOURS=36
[[ "$SUID_TIMEOUT_SECONDS" =~ ^[0-9]+$ ]] || SUID_TIMEOUT_SECONDS=25
[[ "$CAP_TIMEOUT_SECONDS" =~ ^[0-9]+$ ]] || CAP_TIMEOUT_SECONDS=20

ACCEPT_BASELINE=0
QUIET=0
EXIT_ZERO=0
for arg in "$@"; do
    case "$arg" in
        --accept-baseline) ACCEPT_BASELINE=1 ;;
        --quiet) QUIET=1 ;;
        --exit-zero) EXIT_ZERO=1 ;;
    esac
done

install -d -m 0700 "$STATE_DIR" "$REPORT_DIR" "$BASE_DIR"
exec 8>"$STATE_DIR/audit.lock"
if ! flock -n 8; then
    echo '另一个 VPS Audit 正在运行。' >&2
    exit 30
fi

HOST_NAME="$(hostname -f 2>/dev/null || hostname)"
PUBLIC_IPV4="$(curl -4fsS --max-time 6 https://api.ipify.org 2>/dev/null || true)"
[[ -n "$PUBLIC_IPV4" ]] || PUBLIC_IPV4='无法获取'
NOW="$(TZ=Asia/Shanghai date '+%F %T')"
STAMP="$(TZ=Asia/Shanghai date '+%Y%m%d-%H%M%S')"
REPORT_FILE="$REPORT_DIR/audit-$STAMP.txt"
TMP_DIR="$(mktemp -d /tmp/wellmax-audit.XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT

PASS=0
WARN=0
FAIL=0
INFO=0
CHANGES=0

line() { printf '%-6s | %-22s | %s\n' "$1" "$2" "$3" >> "$REPORT_FILE"; }
pass() { PASS=$((PASS + 1)); line PASS "$1" "$2"; }
warn() { WARN=$((WARN + 1)); line WARN "$1" "$2"; }
fail() { FAIL=$((FAIL + 1)); line FAIL "$1" "$2"; }
info() { INFO=$((INFO + 1)); line INFO "$1" "$2"; }

{
    echo '============================================================'
    echo "Wellmax Universal VPS Audit v$VERSION"
    echo '============================================================'
    echo "Server hostname : $HOST_NAME"
    echo "Public IPv4     : $PUBLIC_IPV4"
    echo "Audit time      : $NOW Beijing Time"
    echo
    echo 'STATUS | CHECK                  | RESULT'
    echo '------------------------------------------------------------'
} > "$REPORT_FILE"

# OS / kernel
if [[ -r /etc/os-release ]]; then
    . /etc/os-release
    info 'Operating System' "${PRETTY_NAME:-unknown}"
fi
info 'Kernel' "$(uname -r)"

# SSH effective config
SSH_PORT=22
SSH_PASSWORD_AUTH='unknown'
if command -v sshd >/dev/null 2>&1; then
    SSH_T="$(sshd -T 2>/dev/null || true)"
    ROOT_LOGIN="$(awk '$1=="permitrootlogin"{print $2; exit}' <<<"$SSH_T")"
    SSH_PASSWORD_AUTH="$(awk '$1=="passwordauthentication"{print $2; exit}' <<<"$SSH_T")"
    SSH_PORT="$(awk '$1=="port"{print $2; exit}' <<<"$SSH_T")"
    [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || SSH_PORT=22
    # Conservative network isolation check: UFW output alone cannot prove
    # absence of earlier ACCEPT rules, nftables hooks, or provider routes.
    SSH_ISOLATION='unverified'
    SSH_ISOLATION_REASON='未完成全部 IPv4/IPv6 netfilter 链、nftables hooks 和公网连通性验证'
    if command -v ufw >/dev/null 2>&1 && ufw status verbose 2>/dev/null | grep -q '^Status: active'; then
        UFW_ISOLATION_RULES="$(ufw status verbose 2>/dev/null || true)"
        if grep -Fq 'Anywhere on tailscale0' <<<"$UFW_ISOLATION_RULES" && \
           grep -Fq 'Anywhere (v6) on tailscale0' <<<"$UFW_ISOLATION_RULES" && \
           grep -Eq '^[[:space:]]*22/tcp[[:space:]]+DENY IN[[:space:]]+Anywhere
        no) pass 'SSH Root Login' 'PermitRootLogin=no' ;;
        prohibit-password|without-password) info 'SSH Root Login' "PermitRootLogin=$ROOT_LOGIN；root 仅允许密钥登录" ;;
        yes) warn 'SSH Root Login' 'PermitRootLogin=yes' ;;
        *) info 'SSH Root Login' "PermitRootLogin=${ROOT_LOGIN:-unknown}" ;;
    esac
    if [[ "$SSH_PASSWORD_AUTH" == 'no' ]]; then
        pass 'SSH Password' 'PasswordAuthentication=no'
    elif [[ "$SSH_PASSWORD_AUTH" == 'yes' ]]; then
        warn 'SSH Password' 'PasswordAuthentication=yes'
    else
        info 'SSH Password' '无法确认 PasswordAuthentication'
    fi
    info 'SSH Port' "$SSH_PORT"
else
    info 'SSH' '未找到 sshd；跳过 SSH 配置检查'
fi

# Host firewall. This does not claim to see provider/cloud firewalls.
FW=''
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
    FW='ufw active'
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null | grep -q '^running$'; then
    FW='firewalld running'
elif command -v nft >/dev/null 2>&1 && nft list ruleset 2>/dev/null | grep -Eq 'hook input[^;{]*;[^}]*policy (drop|reject)|policy (drop|reject)[^}]*hook input'; then
    FW='nftables input default-deny'
elif command -v iptables >/dev/null 2>&1 && iptables -S INPUT 2>/dev/null | grep -Eq '^-P INPUT (DROP|REJECT)$'; then
    FW='iptables INPUT default-deny'
fi
if [[ -n "$FW" ]]; then
    pass 'Host Firewall' "$FW"
else
    case "$FIREWALL_POLICY" in
        strict) fail 'Host Firewall' '未确认宿主机入站默认拒绝；云防火墙不在本机可见范围' ;;
        ignore) info 'Host Firewall' '未确认宿主机默认拒绝；按配置仅记录信息' ;;
        *) warn 'Host Firewall' '未确认宿主机入站默认拒绝；可能另有云防火墙/上游 ACL' ;;
    esac
fi

# Brute-force protection adapts to SSH password policy.
if systemctl is-active --quiet fail2ban 2>/dev/null; then
    pass 'Fail2ban' 'service active'
    if command -v fail2ban-client >/dev/null 2>&1; then
        JAILS="$(fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:[[:space:]]*//p' | tr -d ' ' || true)"
        info 'Fail2ban Jails' "${JAILS:-无法读取}"
        if [[ ",${JAILS}," == *,sshd,* ]]; then
            if [[ "$SSH_PORT" == '22' ]]; then
                pass 'Fail2ban SSH' 'sshd jail active；SSH 使用端口 22'
            else
                info 'Fail2ban SSH' "sshd jail active；SSH=$SSH_PORT，非标准端口请结合 action 配置人工核对"
            fi
        elif command -v sshd >/dev/null 2>&1; then
            warn 'Fail2ban SSH' 'Fail2ban active，但未发现 sshd jail'
        fi
    fi
elif systemctl is-active --quiet crowdsec 2>/dev/null; then
    pass 'CrowdSec' 'service active'
elif [[ "$SSH_PASSWORD_AUTH" == 'yes' ]]; then
    warn 'Bruteforce Guard' 'SSH 密码登录开启，但未检测到 Fail2ban/CrowdSec active'
else
    info 'Bruteforce Guard' '未检测到 Fail2ban/CrowdSec；SSH 密码登录未开启或未安装 sshd'
fi

# systemd failed units, with per-host ignore list.
FAILED_RAW="$(systemctl --failed --no-legend --plain 2>/dev/null | awk 'NF{print $1}' || true)"
FAILED_KEEP=''
while IFS= read -r unit; do
    [[ -n "$unit" ]] || continue
    skip=0
    for ignored in $IGNORE_FAILED_UNITS; do
        [[ "$unit" == "$ignored" ]] && skip=1 && break
    done
    (( skip == 1 )) || FAILED_KEEP+="$unit "
done <<< "$FAILED_RAW"
FAILED_KEEP="${FAILED_KEEP% }"
if [[ -z "$FAILED_KEEP" ]]; then
    pass 'systemd' '无未忽略的 failed units'
else
    fail 'systemd' "failed: $FAILED_KEEP"
fi

# Disk usage. Exclude overlay/squashfs to avoid duplicate container views.
while read -r PCT MOUNT; do
    N="${PCT%%%}"
    [[ "$N" =~ ^[0-9]+$ ]] || continue
    if (( N >= 95 )); then fail 'Disk Usage' "$MOUNT ${N}%"
    elif (( N >= 85 )); then warn 'Disk Usage' "$MOUNT ${N}%"
    else pass 'Disk Usage' "$MOUNT ${N}%"
    fi
done < <(df -P -x tmpfs -x devtmpfs -x overlay -x squashfs 2>/dev/null | awk 'NR>1{print $5,$6}')

while read -r PCT MOUNT; do
    N="${PCT%%%}"
    [[ "$N" =~ ^[0-9]+$ ]] || continue
    if (( N >= 95 )); then fail 'Inode Usage' "$MOUNT ${N}%"
    elif (( N >= 85 )); then warn 'Inode Usage' "$MOUNT ${N}%"
    fi
done < <(df -Pi -x tmpfs -x devtmpfs -x overlay -x squashfs 2>/dev/null | awk 'NR>1{print $5,$6}')

# Memory / swap / load.
MEM_TOTAL="$(awk '/MemTotal/{print $2}' /proc/meminfo)"
MEM_AVAIL="$(awk '/MemAvailable/{print $2}' /proc/meminfo)"
if [[ "$MEM_TOTAL" =~ ^[0-9]+$ && "$MEM_AVAIL" =~ ^[0-9]+$ && "$MEM_TOTAL" -gt 0 ]]; then
    MEM_USED=$(( (MEM_TOTAL - MEM_AVAIL) * 100 / MEM_TOTAL ))
    if (( MEM_USED >= 95 )); then fail 'Memory' "${MEM_USED}% used"
    elif (( MEM_USED >= 90 )); then warn 'Memory' "${MEM_USED}% used"
    else pass 'Memory' "${MEM_USED}% used"
    fi
fi
SWAP_TOTAL="$(awk '/SwapTotal/{print $2}' /proc/meminfo)"
SWAP_FREE="$(awk '/SwapFree/{print $2}' /proc/meminfo)"
if [[ "$SWAP_TOTAL" =~ ^[0-9]+$ && "$SWAP_TOTAL" -gt 0 ]]; then
    SWAP_USED=$(( (SWAP_TOTAL - SWAP_FREE) * 100 / SWAP_TOTAL ))
    if (( SWAP_USED >= 90 )); then warn 'Swap' "${SWAP_USED}% used"
    else info 'Swap' "${SWAP_USED}% used"
    fi
else
    info 'Swap' 'not configured'
fi
LOAD1="$(awk '{print $1}' /proc/loadavg 2>/dev/null || true)"
CPU_N="$(nproc 2>/dev/null || echo 1)"
info 'Load Average' "1m=$LOAD1 CPUs=$CPU_N"

# Docker, only if present / requested.
RUN_DOCKER=0
if [[ "$CHECK_DOCKER" == 'true' ]]; then RUN_DOCKER=1
elif [[ "$CHECK_DOCKER" == 'auto' ]] && command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then RUN_DOCKER=1
fi
if (( RUN_DOCKER == 1 )); then
    if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
        BAD_DOCKER="$(docker ps -a --format '{{.Names}}|{{.Status}}' 2>/dev/null | grep -Ei 'unhealthy|restarting|dead' || true)"
        if [[ -z "$BAD_DOCKER" ]]; then pass 'Docker Health' '无 unhealthy/restarting/dead 容器'
        else warn 'Docker Health' "异常容器: $(echo "$BAD_DOCKER" | paste -sd ';' -)"
        fi
        PRIV=''; SOCK=''; HOSTNET=''
        while read -r CID; do
            [[ -n "$CID" ]] || continue
            NAME="$(docker inspect -f '{{.Name}}' "$CID" 2>/dev/null | sed 's#^/##')"
            [[ "$(docker inspect -f '{{.HostConfig.Privileged}}' "$CID" 2>/dev/null)" == true ]] && PRIV+="$NAME "
            docker inspect -f '{{range .Mounts}}{{.Source}}=>{{.Destination}} {{end}}' "$CID" 2>/dev/null | grep -q '/var/run/docker.sock' && SOCK+="$NAME " || true
            [[ "$(docker inspect -f '{{.HostConfig.NetworkMode}}' "$CID" 2>/dev/null)" == 'host' ]] && HOSTNET+="$NAME "
        done < <(docker ps -q 2>/dev/null)
        [[ -z "$PRIV" ]] && pass 'Docker Privileged' '无 privileged 容器' || warn 'Docker Privileged' "$PRIV"
        [[ -z "$SOCK" ]] && pass 'Docker Socket' '运行中容器未挂载 docker.sock' || warn 'Docker Socket' "挂载 docker.sock: $SOCK"
        [[ -z "$HOSTNET" ]] || info 'Docker Host Network' "$HOSTNET"
    else
        warn 'Docker' '配置要求检查 Docker，但 daemon 不可用'
    fi
else
    info 'Docker' '未安装/未运行，或检查被关闭'
fi

# Let's Encrypt certificates only; other TLS stacks remain informationally out of scope.
RUN_TLS=0
if [[ "$CHECK_TLS" == 'true' ]]; then RUN_TLS=1
elif [[ "$CHECK_TLS" == 'auto' ]] && compgen -G '/etc/letsencrypt/live/*/cert.pem' >/dev/null; then RUN_TLS=1
fi
if (( RUN_TLS == 1 )); then
    CERT_FOUND=0
    for cert in /etc/letsencrypt/live/*/cert.pem; do
        [[ -f "$cert" ]] || continue
        CERT_FOUND=1
        NAME="$(basename "$(dirname "$cert")")"
        END="$(openssl x509 -enddate -noout -in "$cert" 2>/dev/null | cut -d= -f2 || true)"
        if [[ -n "$END" ]]; then
            END_EPOCH="$(date -d "$END" +%s 2>/dev/null || echo 0)"
            NOW_EPOCH="$(date +%s)"
            DAYS=$(( (END_EPOCH - NOW_EPOCH) / 86400 ))
            if (( DAYS <= 7 )); then fail 'TLS Certificate' "$NAME 剩余 ${DAYS} 天"
            elif (( DAYS <= 21 )); then warn 'TLS Certificate' "$NAME 剩余 ${DAYS} 天"
            else pass 'TLS Certificate' "$NAME 剩余 ${DAYS} 天"
            fi
        fi
    done
    (( CERT_FOUND == 1 )) || info 'TLS Certificate' '未发现 Let’s Encrypt cert.pem'
else
    info 'TLS Certificate' '未检测到 Let’s Encrypt 证书或检查被关闭'
fi

# sudo logging: don't fail on distributions using different journal arrangements.
if journalctl -t sudo -n 1 --no-pager 2>/dev/null | grep -q . || grep -q 'sudo:' /var/log/auth.log 2>/dev/null || grep -RqsE '^[[:space:]]*Defaults.*logfile' /etc/sudoers /etc/sudoers.d 2>/dev/null; then
    pass 'Sudo Logging' '检测到 sudo 日志或显式日志配置'
else
    info 'Sudo Logging' '未确认；日志后端可能因系统配置不同'
fi

baseline_check() {
    local key="$1" label="$2" current="$3"
    local base="$BASE_DIR/$key.baseline" added="$TMP_DIR/$key.added"
    sort -u "$current" -o "$current" 2>/dev/null || true
    if (( ACCEPT_BASELINE == 1 )) || [[ ! -f "$base" ]]; then
        cp -f "$current" "$base"
        chmod 600 "$base"
        if (( ACCEPT_BASELINE == 1 )); then pass "$label" '已接受当前状态为新基线'
        else info "$label" '首次建立基线；以后发现新增项将报警'
        fi
        return
    fi
    comm -13 "$base" "$current" > "$added" 2>/dev/null || true
    if [[ -s "$added" ]]; then
        local count
        count="$(wc -l < "$added")"
        CHANGES=$(( CHANGES + count ))
        warn "$label" "发现 $count 个相对基线的新增项：$(head -n 8 "$added" | paste -sd ';' -)"
    else
        pass "$label" '无新增项'
    fi
}

# Stable network listener baseline: protocol + local address/port only.
if [[ "$CHECK_LISTENERS" == 'true' ]]; then
    LISTEN="$TMP_DIR/listeners"
    ss -H -lntu 2>/dev/null | awk '{proto=$1; local=$5; if (local ~ /^127\./ || local ~ /^\[::1\]:/ || local ~ /^::1:/) next; print proto "|" local}' | sort -u > "$LISTEN"
    if [[ -n "$IGNORE_LISTENER_REGEX" ]]; then
        grep -Ev "$IGNORE_LISTENER_REGEX" "$LISTEN" > "$LISTEN.filtered" || true
        mv "$LISTEN.filtered" "$LISTEN"
    fi
    NET_BASE="$BASE_DIR/network-listeners.baseline"
    if [[ -f "$NET_BASE" ]] && awk -F'|' 'NF>2{found=1} END{exit found?0:1}' "$NET_BASE"; then
        mv "$NET_BASE" "${NET_BASE}.legacy-${STAMP}"
        info 'Network Listeners' '检测到旧版 PID-sensitive 基线，已自动迁移为稳定格式'
    fi
    baseline_check 'network-listeners' 'Network Listeners' "$LISTEN"
fi

# Authorized keys baseline stores hashes only.
if [[ "$CHECK_AUTHORIZED_KEYS" == 'true' ]]; then
    KEYS="$TMP_DIR/authorized_keys"; : > "$KEYS"
    while IFS=: read -r user _ uid _ _ home _; do
        [[ "$uid" =~ ^[0-9]+$ ]] || continue
        (( uid == 0 || uid >= 1000 )) || continue
        for f in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
            [[ -f "$f" ]] || continue
            while IFS= read -r k; do
                [[ -n "$k" && "$k" != \#* ]] || continue
                printf '%s|%s\n' "$user" "$(printf '%s' "$k" | sha256sum | awk '{print $1}')" >> "$KEYS"
            done < "$f"
        done
    done < /etc/passwd
    baseline_check 'authorized-keys' 'Authorized Keys' "$KEYS"
fi

# Host-only SUID/SGID baseline. Container/VM image roots are pruned.
if [[ "$CHECK_SUID" == 'true' ]]; then
    SUID="$TMP_DIR/suid"; : > "$SUID"
    if ! timeout "${SUID_TIMEOUT_SECONDS}s" find /usr /bin /sbin /opt /root /home /var -xdev \
        \( -path '/var/lib/docker' -o -path '/var/lib/docker/*' -o -path '/var/lib/containerd' -o -path '/var/lib/containerd/*' -o -path '/var/lib/containers' -o -path '/var/lib/containers/*' -o -path '/var/lib/kubelet' -o -path '/var/lib/kubelet/*' -o -path '/var/lib/lxc' -o -path '/var/lib/lxc/*' -o -path '/var/lib/lxd' -o -path '/var/lib/lxd/*' -o -path '/var/lib/incus' -o -path '/var/lib/incus/*' -o -path '/var/lib/machines' -o -path '/var/lib/machines/*' \) -prune -o \
        -type f \( -perm -4000 -o -perm -2000 \) -printf '%p|%u|%g|%m\n' 2>/dev/null | sort -u > "$SUID"; then
        warn 'SUID/SGID Scan' "扫描超过 ${SUID_TIMEOUT_SECONDS}s 或部分目录不可读"
    fi
    SUID_BASE="$BASE_DIR/suid-sgid.baseline"
    if [[ -f "$SUID_BASE" ]] && grep -Eq '^/var/lib/(docker|containerd|containers|kubelet|lxc|lxd|incus|machines)/' "$SUID_BASE"; then
        mv "$SUID_BASE" "${SUID_BASE}.legacy-${STAMP}"
        info 'SUID/SGID Baseline' '检测到旧版容器镜像条目，已自动重建 Host-only 基线'
    fi
    baseline_check 'suid-sgid' 'SUID/SGID Baseline' "$SUID"
fi

# File capabilities baseline, filtered to exclude container storage roots.
if [[ "$CHECK_CAPABILITIES" == 'true' ]] && command -v getcap >/dev/null 2>&1; then
    CAPS="$TMP_DIR/capabilities"; : > "$CAPS"
    if ! timeout "${CAP_TIMEOUT_SECONDS}s" getcap -r /usr /bin /sbin /opt /root /home /var 2>/dev/null | awk '!/^\/var\/lib\/(docker|containerd|containers|kubelet|lxc|lxd|incus|machines)\//' | sort -u > "$CAPS"; then
        warn 'Capabilities Scan' "扫描超过 ${CAP_TIMEOUT_SECONDS}s 或部分目录不可读"
    fi
    CAP_BASE="$BASE_DIR/capabilities.baseline"
    if [[ -f "$CAP_BASE" ]] && grep -Eq '^/var/lib/(docker|containerd|containers|kubelet|lxc|lxd|incus|machines)/' "$CAP_BASE"; then
        mv "$CAP_BASE" "${CAP_BASE}.legacy-${STAMP}"
        info 'File Capabilities' '检测到旧版容器镜像条目，已自动重建 Host-only 基线'
    fi
    baseline_check 'capabilities' 'File Capabilities' "$CAPS"
fi

# Optional backup freshness sentinel.
if [[ -n "$BACKUP_SENTINEL" ]]; then
    if [[ -e "$BACKUP_SENTINEL" ]]; then
        NOW_EPOCH="$(date +%s)"
        MTIME="$(stat -c %Y "$BACKUP_SENTINEL" 2>/dev/null || echo 0)"
        AGE_HOURS=$(( (NOW_EPOCH - MTIME) / 3600 ))
        if (( AGE_HOURS > BACKUP_MAX_AGE_HOURS )); then fail 'Backup Freshness' "最后成功标记已 ${AGE_HOURS} 小时"
        else pass 'Backup Freshness' "最后成功标记 ${AGE_HOURS} 小时前"
        fi
    else
        fail 'Backup Freshness' "未找到 $BACKUP_SENTINEL"
    fi
fi

if [[ -f /var/run/reboot-required ]]; then
    warn 'Reboot Required' 'YES，需要重启服务器'; REBOOT_REQUIRED=1
else
    pass 'Reboot Required' 'NO'; REBOOT_REQUIRED=0
fi

if (( FAIL > 0 )); then STATUS='FAIL'; EXIT_CODE=20
elif (( WARN > 0 )); then STATUS='WARN'; EXIT_CODE=10
else STATUS='PASS'; EXIT_CODE=0
fi

{
    echo
    echo '------------------------------------------------------------'
    echo "Final status     : $STATUS"
    echo "PASS             : $PASS"
    echo "WARN             : $WARN"
    echo "FAIL             : $FAIL"
    echo "INFO             : $INFO"
    echo "Baseline changes : $CHANGES"
    echo "Reboot required  : $REBOOT_REQUIRED"
    echo '============================================================'
} >> "$REPORT_FILE"

{
    echo 'VPS Security Audit Summary'
    echo '------------------------------------------------------------'
    echo "Status           : $STATUS"
    echo "PASS/WARN/FAIL   : $PASS/$WARN/$FAIL"
    echo "Baseline changes : $CHANGES"
    echo "Reboot required  : $REBOOT_REQUIRED"
    echo
    cat "$REPORT_FILE"
} > "$MAIL_FILE"
chmod 600 "$REPORT_FILE" "$MAIL_FILE"

{
    printf 'AUDIT_STATUS=%q\n' "$STATUS"
    printf 'AUDIT_EXIT_CODE=%q\n' "$EXIT_CODE"
    printf 'PASS_COUNT=%q\n' "$PASS"
    printf 'WARN_COUNT=%q\n' "$WARN"
    printf 'FAIL_COUNT=%q\n' "$FAIL"
    printf 'CHANGE_ALERTS=%q\n' "$CHANGES"
    printf 'REBOOT_REQUIRED=%q\n' "$REBOOT_REQUIRED"
    printf 'REPORT_FILE=%q\n' "$REPORT_FILE"
    printf 'MAIL_FILE=%q\n' "$MAIL_FILE"
} > "$ENV_FILE"
chmod 600 "$ENV_FILE"

if (( QUIET == 0 )); then
    cat "$REPORT_FILE"
    echo
    echo '如确认所有新增基线项均合法：'
    echo 'sudo /usr/local/sbin/vpscheck-audit --accept-baseline --exit-zero'
fi

(( EXIT_ZERO == 1 )) && exit 0
exit "$EXIT_CODE" <<<"$UFW_ISOLATION_RULES" && \
           grep -Eq '^[[:space:]]*22/tcp \(v6\)[[:space:]]+DENY IN[[:space:]]+Anywhere \(v6\)
        no) pass 'SSH Root Login' 'PermitRootLogin=no' ;;
        prohibit-password|without-password) info 'SSH Root Login' "PermitRootLogin=$ROOT_LOGIN；root 仅允许密钥登录" ;;
        yes) warn 'SSH Root Login' 'PermitRootLogin=yes' ;;
        *) info 'SSH Root Login' "PermitRootLogin=${ROOT_LOGIN:-unknown}" ;;
    esac
    if [[ "$SSH_PASSWORD_AUTH" == 'no' ]]; then
        pass 'SSH Password' 'PasswordAuthentication=no'
    elif [[ "$SSH_PASSWORD_AUTH" == 'yes' ]]; then
        warn 'SSH Password' 'PasswordAuthentication=yes'
    else
        info 'SSH Password' '无法确认 PasswordAuthentication'
    fi
    info 'SSH Port' "$SSH_PORT"
else
    info 'SSH' '未找到 sshd；跳过 SSH 配置检查'
fi

# Host firewall. This does not claim to see provider/cloud firewalls.
FW=''
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
    FW='ufw active'
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null | grep -q '^running$'; then
    FW='firewalld running'
elif command -v nft >/dev/null 2>&1 && nft list ruleset 2>/dev/null | grep -Eq 'hook input[^;{]*;[^}]*policy (drop|reject)|policy (drop|reject)[^}]*hook input'; then
    FW='nftables input default-deny'
elif command -v iptables >/dev/null 2>&1 && iptables -S INPUT 2>/dev/null | grep -Eq '^-P INPUT (DROP|REJECT)$'; then
    FW='iptables INPUT default-deny'
fi
if [[ -n "$FW" ]]; then
    pass 'Host Firewall' "$FW"
else
    case "$FIREWALL_POLICY" in
        strict) fail 'Host Firewall' '未确认宿主机入站默认拒绝；云防火墙不在本机可见范围' ;;
        ignore) info 'Host Firewall' '未确认宿主机默认拒绝；按配置仅记录信息' ;;
        *) warn 'Host Firewall' '未确认宿主机入站默认拒绝；可能另有云防火墙/上游 ACL' ;;
    esac
fi

# Brute-force protection adapts to SSH password policy.
if systemctl is-active --quiet fail2ban 2>/dev/null; then
    pass 'Fail2ban' 'service active'
    if command -v fail2ban-client >/dev/null 2>&1; then
        JAILS="$(fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:[[:space:]]*//p' | tr -d ' ' || true)"
        info 'Fail2ban Jails' "${JAILS:-无法读取}"
        if [[ ",${JAILS}," == *,sshd,* ]]; then
            if [[ "$SSH_PORT" == '22' ]]; then
                pass 'Fail2ban SSH' 'sshd jail active；SSH 使用端口 22'
            else
                info 'Fail2ban SSH' "sshd jail active；SSH=$SSH_PORT，非标准端口请结合 action 配置人工核对"
            fi
        elif command -v sshd >/dev/null 2>&1; then
            warn 'Fail2ban SSH' 'Fail2ban active，但未发现 sshd jail'
        fi
    fi
elif systemctl is-active --quiet crowdsec 2>/dev/null; then
    pass 'CrowdSec' 'service active'
elif [[ "$SSH_PASSWORD_AUTH" == 'yes' ]]; then
    warn 'Bruteforce Guard' 'SSH 密码登录开启，但未检测到 Fail2ban/CrowdSec active'
else
    info 'Bruteforce Guard' '未检测到 Fail2ban/CrowdSec；SSH 密码登录未开启或未安装 sshd'
fi

# systemd failed units, with per-host ignore list.
FAILED_RAW="$(systemctl --failed --no-legend --plain 2>/dev/null | awk 'NF{print $1}' || true)"
FAILED_KEEP=''
while IFS= read -r unit; do
    [[ -n "$unit" ]] || continue
    skip=0
    for ignored in $IGNORE_FAILED_UNITS; do
        [[ "$unit" == "$ignored" ]] && skip=1 && break
    done
    (( skip == 1 )) || FAILED_KEEP+="$unit "
done <<< "$FAILED_RAW"
FAILED_KEEP="${FAILED_KEEP% }"
if [[ -z "$FAILED_KEEP" ]]; then
    pass 'systemd' '无未忽略的 failed units'
else
    fail 'systemd' "failed: $FAILED_KEEP"
fi

# Disk usage. Exclude overlay/squashfs to avoid duplicate container views.
while read -r PCT MOUNT; do
    N="${PCT%%%}"
    [[ "$N" =~ ^[0-9]+$ ]] || continue
    if (( N >= 95 )); then fail 'Disk Usage' "$MOUNT ${N}%"
    elif (( N >= 85 )); then warn 'Disk Usage' "$MOUNT ${N}%"
    else pass 'Disk Usage' "$MOUNT ${N}%"
    fi
done < <(df -P -x tmpfs -x devtmpfs -x overlay -x squashfs 2>/dev/null | awk 'NR>1{print $5,$6}')

while read -r PCT MOUNT; do
    N="${PCT%%%}"
    [[ "$N" =~ ^[0-9]+$ ]] || continue
    if (( N >= 95 )); then fail 'Inode Usage' "$MOUNT ${N}%"
    elif (( N >= 85 )); then warn 'Inode Usage' "$MOUNT ${N}%"
    fi
done < <(df -Pi -x tmpfs -x devtmpfs -x overlay -x squashfs 2>/dev/null | awk 'NR>1{print $5,$6}')

# Memory / swap / load.
MEM_TOTAL="$(awk '/MemTotal/{print $2}' /proc/meminfo)"
MEM_AVAIL="$(awk '/MemAvailable/{print $2}' /proc/meminfo)"
if [[ "$MEM_TOTAL" =~ ^[0-9]+$ && "$MEM_AVAIL" =~ ^[0-9]+$ && "$MEM_TOTAL" -gt 0 ]]; then
    MEM_USED=$(( (MEM_TOTAL - MEM_AVAIL) * 100 / MEM_TOTAL ))
    if (( MEM_USED >= 95 )); then fail 'Memory' "${MEM_USED}% used"
    elif (( MEM_USED >= 90 )); then warn 'Memory' "${MEM_USED}% used"
    else pass 'Memory' "${MEM_USED}% used"
    fi
fi
SWAP_TOTAL="$(awk '/SwapTotal/{print $2}' /proc/meminfo)"
SWAP_FREE="$(awk '/SwapFree/{print $2}' /proc/meminfo)"
if [[ "$SWAP_TOTAL" =~ ^[0-9]+$ && "$SWAP_TOTAL" -gt 0 ]]; then
    SWAP_USED=$(( (SWAP_TOTAL - SWAP_FREE) * 100 / SWAP_TOTAL ))
    if (( SWAP_USED >= 90 )); then warn 'Swap' "${SWAP_USED}% used"
    else info 'Swap' "${SWAP_USED}% used"
    fi
else
    info 'Swap' 'not configured'
fi
LOAD1="$(awk '{print $1}' /proc/loadavg 2>/dev/null || true)"
CPU_N="$(nproc 2>/dev/null || echo 1)"
info 'Load Average' "1m=$LOAD1 CPUs=$CPU_N"

# Docker, only if present / requested.
RUN_DOCKER=0
if [[ "$CHECK_DOCKER" == 'true' ]]; then RUN_DOCKER=1
elif [[ "$CHECK_DOCKER" == 'auto' ]] && command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then RUN_DOCKER=1
fi
if (( RUN_DOCKER == 1 )); then
    if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
        BAD_DOCKER="$(docker ps -a --format '{{.Names}}|{{.Status}}' 2>/dev/null | grep -Ei 'unhealthy|restarting|dead' || true)"
        if [[ -z "$BAD_DOCKER" ]]; then pass 'Docker Health' '无 unhealthy/restarting/dead 容器'
        else warn 'Docker Health' "异常容器: $(echo "$BAD_DOCKER" | paste -sd ';' -)"
        fi
        PRIV=''; SOCK=''; HOSTNET=''
        while read -r CID; do
            [[ -n "$CID" ]] || continue
            NAME="$(docker inspect -f '{{.Name}}' "$CID" 2>/dev/null | sed 's#^/##')"
            [[ "$(docker inspect -f '{{.HostConfig.Privileged}}' "$CID" 2>/dev/null)" == true ]] && PRIV+="$NAME "
            docker inspect -f '{{range .Mounts}}{{.Source}}=>{{.Destination}} {{end}}' "$CID" 2>/dev/null | grep -q '/var/run/docker.sock' && SOCK+="$NAME " || true
            [[ "$(docker inspect -f '{{.HostConfig.NetworkMode}}' "$CID" 2>/dev/null)" == 'host' ]] && HOSTNET+="$NAME "
        done < <(docker ps -q 2>/dev/null)
        [[ -z "$PRIV" ]] && pass 'Docker Privileged' '无 privileged 容器' || warn 'Docker Privileged' "$PRIV"
        [[ -z "$SOCK" ]] && pass 'Docker Socket' '运行中容器未挂载 docker.sock' || warn 'Docker Socket' "挂载 docker.sock: $SOCK"
        [[ -z "$HOSTNET" ]] || info 'Docker Host Network' "$HOSTNET"
    else
        warn 'Docker' '配置要求检查 Docker，但 daemon 不可用'
    fi
else
    info 'Docker' '未安装/未运行，或检查被关闭'
fi

# Let's Encrypt certificates only; other TLS stacks remain informationally out of scope.
RUN_TLS=0
if [[ "$CHECK_TLS" == 'true' ]]; then RUN_TLS=1
elif [[ "$CHECK_TLS" == 'auto' ]] && compgen -G '/etc/letsencrypt/live/*/cert.pem' >/dev/null; then RUN_TLS=1
fi
if (( RUN_TLS == 1 )); then
    CERT_FOUND=0
    for cert in /etc/letsencrypt/live/*/cert.pem; do
        [[ -f "$cert" ]] || continue
        CERT_FOUND=1
        NAME="$(basename "$(dirname "$cert")")"
        END="$(openssl x509 -enddate -noout -in "$cert" 2>/dev/null | cut -d= -f2 || true)"
        if [[ -n "$END" ]]; then
            END_EPOCH="$(date -d "$END" +%s 2>/dev/null || echo 0)"
            NOW_EPOCH="$(date +%s)"
            DAYS=$(( (END_EPOCH - NOW_EPOCH) / 86400 ))
            if (( DAYS <= 7 )); then fail 'TLS Certificate' "$NAME 剩余 ${DAYS} 天"
            elif (( DAYS <= 21 )); then warn 'TLS Certificate' "$NAME 剩余 ${DAYS} 天"
            else pass 'TLS Certificate' "$NAME 剩余 ${DAYS} 天"
            fi
        fi
    done
    (( CERT_FOUND == 1 )) || info 'TLS Certificate' '未发现 Let’s Encrypt cert.pem'
else
    info 'TLS Certificate' '未检测到 Let’s Encrypt 证书或检查被关闭'
fi

# sudo logging: don't fail on distributions using different journal arrangements.
if journalctl -t sudo -n 1 --no-pager 2>/dev/null | grep -q . || grep -q 'sudo:' /var/log/auth.log 2>/dev/null || grep -RqsE '^[[:space:]]*Defaults.*logfile' /etc/sudoers /etc/sudoers.d 2>/dev/null; then
    pass 'Sudo Logging' '检测到 sudo 日志或显式日志配置'
else
    info 'Sudo Logging' '未确认；日志后端可能因系统配置不同'
fi

baseline_check() {
    local key="$1" label="$2" current="$3"
    local base="$BASE_DIR/$key.baseline" added="$TMP_DIR/$key.added"
    sort -u "$current" -o "$current" 2>/dev/null || true
    if (( ACCEPT_BASELINE == 1 )) || [[ ! -f "$base" ]]; then
        cp -f "$current" "$base"
        chmod 600 "$base"
        if (( ACCEPT_BASELINE == 1 )); then pass "$label" '已接受当前状态为新基线'
        else info "$label" '首次建立基线；以后发现新增项将报警'
        fi
        return
    fi
    comm -13 "$base" "$current" > "$added" 2>/dev/null || true
    if [[ -s "$added" ]]; then
        local count
        count="$(wc -l < "$added")"
        CHANGES=$(( CHANGES + count ))
        warn "$label" "发现 $count 个相对基线的新增项：$(head -n 8 "$added" | paste -sd ';' -)"
    else
        pass "$label" '无新增项'
    fi
}

# Stable network listener baseline: protocol + local address/port only.
if [[ "$CHECK_LISTENERS" == 'true' ]]; then
    LISTEN="$TMP_DIR/listeners"
    ss -H -lntu 2>/dev/null | awk '{proto=$1; local=$5; if (local ~ /^127\./ || local ~ /^\[::1\]:/ || local ~ /^::1:/) next; print proto "|" local}' | sort -u > "$LISTEN"
    if [[ -n "$IGNORE_LISTENER_REGEX" ]]; then
        grep -Ev "$IGNORE_LISTENER_REGEX" "$LISTEN" > "$LISTEN.filtered" || true
        mv "$LISTEN.filtered" "$LISTEN"
    fi
    NET_BASE="$BASE_DIR/network-listeners.baseline"
    if [[ -f "$NET_BASE" ]] && awk -F'|' 'NF>2{found=1} END{exit found?0:1}' "$NET_BASE"; then
        mv "$NET_BASE" "${NET_BASE}.legacy-${STAMP}"
        info 'Network Listeners' '检测到旧版 PID-sensitive 基线，已自动迁移为稳定格式'
    fi
    baseline_check 'network-listeners' 'Network Listeners' "$LISTEN"
fi

# Authorized keys baseline stores hashes only.
if [[ "$CHECK_AUTHORIZED_KEYS" == 'true' ]]; then
    KEYS="$TMP_DIR/authorized_keys"; : > "$KEYS"
    while IFS=: read -r user _ uid _ _ home _; do
        [[ "$uid" =~ ^[0-9]+$ ]] || continue
        (( uid == 0 || uid >= 1000 )) || continue
        for f in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
            [[ -f "$f" ]] || continue
            while IFS= read -r k; do
                [[ -n "$k" && "$k" != \#* ]] || continue
                printf '%s|%s\n' "$user" "$(printf '%s' "$k" | sha256sum | awk '{print $1}')" >> "$KEYS"
            done < "$f"
        done
    done < /etc/passwd
    baseline_check 'authorized-keys' 'Authorized Keys' "$KEYS"
fi

# Host-only SUID/SGID baseline. Container/VM image roots are pruned.
if [[ "$CHECK_SUID" == 'true' ]]; then
    SUID="$TMP_DIR/suid"; : > "$SUID"
    if ! timeout "${SUID_TIMEOUT_SECONDS}s" find /usr /bin /sbin /opt /root /home /var -xdev \
        \( -path '/var/lib/docker' -o -path '/var/lib/docker/*' -o -path '/var/lib/containerd' -o -path '/var/lib/containerd/*' -o -path '/var/lib/containers' -o -path '/var/lib/containers/*' -o -path '/var/lib/kubelet' -o -path '/var/lib/kubelet/*' -o -path '/var/lib/lxc' -o -path '/var/lib/lxc/*' -o -path '/var/lib/lxd' -o -path '/var/lib/lxd/*' -o -path '/var/lib/incus' -o -path '/var/lib/incus/*' -o -path '/var/lib/machines' -o -path '/var/lib/machines/*' \) -prune -o \
        -type f \( -perm -4000 -o -perm -2000 \) -printf '%p|%u|%g|%m\n' 2>/dev/null | sort -u > "$SUID"; then
        warn 'SUID/SGID Scan' "扫描超过 ${SUID_TIMEOUT_SECONDS}s 或部分目录不可读"
    fi
    SUID_BASE="$BASE_DIR/suid-sgid.baseline"
    if [[ -f "$SUID_BASE" ]] && grep -Eq '^/var/lib/(docker|containerd|containers|kubelet|lxc|lxd|incus|machines)/' "$SUID_BASE"; then
        mv "$SUID_BASE" "${SUID_BASE}.legacy-${STAMP}"
        info 'SUID/SGID Baseline' '检测到旧版容器镜像条目，已自动重建 Host-only 基线'
    fi
    baseline_check 'suid-sgid' 'SUID/SGID Baseline' "$SUID"
fi

# File capabilities baseline, filtered to exclude container storage roots.
if [[ "$CHECK_CAPABILITIES" == 'true' ]] && command -v getcap >/dev/null 2>&1; then
    CAPS="$TMP_DIR/capabilities"; : > "$CAPS"
    if ! timeout "${CAP_TIMEOUT_SECONDS}s" getcap -r /usr /bin /sbin /opt /root /home /var 2>/dev/null | awk '!/^\/var\/lib\/(docker|containerd|containers|kubelet|lxc|lxd|incus|machines)\//' | sort -u > "$CAPS"; then
        warn 'Capabilities Scan' "扫描超过 ${CAP_TIMEOUT_SECONDS}s 或部分目录不可读"
    fi
    CAP_BASE="$BASE_DIR/capabilities.baseline"
    if [[ -f "$CAP_BASE" ]] && grep -Eq '^/var/lib/(docker|containerd|containers|kubelet|lxc|lxd|incus|machines)/' "$CAP_BASE"; then
        mv "$CAP_BASE" "${CAP_BASE}.legacy-${STAMP}"
        info 'File Capabilities' '检测到旧版容器镜像条目，已自动重建 Host-only 基线'
    fi
    baseline_check 'capabilities' 'File Capabilities' "$CAPS"
fi

# Optional backup freshness sentinel.
if [[ -n "$BACKUP_SENTINEL" ]]; then
    if [[ -e "$BACKUP_SENTINEL" ]]; then
        NOW_EPOCH="$(date +%s)"
        MTIME="$(stat -c %Y "$BACKUP_SENTINEL" 2>/dev/null || echo 0)"
        AGE_HOURS=$(( (NOW_EPOCH - MTIME) / 3600 ))
        if (( AGE_HOURS > BACKUP_MAX_AGE_HOURS )); then fail 'Backup Freshness' "最后成功标记已 ${AGE_HOURS} 小时"
        else pass 'Backup Freshness' "最后成功标记 ${AGE_HOURS} 小时前"
        fi
    else
        fail 'Backup Freshness' "未找到 $BACKUP_SENTINEL"
    fi
fi

if [[ -f /var/run/reboot-required ]]; then
    warn 'Reboot Required' 'YES，需要重启服务器'; REBOOT_REQUIRED=1
else
    pass 'Reboot Required' 'NO'; REBOOT_REQUIRED=0
fi

if (( FAIL > 0 )); then STATUS='FAIL'; EXIT_CODE=20
elif (( WARN > 0 )); then STATUS='WARN'; EXIT_CODE=10
else STATUS='PASS'; EXIT_CODE=0
fi

{
    echo
    echo '------------------------------------------------------------'
    echo "Final status     : $STATUS"
    echo "PASS             : $PASS"
    echo "WARN             : $WARN"
    echo "FAIL             : $FAIL"
    echo "INFO             : $INFO"
    echo "Baseline changes : $CHANGES"
    echo "Reboot required  : $REBOOT_REQUIRED"
    echo '============================================================'
} >> "$REPORT_FILE"

{
    echo 'VPS Security Audit Summary'
    echo '------------------------------------------------------------'
    echo "Status           : $STATUS"
    echo "PASS/WARN/FAIL   : $PASS/$WARN/$FAIL"
    echo "Baseline changes : $CHANGES"
    echo "Reboot required  : $REBOOT_REQUIRED"
    echo
    cat "$REPORT_FILE"
} > "$MAIL_FILE"
chmod 600 "$REPORT_FILE" "$MAIL_FILE"

{
    printf 'AUDIT_STATUS=%q\n' "$STATUS"
    printf 'AUDIT_EXIT_CODE=%q\n' "$EXIT_CODE"
    printf 'PASS_COUNT=%q\n' "$PASS"
    printf 'WARN_COUNT=%q\n' "$WARN"
    printf 'FAIL_COUNT=%q\n' "$FAIL"
    printf 'CHANGE_ALERTS=%q\n' "$CHANGES"
    printf 'REBOOT_REQUIRED=%q\n' "$REBOOT_REQUIRED"
    printf 'REPORT_FILE=%q\n' "$REPORT_FILE"
    printf 'MAIL_FILE=%q\n' "$MAIL_FILE"
} > "$ENV_FILE"
chmod 600 "$ENV_FILE"

if (( QUIET == 0 )); then
    cat "$REPORT_FILE"
    echo
    echo '如确认所有新增基线项均合法：'
    echo 'sudo /usr/local/sbin/vpscheck-audit --accept-baseline --exit-zero'
fi

(( EXIT_ZERO == 1 )) && exit 0
exit "$EXIT_CODE" <<<"$UFW_ISOLATION_RULES"; then
            SSH_ISOLATION_REASON='UFW 显示 Tailscale 放行及双栈 SSH 拒绝；完整防火墙路径尚未证明'
        fi
    fi
    warn 'SSH Network Isolation' "$SSH_ISOLATION_REASON"
    case "$ROOT_LOGIN" in
        no) pass 'SSH Root Login' 'PermitRootLogin=no' ;;
        prohibit-password|without-password) info 'SSH Root Login' "PermitRootLogin=$ROOT_LOGIN；root 仅允许密钥登录" ;;
        yes) warn 'SSH Root Login' 'PermitRootLogin=yes' ;;
        *) info 'SSH Root Login' "PermitRootLogin=${ROOT_LOGIN:-unknown}" ;;
    esac
    if [[ "$SSH_PASSWORD_AUTH" == 'no' ]]; then
        pass 'SSH Password' 'PasswordAuthentication=no'
    elif [[ "$SSH_PASSWORD_AUTH" == 'yes' ]]; then
        warn 'SSH Password' 'PasswordAuthentication=yes'
    else
        info 'SSH Password' '无法确认 PasswordAuthentication'
    fi
    info 'SSH Port' "$SSH_PORT"
else
    info 'SSH' '未找到 sshd；跳过 SSH 配置检查'
fi

# Host firewall. This does not claim to see provider/cloud firewalls.
FW=''
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
    FW='ufw active'
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null | grep -q '^running$'; then
    FW='firewalld running'
elif command -v nft >/dev/null 2>&1 && nft list ruleset 2>/dev/null | grep -Eq 'hook input[^;{]*;[^}]*policy (drop|reject)|policy (drop|reject)[^}]*hook input'; then
    FW='nftables input default-deny'
elif command -v iptables >/dev/null 2>&1 && iptables -S INPUT 2>/dev/null | grep -Eq '^-P INPUT (DROP|REJECT)$'; then
    FW='iptables INPUT default-deny'
fi
if [[ -n "$FW" ]]; then
    pass 'Host Firewall' "$FW"
else
    case "$FIREWALL_POLICY" in
        strict) fail 'Host Firewall' '未确认宿主机入站默认拒绝；云防火墙不在本机可见范围' ;;
        ignore) info 'Host Firewall' '未确认宿主机默认拒绝；按配置仅记录信息' ;;
        *) warn 'Host Firewall' '未确认宿主机入站默认拒绝；可能另有云防火墙/上游 ACL' ;;
    esac
fi

# Brute-force protection adapts to SSH password policy.
if systemctl is-active --quiet fail2ban 2>/dev/null; then
    pass 'Fail2ban' 'service active'
    if command -v fail2ban-client >/dev/null 2>&1; then
        JAILS="$(fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:[[:space:]]*//p' | tr -d ' ' || true)"
        info 'Fail2ban Jails' "${JAILS:-无法读取}"
        if [[ ",${JAILS}," == *,sshd,* ]]; then
            if [[ "$SSH_PORT" == '22' ]]; then
                pass 'Fail2ban SSH' 'sshd jail active；SSH 使用端口 22'
            else
                info 'Fail2ban SSH' "sshd jail active；SSH=$SSH_PORT，非标准端口请结合 action 配置人工核对"
            fi
        elif command -v sshd >/dev/null 2>&1; then
            warn 'Fail2ban SSH' 'Fail2ban active，但未发现 sshd jail'
        fi
    fi
elif systemctl is-active --quiet crowdsec 2>/dev/null; then
    pass 'CrowdSec' 'service active'
elif [[ "$SSH_PASSWORD_AUTH" == 'yes' ]]; then
    warn 'Bruteforce Guard' 'SSH 密码登录开启，但未检测到 Fail2ban/CrowdSec active'
else
    info 'Bruteforce Guard' '未检测到 Fail2ban/CrowdSec；SSH 密码登录未开启或未安装 sshd'
fi

# systemd failed units, with per-host ignore list.
FAILED_RAW="$(systemctl --failed --no-legend --plain 2>/dev/null | awk 'NF{print $1}' || true)"
FAILED_KEEP=''
while IFS= read -r unit; do
    [[ -n "$unit" ]] || continue
    skip=0
    for ignored in $IGNORE_FAILED_UNITS; do
        [[ "$unit" == "$ignored" ]] && skip=1 && break
    done
    (( skip == 1 )) || FAILED_KEEP+="$unit "
done <<< "$FAILED_RAW"
FAILED_KEEP="${FAILED_KEEP% }"
if [[ -z "$FAILED_KEEP" ]]; then
    pass 'systemd' '无未忽略的 failed units'
else
    fail 'systemd' "failed: $FAILED_KEEP"
fi

# Disk usage. Exclude overlay/squashfs to avoid duplicate container views.
while read -r PCT MOUNT; do
    N="${PCT%%%}"
    [[ "$N" =~ ^[0-9]+$ ]] || continue
    if (( N >= 95 )); then fail 'Disk Usage' "$MOUNT ${N}%"
    elif (( N >= 85 )); then warn 'Disk Usage' "$MOUNT ${N}%"
    else pass 'Disk Usage' "$MOUNT ${N}%"
    fi
done < <(df -P -x tmpfs -x devtmpfs -x overlay -x squashfs 2>/dev/null | awk 'NR>1{print $5,$6}')

while read -r PCT MOUNT; do
    N="${PCT%%%}"
    [[ "$N" =~ ^[0-9]+$ ]] || continue
    if (( N >= 95 )); then fail 'Inode Usage' "$MOUNT ${N}%"
    elif (( N >= 85 )); then warn 'Inode Usage' "$MOUNT ${N}%"
    fi
done < <(df -Pi -x tmpfs -x devtmpfs -x overlay -x squashfs 2>/dev/null | awk 'NR>1{print $5,$6}')

# Memory / swap / load.
MEM_TOTAL="$(awk '/MemTotal/{print $2}' /proc/meminfo)"
MEM_AVAIL="$(awk '/MemAvailable/{print $2}' /proc/meminfo)"
if [[ "$MEM_TOTAL" =~ ^[0-9]+$ && "$MEM_AVAIL" =~ ^[0-9]+$ && "$MEM_TOTAL" -gt 0 ]]; then
    MEM_USED=$(( (MEM_TOTAL - MEM_AVAIL) * 100 / MEM_TOTAL ))
    if (( MEM_USED >= 95 )); then fail 'Memory' "${MEM_USED}% used"
    elif (( MEM_USED >= 90 )); then warn 'Memory' "${MEM_USED}% used"
    else pass 'Memory' "${MEM_USED}% used"
    fi
fi
SWAP_TOTAL="$(awk '/SwapTotal/{print $2}' /proc/meminfo)"
SWAP_FREE="$(awk '/SwapFree/{print $2}' /proc/meminfo)"
if [[ "$SWAP_TOTAL" =~ ^[0-9]+$ && "$SWAP_TOTAL" -gt 0 ]]; then
    SWAP_USED=$(( (SWAP_TOTAL - SWAP_FREE) * 100 / SWAP_TOTAL ))
    if (( SWAP_USED >= 90 )); then warn 'Swap' "${SWAP_USED}% used"
    else info 'Swap' "${SWAP_USED}% used"
    fi
else
    info 'Swap' 'not configured'
fi
LOAD1="$(awk '{print $1}' /proc/loadavg 2>/dev/null || true)"
CPU_N="$(nproc 2>/dev/null || echo 1)"
info 'Load Average' "1m=$LOAD1 CPUs=$CPU_N"

# Docker, only if present / requested.
RUN_DOCKER=0
if [[ "$CHECK_DOCKER" == 'true' ]]; then RUN_DOCKER=1
elif [[ "$CHECK_DOCKER" == 'auto' ]] && command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then RUN_DOCKER=1
fi
if (( RUN_DOCKER == 1 )); then
    if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
        BAD_DOCKER="$(docker ps -a --format '{{.Names}}|{{.Status}}' 2>/dev/null | grep -Ei 'unhealthy|restarting|dead' || true)"
        if [[ -z "$BAD_DOCKER" ]]; then pass 'Docker Health' '无 unhealthy/restarting/dead 容器'
        else warn 'Docker Health' "异常容器: $(echo "$BAD_DOCKER" | paste -sd ';' -)"
        fi
        PRIV=''; SOCK=''; HOSTNET=''
        while read -r CID; do
            [[ -n "$CID" ]] || continue
            NAME="$(docker inspect -f '{{.Name}}' "$CID" 2>/dev/null | sed 's#^/##')"
            [[ "$(docker inspect -f '{{.HostConfig.Privileged}}' "$CID" 2>/dev/null)" == true ]] && PRIV+="$NAME "
            docker inspect -f '{{range .Mounts}}{{.Source}}=>{{.Destination}} {{end}}' "$CID" 2>/dev/null | grep -q '/var/run/docker.sock' && SOCK+="$NAME " || true
            [[ "$(docker inspect -f '{{.HostConfig.NetworkMode}}' "$CID" 2>/dev/null)" == 'host' ]] && HOSTNET+="$NAME "
        done < <(docker ps -q 2>/dev/null)
        [[ -z "$PRIV" ]] && pass 'Docker Privileged' '无 privileged 容器' || warn 'Docker Privileged' "$PRIV"
        [[ -z "$SOCK" ]] && pass 'Docker Socket' '运行中容器未挂载 docker.sock' || warn 'Docker Socket' "挂载 docker.sock: $SOCK"
        [[ -z "$HOSTNET" ]] || info 'Docker Host Network' "$HOSTNET"
    else
        warn 'Docker' '配置要求检查 Docker，但 daemon 不可用'
    fi
else
    info 'Docker' '未安装/未运行，或检查被关闭'
fi

# Let's Encrypt certificates only; other TLS stacks remain informationally out of scope.
RUN_TLS=0
if [[ "$CHECK_TLS" == 'true' ]]; then RUN_TLS=1
elif [[ "$CHECK_TLS" == 'auto' ]] && compgen -G '/etc/letsencrypt/live/*/cert.pem' >/dev/null; then RUN_TLS=1
fi
if (( RUN_TLS == 1 )); then
    CERT_FOUND=0
    for cert in /etc/letsencrypt/live/*/cert.pem; do
        [[ -f "$cert" ]] || continue
        CERT_FOUND=1
        NAME="$(basename "$(dirname "$cert")")"
        END="$(openssl x509 -enddate -noout -in "$cert" 2>/dev/null | cut -d= -f2 || true)"
        if [[ -n "$END" ]]; then
            END_EPOCH="$(date -d "$END" +%s 2>/dev/null || echo 0)"
            NOW_EPOCH="$(date +%s)"
            DAYS=$(( (END_EPOCH - NOW_EPOCH) / 86400 ))
            if (( DAYS <= 7 )); then fail 'TLS Certificate' "$NAME 剩余 ${DAYS} 天"
            elif (( DAYS <= 21 )); then warn 'TLS Certificate' "$NAME 剩余 ${DAYS} 天"
            else pass 'TLS Certificate' "$NAME 剩余 ${DAYS} 天"
            fi
        fi
    done
    (( CERT_FOUND == 1 )) || info 'TLS Certificate' '未发现 Let’s Encrypt cert.pem'
else
    info 'TLS Certificate' '未检测到 Let’s Encrypt 证书或检查被关闭'
fi

# sudo logging: don't fail on distributions using different journal arrangements.
if journalctl -t sudo -n 1 --no-pager 2>/dev/null | grep -q . || grep -q 'sudo:' /var/log/auth.log 2>/dev/null || grep -RqsE '^[[:space:]]*Defaults.*logfile' /etc/sudoers /etc/sudoers.d 2>/dev/null; then
    pass 'Sudo Logging' '检测到 sudo 日志或显式日志配置'
else
    info 'Sudo Logging' '未确认；日志后端可能因系统配置不同'
fi

baseline_check() {
    local key="$1" label="$2" current="$3"
    local base="$BASE_DIR/$key.baseline" added="$TMP_DIR/$key.added"
    sort -u "$current" -o "$current" 2>/dev/null || true
    if (( ACCEPT_BASELINE == 1 )) || [[ ! -f "$base" ]]; then
        cp -f "$current" "$base"
        chmod 600 "$base"
        if (( ACCEPT_BASELINE == 1 )); then pass "$label" '已接受当前状态为新基线'
        else info "$label" '首次建立基线；以后发现新增项将报警'
        fi
        return
    fi
    comm -13 "$base" "$current" > "$added" 2>/dev/null || true
    if [[ -s "$added" ]]; then
        local count
        count="$(wc -l < "$added")"
        CHANGES=$(( CHANGES + count ))
        warn "$label" "发现 $count 个相对基线的新增项：$(head -n 8 "$added" | paste -sd ';' -)"
    else
        pass "$label" '无新增项'
    fi
}

# Stable network listener baseline: protocol + local address/port only.
if [[ "$CHECK_LISTENERS" == 'true' ]]; then
    LISTEN="$TMP_DIR/listeners"
    ss -H -lntu 2>/dev/null | awk '{proto=$1; local=$5; if (local ~ /^127\./ || local ~ /^\[::1\]:/ || local ~ /^::1:/) next; print proto "|" local}' | sort -u > "$LISTEN"
    if [[ -n "$IGNORE_LISTENER_REGEX" ]]; then
        grep -Ev "$IGNORE_LISTENER_REGEX" "$LISTEN" > "$LISTEN.filtered" || true
        mv "$LISTEN.filtered" "$LISTEN"
    fi
    NET_BASE="$BASE_DIR/network-listeners.baseline"
    if [[ -f "$NET_BASE" ]] && awk -F'|' 'NF>2{found=1} END{exit found?0:1}' "$NET_BASE"; then
        mv "$NET_BASE" "${NET_BASE}.legacy-${STAMP}"
        info 'Network Listeners' '检测到旧版 PID-sensitive 基线，已自动迁移为稳定格式'
    fi
    baseline_check 'network-listeners' 'Network Listeners' "$LISTEN"
fi

# Authorized keys baseline stores hashes only.
if [[ "$CHECK_AUTHORIZED_KEYS" == 'true' ]]; then
    KEYS="$TMP_DIR/authorized_keys"; : > "$KEYS"
    while IFS=: read -r user _ uid _ _ home _; do
        [[ "$uid" =~ ^[0-9]+$ ]] || continue
        (( uid == 0 || uid >= 1000 )) || continue
        for f in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
            [[ -f "$f" ]] || continue
            while IFS= read -r k; do
                [[ -n "$k" && "$k" != \#* ]] || continue
                printf '%s|%s\n' "$user" "$(printf '%s' "$k" | sha256sum | awk '{print $1}')" >> "$KEYS"
            done < "$f"
        done
    done < /etc/passwd
    baseline_check 'authorized-keys' 'Authorized Keys' "$KEYS"
fi

# Host-only SUID/SGID baseline. Container/VM image roots are pruned.
if [[ "$CHECK_SUID" == 'true' ]]; then
    SUID="$TMP_DIR/suid"; : > "$SUID"
    if ! timeout "${SUID_TIMEOUT_SECONDS}s" find /usr /bin /sbin /opt /root /home /var -xdev \
        \( -path '/var/lib/docker' -o -path '/var/lib/docker/*' -o -path '/var/lib/containerd' -o -path '/var/lib/containerd/*' -o -path '/var/lib/containers' -o -path '/var/lib/containers/*' -o -path '/var/lib/kubelet' -o -path '/var/lib/kubelet/*' -o -path '/var/lib/lxc' -o -path '/var/lib/lxc/*' -o -path '/var/lib/lxd' -o -path '/var/lib/lxd/*' -o -path '/var/lib/incus' -o -path '/var/lib/incus/*' -o -path '/var/lib/machines' -o -path '/var/lib/machines/*' \) -prune -o \
        -type f \( -perm -4000 -o -perm -2000 \) -printf '%p|%u|%g|%m\n' 2>/dev/null | sort -u > "$SUID"; then
        warn 'SUID/SGID Scan' "扫描超过 ${SUID_TIMEOUT_SECONDS}s 或部分目录不可读"
    fi
    SUID_BASE="$BASE_DIR/suid-sgid.baseline"
    if [[ -f "$SUID_BASE" ]] && grep -Eq '^/var/lib/(docker|containerd|containers|kubelet|lxc|lxd|incus|machines)/' "$SUID_BASE"; then
        mv "$SUID_BASE" "${SUID_BASE}.legacy-${STAMP}"
        info 'SUID/SGID Baseline' '检测到旧版容器镜像条目，已自动重建 Host-only 基线'
    fi
    baseline_check 'suid-sgid' 'SUID/SGID Baseline' "$SUID"
fi

# File capabilities baseline, filtered to exclude container storage roots.
if [[ "$CHECK_CAPABILITIES" == 'true' ]] && command -v getcap >/dev/null 2>&1; then
    CAPS="$TMP_DIR/capabilities"; : > "$CAPS"
    if ! timeout "${CAP_TIMEOUT_SECONDS}s" getcap -r /usr /bin /sbin /opt /root /home /var 2>/dev/null | awk '!/^\/var\/lib\/(docker|containerd|containers|kubelet|lxc|lxd|incus|machines)\//' | sort -u > "$CAPS"; then
        warn 'Capabilities Scan' "扫描超过 ${CAP_TIMEOUT_SECONDS}s 或部分目录不可读"
    fi
    CAP_BASE="$BASE_DIR/capabilities.baseline"
    if [[ -f "$CAP_BASE" ]] && grep -Eq '^/var/lib/(docker|containerd|containers|kubelet|lxc|lxd|incus|machines)/' "$CAP_BASE"; then
        mv "$CAP_BASE" "${CAP_BASE}.legacy-${STAMP}"
        info 'File Capabilities' '检测到旧版容器镜像条目，已自动重建 Host-only 基线'
    fi
    baseline_check 'capabilities' 'File Capabilities' "$CAPS"
fi

# Optional backup freshness sentinel.
if [[ -n "$BACKUP_SENTINEL" ]]; then
    if [[ -e "$BACKUP_SENTINEL" ]]; then
        NOW_EPOCH="$(date +%s)"
        MTIME="$(stat -c %Y "$BACKUP_SENTINEL" 2>/dev/null || echo 0)"
        AGE_HOURS=$(( (NOW_EPOCH - MTIME) / 3600 ))
        if (( AGE_HOURS > BACKUP_MAX_AGE_HOURS )); then fail 'Backup Freshness' "最后成功标记已 ${AGE_HOURS} 小时"
        else pass 'Backup Freshness' "最后成功标记 ${AGE_HOURS} 小时前"
        fi
    else
        fail 'Backup Freshness' "未找到 $BACKUP_SENTINEL"
    fi
fi

if [[ -f /var/run/reboot-required ]]; then
    warn 'Reboot Required' 'YES，需要重启服务器'; REBOOT_REQUIRED=1
else
    pass 'Reboot Required' 'NO'; REBOOT_REQUIRED=0
fi

if (( FAIL > 0 )); then STATUS='FAIL'; EXIT_CODE=20
elif (( WARN > 0 )); then STATUS='WARN'; EXIT_CODE=10
else STATUS='PASS'; EXIT_CODE=0
fi

{
    echo
    echo '------------------------------------------------------------'
    echo "Final status     : $STATUS"
    echo "PASS             : $PASS"
    echo "WARN             : $WARN"
    echo "FAIL             : $FAIL"
    echo "INFO             : $INFO"
    echo "Baseline changes : $CHANGES"
    echo "Reboot required  : $REBOOT_REQUIRED"
    echo '============================================================'
} >> "$REPORT_FILE"

{
    echo 'VPS Security Audit Summary'
    echo '------------------------------------------------------------'
    echo "Status           : $STATUS"
    echo "PASS/WARN/FAIL   : $PASS/$WARN/$FAIL"
    echo "Baseline changes : $CHANGES"
    echo "Reboot required  : $REBOOT_REQUIRED"
    echo
    cat "$REPORT_FILE"
} > "$MAIL_FILE"
chmod 600 "$REPORT_FILE" "$MAIL_FILE"

{
    printf 'AUDIT_STATUS=%q\n' "$STATUS"
    printf 'AUDIT_EXIT_CODE=%q\n' "$EXIT_CODE"
    printf 'PASS_COUNT=%q\n' "$PASS"
    printf 'WARN_COUNT=%q\n' "$WARN"
    printf 'FAIL_COUNT=%q\n' "$FAIL"
    printf 'CHANGE_ALERTS=%q\n' "$CHANGES"
    printf 'REBOOT_REQUIRED=%q\n' "$REBOOT_REQUIRED"
    printf 'REPORT_FILE=%q\n' "$REPORT_FILE"
    printf 'MAIL_FILE=%q\n' "$MAIL_FILE"
} > "$ENV_FILE"
chmod 600 "$ENV_FILE"

if (( QUIET == 0 )); then
    cat "$REPORT_FILE"
    echo
    echo '如确认所有新增基线项均合法：'
    echo 'sudo /usr/local/sbin/vpscheck-audit --accept-baseline --exit-zero'
fi

(( EXIT_ZERO == 1 )) && exit 0
exit "$EXIT_CODE"