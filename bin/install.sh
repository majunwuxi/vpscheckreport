#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
(( EUID == 0 )) || { echo '请使用 sudo/root'; exit 1; }
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
[[ -r "$ROOT/bin/vpscheck-audit.sh" && -r "$ROOT/bin/vpscheck-maintain.sh" ]] || { echo '安装文件不完整'; exit 1; }
[[ -r /dev/tty ]] || { echo '需要 SSH 交互终端'; exit 1; }
exec 3</dev/tty
ask() { printf '%s' "$1" >/dev/tty; IFS= read -r "$2" <&3; }
LEGACY=0
for f in /usr/local/sbin/daily-apt-upgrade.sh /usr/local/sbin/wellmax-vps-audit; do [[ -e "$f" ]] && LEGACY=1; done
for u in daily-apt-upgrade.timer daily-apt-upgrade.service; do systemctl cat "$u" >/dev/null 2>&1 && LEGACY=1; done
if crontab -l 2>/dev/null | grep -Eq 'daily-apt-upgrade|wellmax-vps-audit'; then LEGACY=1; fi
if grep -REql 'daily-apt-upgrade|wellmax-vps-audit' /etc/cron.d /etc/cron.daily /etc/crontab 2>/dev/null; then LEGACY=1; fi
echo '自动升级安装：验证邮件后自动切换新旧定时器，并备份旧版代码。'
(( LEGACY )) && echo '检测到旧版：成功切换后停用旧版调度并归档旧脚本。'
ask '输入 YES 继续：' confirm
[[ "$confirm" == YES ]] || { echo '取消'; exit 0; }
for c in python3 ss find timeout flock curl openssl; do command -v "$c" >/dev/null || { echo "缺少依赖：$c"; exit 1; }; done
backup="/var/backups/vpscheckreport/$(date -u +%Y%m%dT%H%M%SZ)"
install -d -m 0700 "$backup" /etc/vpscheckreport /var/lib/vpscheckreport /var/log/vpscheckreport /usr/local/lib/vpscheckreport
for f in /usr/local/sbin/vpscheck-audit /usr/local/sbin/vpscheck-maintain /usr/local/lib/vpscheckreport/ssh-attack-report.py /usr/local/lib/vpscheckreport/ssh-isolation.py /usr/local/lib/vpscheckreport/mail-send.py /etc/vpscheckreport/config /etc/vpscheckreport/audit.conf /etc/vpscheckreport/mail.ini /etc/systemd/system/vpscheckreport.service /etc/systemd/system/vpscheckreport.timer; do
 if [[ -f "$f" ]]; then mkdir -p "$backup$(dirname "$f")"; cp -a "$f" "$backup$f"; fi
done
install -m 0755 "$ROOT/bin/vpscheck-audit.sh" /usr/local/sbin/vpscheck-audit
install -m 0755 "$ROOT/bin/vpscheck-maintain.sh" /usr/local/sbin/vpscheck-maintain
install -m 0755 "$ROOT/bin/ssh-attack-report.py" /usr/local/lib/vpscheckreport/ssh-attack-report.py
install -m 0755 "$ROOT/bin/ssh-isolation.py" /usr/local/lib/vpscheckreport/ssh-isolation.py
install -m 0755 "$ROOT/bin/mail-send.py" /usr/local/lib/vpscheckreport/mail-send.py
install -m 0644 "$ROOT/systemd/vpscheckreport.service" /etc/systemd/system/vpscheckreport.service
install -m 0644 "$ROOT/systemd/vpscheckreport.timer" /etc/systemd/system/vpscheckreport.timer
if [[ ! -e /etc/vpscheckreport/config ]]; then printf 'ALLOW_AUTOREMOVE=false\n' > /etc/vpscheckreport/config; chmod 600 /etc/vpscheckreport/config; fi
if [[ ! -e /etc/vpscheckreport/mail.ini ]]; then
 echo '1) 普通 SMTP  2) Gmail 应用专用密码'
 ask '选择 [1/2]：' method
 if [[ "$method" == 2 ]]; then host=smtp.gmail.com; port=465; security=ssl
 else
  ask 'SMTP 服务器：' host
  ask '端口 [587]：' port; port="${port:-587}"
  ask '加密 starttls/ssl [starttls]：' security; security="${security:-starttls}"
 fi
 [[ "$security" == ssl || "$security" == starttls ]] || { echo '禁止明文 SMTP'; exit 1; }
 [[ "$port" =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 65535 )) || { echo '无效端口'; exit 1; }
 ask '发件邮箱：' sender
 ask '收件邮箱：' recipient
 ask '登录用户名（回车默认与发件邮箱相同）：' username
 username="${username:-$sender}"
 if [[ "$host" == smtp.gmail.com && "$username" != "$sender" ]]; then
  echo '警告：Gmail 登录用户名与发件邮箱不同。'
  ask '继续使用不同账号？输入 YES：' mismatch_ok
  [[ "$mismatch_ok" == YES ]] || exit 1
 fi
 printf 'SMTP 密码 / Gmail 应用专用密码：' >/dev/tty
 IFS= read -rs password <&3; printf '\n' >/dev/tty
 export HOST="$host" PORT="$port" SEC="$security" FROM="$sender" TO="$recipient" USERNAME="$username" PASSWORD="$password"
 python3 - <<'PY'
import configparser,os
c=configparser.ConfigParser(interpolation=None)
c['smtp']={k:os.environ[v] for k,v in [('host','HOST'),('port','PORT'),('security','SEC'),('from','FROM'),('to','TO'),('username','USERNAME'),('password','PASSWORD')]}
with open('/etc/vpscheckreport/mail.ini','w') as f:c.write(f)
PY
 unset password PASSWORD
 chmod 600 /etc/vpscheckreport/mail.ini
fi
systemctl daemon-reload
echo '正在发送 SMTP 验证邮件……'
test_body="$(mktemp)"
printf 'VPSCheckReport SMTP verification\nHost: %s\nTime: %s\n' "$(hostname -f 2>/dev/null || hostname)" "$(date -u +%FT%TZ)" > "$test_body"
if python3 /usr/local/lib/vpscheckreport/mail-send.py --subject '[VPSCheckReport] SMTP installation verification' --body "$test_body"; then
 echo 'SMTP 验证：服务器已接受测试邮件。请检查收件箱（含垃圾邮件）。'
else
 echo 'SMTP 验证失败：请修正 /etc/vpscheckreport/mail.ini 后重试。' >&2
 rm -f "$test_body"
 exit 1
fi
rm -f "$test_body"
# 自动迁移已知的 Wellmax 旧版 systemd 调度；未知 cron 引用必须人工确认。
legacy_units=(daily-apt-upgrade.timer daily-apt-upgrade.service)
legacy_files=(/usr/local/sbin/daily-apt-upgrade.sh /usr/local/sbin/wellmax-vps-audit /etc/systemd/system/daily-apt-upgrade.timer /etc/systemd/system/daily-apt-upgrade.service)
if crontab -l 2>/dev/null | grep -Eq 'daily-apt-upgrade|wellmax-vps-audit' || grep -REq 'daily-apt-upgrade|wellmax-vps-audit' /etc/cron.d /etc/cron.daily /etc/crontab 2>/dev/null; then
 echo '检测到旧版 cron 调度：为避免重复执行，已停止自动切换；请先检查 cron 来源。' >&2
 exit 1
fi
for f in "${legacy_files[@]}"; do
 if [[ -f "$f" ]]; then
  mkdir -p "$backup$(dirname "$f")"
  cp -a "$f" "$backup$f"
 fi
done
old_enabled=0
old_active=0
systemctl is-enabled --quiet daily-apt-upgrade.timer 2>/dev/null && old_enabled=1
systemctl is-active --quiet daily-apt-upgrade.timer 2>/dev/null && old_active=1
if systemctl is-active --quiet daily-apt-upgrade.service 2>/dev/null; then
 echo '旧版维护服务仍在执行，拒绝切换；稍后重新运行安装程序。' >&2
 exit 1
fi
if systemctl is-active --quiet vpscheckreport.service 2>/dev/null; then
 echo '新版维护服务正在执行，拒绝切换。' >&2
 exit 1
fi
rollback_migration() {
 local rc=$?
 trap - ERR
 echo "切换失败（状态码 $rc），正在恢复原定时器状态……" >&2
 systemctl disable --now vpscheckreport.timer >/dev/null 2>&1 || true
 if (( old_enabled )); then systemctl enable daily-apt-upgrade.timer >/dev/null 2>&1 || true; fi
 if (( old_active )); then systemctl start daily-apt-upgrade.timer >/dev/null 2>&1 || true; fi
 exit "$rc"
}
trap rollback_migration ERR
echo '正在自动切换新旧定时任务……'
systemctl disable --now daily-apt-upgrade.timer 2>/dev/null || {
 if (( old_enabled || old_active )); then echo '无法停用旧版定时器' >&2; false; fi
}
systemctl enable --now vpscheckreport.timer
systemctl is-enabled --quiet vpscheckreport.timer
systemctl is-active --quiet vpscheckreport.timer
if systemctl is-active --quiet daily-apt-upgrade.timer; then
 echo '旧版定时器仍在运行，拒绝归档旧代码。' >&2
 false
fi
# 只有在新调度验证成功后，才将旧版可执行脚本移出运行路径。
# systemd 单元保留为 disabled，便于故障回退；所有原始文件已备份。
for f in /usr/local/sbin/daily-apt-upgrade.sh /usr/local/sbin/wellmax-vps-audit; do
 if [[ -f "$f" ]]; then mv "$f" "$backup$f"; fi
done
trap - ERR
echo "升级完成：新版定时器已启用，旧版定时器已停用；旧版脚本已归档。备份：$backup"
echo '计划执行：每天北京时间 00:15，随机延迟最多 5 分钟。'
echo '检查：systemctl list-timers --all vpscheckreport.timer'
