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
echo '安全预览安装：只安装文件，不启用新版定时器。'
(( LEGACY )) && echo '检测到旧版，旧版程序与调度保持不变。'
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
if ! systemctl is-enabled --quiet vpscheckreport.timer 2>/dev/null; then
 systemctl disable --now vpscheckreport.timer >/dev/null 2>&1 || true
fi
echo "安装完毕，新版定时器未启用；旧版未修改。备份：$backup"
echo '只读巡检：sudo /usr/local/sbin/vpscheck-audit --quiet --exit-zero'
