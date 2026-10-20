#!/usr/bin/env bash
set -euo pipefail
((EUID==0)) || { echo 'Please use sudo' >&2;exit 1; }
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
apt-get update
apt-get install -y python3 iproute2 util-linux findutils libcap2-bin ca-certificates
install -d -m 0700 /etc/vpscheckreport /var/lib/vpscheckreport /var/log/vpscheckreport
install -d -m 0755 /usr/local/lib/vpscheckreport
install -m 0755 "$ROOT/bin/ssh-attack-report.py" /usr/local/lib/vpscheckreport/
install -m 0755 "$ROOT/bin/mail-send.py" /usr/local/lib/vpscheckreport/
install -m 0755 "$ROOT/bin/vpscheck-audit.sh" /usr/local/sbin/vpscheck-audit
install -m 0755 "$ROOT/bin/vpscheck-maintain.sh" /usr/local/sbin/vpscheck-maintain
install -m 0644 "$ROOT/systemd/vpscheckreport.service" /etc/systemd/system/
install -m 0644 "$ROOT/systemd/vpscheckreport.timer" /etc/systemd/system/
if [[ ! -e /etc/vpscheckreport/config ]];then
 printf 'RUN_UPDATES=true\nCHECK_SUID=true\n' > /etc/vpscheckreport/config
 chmod 600 /etc/vpscheckreport/config
fi
if [[ ! -e /etc/vpscheckreport/mail.ini ]];then
 echo '1) Standard SMTP (TLS)'
 echo '2) Gmail App Password'
 read -rp 'Choose [1/2]: ' mode </dev/tty
 if [[ "$mode" == 2 ]];then
  host=smtp.gmail.com;port=465;security=ssl
 else
  read -rp 'SMTP host: ' host </dev/tty
  read -rp 'Port [587]: ' port </dev/tty;port=${port:-587}
  read -rp 'Security starttls/ssl [starttls]: ' security </dev/tty;security=${security:-starttls}
 fi
 [[ "$security" == ssl || "$security" == starttls ]] || exit 1
 [[ "$port" =~ ^[0-9]+$ ]] || exit 1
 read -rp 'From address: ' sender </dev/tty
 read -rp 'To address: ' recipient </dev/tty
 read -rp 'SMTP username: ' user </dev/tty
 read -rsp 'SMTP password or Gmail app password: ' password </dev/tty;echo
 MAIL_HOST="$host" MAIL_PORT="$port" MAIL_SECURITY="$security" MAIL_FROM="$sender" MAIL_TO="$recipient" MAIL_USER="$user" MAIL_PASS="$password" python3 - <<'PY'
import configparser,os
c=configparser.ConfigParser(interpolation=None)
c['smtp']={'host':os.environ['MAIL_HOST'],'port':os.environ['MAIL_PORT'],'security':os.environ['MAIL_SECURITY'],'from':os.environ['MAIL_FROM'],'to':os.environ['MAIL_TO'],'username':os.environ['MAIL_USER'],'password':os.environ['MAIL_PASS']}
with open('/etc/vpscheckreport/mail.ini','w') as f:c.write(f)
PY
 chmod 600 /etc/vpscheckreport/mail.ini
 unset password
else echo 'Existing mail configuration preserved';fi
systemctl daemon-reload
legacy=0
for unit in daily-apt-upgrade.timer daily-apt-upgrade.service; do
 systemctl cat "$unit" >/dev/null 2>&1 && legacy=1
done
for file in /usr/local/sbin/daily-apt-upgrade.sh /usr/local/sbin/wellmax-vps-audit; do
 [[ -e "$file" ]] && legacy=1
done
if crontab -l 2>/dev/null | grep -Eq 'daily-apt-upgrade|wellmax-vps-audit'; then legacy=1; fi
if grep -REql 'daily-apt-upgrade|wellmax-vps-audit' /etc/cron.d /etc/cron.daily /etc/crontab 2>/dev/null; then legacy=1; fi
# Staging-only: do not activate any timer until migration tests pass.
systemctl disable --now vpscheckreport.timer 2>/dev/null || true
if ((legacy)); then
 echo '检测到旧版：仅安装新版文件；保留旧版定时任务。'
else
 echo '首次安装：仅安装新版文件；安全审查通过后再启用定时任务。'
fi
echo 'Installed. Test: sudo /usr/local/sbin/vpscheck-audit'
