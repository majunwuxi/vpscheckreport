#!/usr/bin/env bash
set -uo pipefail
umask 077
source /etc/vpscheckreport/config
DIR=/var/log/vpscheckreport;STATE=/var/lib/vpscheckreport
mkdir -p "$DIR" "$STATE"
R="$DIR/audit-$(date +%Y%m%d-%H%M%S).txt"
P=0;W=0;F=0
line(){ printf '%-6s | %-22s | %s\n' "$1" "$2" "$3" >> "$R"; }
pass(){ P=$((P+1));line PASS "$1" "$2"; }
warn(){ W=$((W+1));line WARN "$1" "$2"; }
info(){ line INFO "$1" "$2"; }
printf 'VPSCheckReport Security Audit: %s\n' "$(hostname)" > "$R"
info Kernel "$(uname -r)"
if command -v sshd >/dev/null 2>&1;then
 conf="$(sshd -T 2>&1)";rc=$?
 if ((rc));then warn SSH "配置无法读取：${conf:0:150}"
 else
  root="$(awk '$1=="permitrootlogin"{print $2;exit}' <<< "$conf")"
  password="$(awk '$1=="passwordauthentication"{print $2;exit}' <<< "$conf")"
  [[ "$root" == no || "$root" == prohibit-password || "$root" == without-password ]] && pass 'SSH root' "$root" || warn 'SSH root' "$root"
  [[ "$password" == no ]] && pass 'SSH password' disabled || warn 'SSH password' "$password"
 fi
else info SSH 'Not installed';fi
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q 'Status: active';then pass Firewall 'UFW active'
elif command -v nft >/dev/null && nft list ruleset 2>/dev/null | grep -Eq 'policy drop|policy reject';then pass Firewall 'nftables drop policy detected'
else warn Firewall '默认拒绝规则未确认';fi
systemctl is-active --quiet fail2ban && pass Fail2ban active || warn Fail2ban inactive
if command -v tailscale >/dev/null;then info Tailscale "$(tailscale ip -4 2>/dev/null | head -1)";fi
if command -v ss >/dev/null;then
 echo '===== NETWORK LISTENERS =====' >> "$R"
 ss -lntup 2>/dev/null | head -100 >> "$R"
else warn 'Network Listeners' 'ss unavailable';fi
keys=0
for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys;do
 [[ -r "$f" ]] || continue
 n="$(grep -Ec '^(ssh-|ecdsa-|sk-)' "$f" || true)";keys=$((keys+n))
done
info 'Authorized Keys' "$keys keys"
if [[ "${CHECK_SUID:-true}" == true ]];then
 timeout 90 find /usr /bin /sbin /opt -xdev -type f \( -perm -4000 -o -perm -2000 \) -printf '%p\n' > "$STATE/suid.txt" 2>/dev/null
 rc=$?; if ((rc));then warn SUID/SGID "扫描不完整，退出代码 $rc";else pass SUID/SGID 'scan finished';fi
fi
if command -v getcap >/dev/null;then
 timeout 60 getcap -r /usr /bin /sbin /opt > "$STATE/capabilities.txt" 2>/dev/null
 rc=$?;if ((rc));then warn Capabilities "扫描不完整，退出代码 $rc";else pass Capabilities 'scan finished';fi
fi
info Disk "$(df -h / | awk 'NR==2{print $5}')"
info Memory "$(free -m | awk '/^Mem:/{printf "%s/%s MB",$3,$2}')"
[[ -f /run/reboot-required ]] && warn Reboot YES || pass Reboot NO
attack="$(python3 /usr/local/lib/vpscheckreport/ssh-attack-report.py --json-output "$STATE/latest-attacks.json" 2>&1)"
rc=$?;if ((rc));then warn 'Attack data' 'SSH 日志不足';else info 'Attack data' '已统计';fi
{ echo '===== SSH FAILURES / FAIL2BAN BANS =====';printf '%s\n' "$attack";echo "PASS=$P WARN=$W FAIL=$F";} >> "$R"
cp "$R" "$STATE/latest-audit.txt"
printf 'PASS_COUNT=%s\nWARN_COUNT=%s\nFAIL_COUNT=%s\n' "$P" "$W" "$F" > "$STATE/latest.env"
chmod 600 "$R" "$STATE/latest-audit.txt" "$STATE/latest.env"
cat "$R"
