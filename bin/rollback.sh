#!/usr/bin/env bash
set -Eeuo pipefail
(( EUID == 0 )) || { echo '需要 sudo/root'; exit 1; }
backup="${1:-}"
[[ -n "$backup" && -d "$backup" && "$backup" == /var/backups/vpscheckreport/* ]] || { echo '用法: sudo bash rollback.sh /var/backups/vpscheckreport/<备份目录>'; exit 2; }
systemctl disable --now vpscheckreport.timer >/dev/null 2>&1 || true
while IFS= read -r -d '' f; do
 target="${f#"$backup"}"
 [[ "$target" == /* ]] || continue
 install -d -m 0755 "$(dirname "$target")"
 cp -a "$f" "$target"
done < <(find "$backup" -type f -print0)
systemctl daemon-reload
echo '已停止新版定时器并恢复备份中存在的文件。旧版调度未修改。'
