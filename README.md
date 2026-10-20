# VPSCheckReport 3.0 preview

Ubuntu 每日更新、安全巡检、SSH 登录攻击与 Fail2ban 封禁统计。邮件支持普通 SMTP STARTTLS/SSL 和 Gmail 应用专用密码。

**预览版：目前通过本地静态检查及 4 项 SSH 统计单元测试，尚未在 GreenCloud 上端到端验证；禁止直接切换生产调度。**

## 一键安装（仅部署，不启用）

```bash
curl -fsSL https://raw.githubusercontent.com/majunwuxi/vpscheckreport/main/install.sh | sudo bash
```

需要 SSH 交互终端。安装会检查旧版服务、cron 和脚本，保留旧版程序和定时任务；无论有无旧版，**均不自动启用新版 timer**。SMTP 密码配置为仅 root 可读。

安装后仅执行巡检（不更新、不发邮件）：

```bash
sudo /usr/local/sbin/vpscheck-audit --quiet --exit-zero
```

## 兼容与变更

- 基于 GreenCloud 原版 v2.0.1 完整迁入 SSH、firewall、Fail2ban、systemd、磁盘、内存、Docker、TLS、sudo、监听端口、authorized_keys、SUID/SGID、capabilities、备份与 reboot 检查。
- 新版状态目录为 `/var/lib/vpscheckreport/audit`，**首次执行会建立新基线，尚未继承旧基线**。
- 更新保留原版完整日志、审计状态与邮件摘要；为避免删除关键软件包，默认采用 `apt-get -y --no-remove upgrade` 而非 `dist-upgrade`；默认跳过 `autoremove`（设置 `ALLOW_AUTOREMOVE=true` 可启用）。
- 攻击窗口为北京时间前一日 01:00 到当日 01:00，计划 01:15 运行，公网 IP 排名排除 Tailscale/CGNAT。
- 日报含 SSH 攻击统计，JSON 写入 `/var/lib/vpscheckreport/latest-attacks.json`。

## 备份和回滚

已有新版文件会备份至 `/var/backups/vpscheckreport/<时间戳>/`。在克隆仓库目录中执行：

```bash
sudo bash bin/rollback.sh /var/backups/vpscheckreport/<时间戳>
```

回滚停止新版 timer 并恢复备份中存在的文件，不自动删除首次安装文件、不改变旧版调度。

## 验证

```bash
bash -n install.sh bin/*.sh
python3 -m py_compile bin/*.py
python3 -m unittest discover -s tests -v
systemd-analyze calendar '*-*-* 01:15:00 Asia/Shanghai'
```

离线 4 项测试通过，但 SMTP 实发、Ubuntu apt 流程、日志轮转覆盖、旧版到新版切换、回滚演练仍需在隔离测试机验证。参见 `docs/MIGRATION_CHECKLIST.md`。
