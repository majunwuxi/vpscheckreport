# VPSCheckReport 3.0

适用于 Ubuntu VPS 的每日系统更新、安全巡检、SSH 登录攻击与 Fail2ban 封禁统计，以及邮件报告。支持普通 SMTP（STARTTLS/SSL）与 Gmail 应用专用密码。

## 一键安装与升级

```bash
curl -fsSL https://raw.githubusercontent.com/majunwuxi/vpscheckreport/main/install.sh | sudo bash
```

需在 SSH 交互终端中运行，并输入 `YES` 确认。安装程序会：

1. 检查旧版 Wellmax 维护脚本、systemd 服务、定时器及相关 cron 配置。
2. 备份已有新版文件、旧版服务配置与旧版脚本至 `/var/backups/vpscheckreport/<UTC时间戳>/`。
3. 安装新版维护、安全巡检及邮件组件。
4. 如果 `/etc/vpscheckreport/mail.ini` 已包含完整 SMTP 配置及非空密码，则**自动沿用原配置**，无需重新输入 Gmail 应用专用密码；首次安装时引导配置。若已有文件不完整，则保留原文件并中止安装，不自动覆盖。
5. 发送 SMTP 验证邮件。服务器接受邮件后才继续切换；仍需在收件箱确认实际收到。
6. 确认旧版维护服务未在执行、且不存在相关 cron 调度冲突后，自动停用旧版 `daily-apt-upgrade.timer`、启用新版 `vpscheckreport.timer`，并将旧版可执行脚本归档到备份目录。

**安全说明：** 对无法安全判断的旧版 cron 调度，安装程序会停止自动迁移，不会擅自删除。切换失败时程序尝试恢复旧版脚本及原定时器状态，但不能保证所有异常情况均可自动回滚。旧版 systemd 单元文件会保留，便于恢复。

## 每日运行时间

- **北京时间每天 00:15**，随机延迟最多 **5 分钟**（通常在 00:15–00:20 之间触发）。
- `Persistent=true`：错过定时运行时可在定时器恢复后补跑。
- 新版定时器：`vpscheckreport.timer`；执行服务：`vpscheckreport.service`。

查看状态：

```bash
systemctl is-enabled daily-apt-upgrade.timer vpscheckreport.timer
systemctl is-active daily-apt-upgrade.timer vpscheckreport.timer
systemctl list-timers --all vpscheckreport.timer --no-pager
```

## 功能与默认策略

- 安全巡检覆盖 SSH、防火墙、Fail2ban、systemd、磁盘、内存、Docker、TLS、sudo、监听端口、authorized_keys、SUID/SGID、capabilities、备份和重启需求等。
- SSH Network Isolation 检查本机 IPv4/IPv6 防火墙中的 Tailscale-only 路径。**PASS 只代表本机规则检查通过，不等于已经从外部网络实测 SSH 不可访问。**
- 新版状态目录为 `/var/lib/vpscheckreport/audit`，首次巡检建立独立基线，不自动继承旧版基线。
- 系统升级默认使用 `apt-get -y --no-remove upgrade`，避免升级时自动移除软件包。
- 默认不执行 `autoremove`；确需启用可在 `/etc/vpscheckreport/config` 中设置 `ALLOW_AUTOREMOVE=true`。
- SSH 攻击统计写入 `/var/lib/vpscheckreport/latest-attacks.json`，并纳入日报。公网 IP 排名排除 Tailscale/CGNAT 地址。

手动运行**只读巡检**（不升级系统、不发送日报）：

```bash
sudo /usr/local/sbin/vpscheck-audit --quiet --exit-zero
```

## 备份与回滚

安装前备份保存在 `/var/backups/vpscheckreport/<UTC时间戳>/`。旧版可执行脚本在迁移成功后归档到该备份目录。

仓库提供 `bin/rollback.sh` 供恢复参考；由于新版安装已涉及旧版定时器切换，**不要假设单独执行回滚脚本即可完整恢复旧版自动调度**。回滚时应核实脚本、systemd 单元及定时器状态，避免新旧任务同时运行。

## 验证情况

在 GreenCloud Ubuntu 22.04 VPS 上已确认：

- SMTP 验证邮件被服务器接受，且曾在收件箱确认收到。
- 安全巡检结果：**15 PASS / 0 WARN / 0 FAIL**；SSH Network Isolation 返回 PASS。
- 自动迁移后，旧版定时器为 `disabled/inactive`，新版为 `enabled/active`。
- systemd 曾计算出下一次执行时间为北京时间 **2026-10-21 00:16:53**，符合 00:15 加最多 5 分钟随机延迟的规则。
- 安装脚本已通过 `bash -n` 语法检查。

**尚未验证：** 新版首次自动定时维护的完整 apt 升级、巡检、日报邮件端到端结果；最新加入的“复用现有 SMTP 配置”分支也尚未在 GreenCloud 重新执行安装验证。不要将上述验证理解为全面测试通过。

## 开发检查

```bash
bash -n install.sh bin/*.sh
python3 -m py_compile bin/*.py
python3 -m unittest discover -s tests -v
systemd-analyze calendar '*-*-* 00:15:00 Asia/Shanghai'
```

另见 `docs/MIGRATION_CHECKLIST.md`；若其内容与当前安装程序不一致，以最新代码为准。
