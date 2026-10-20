# VPSCheckReport

Ubuntu VPS 每日系统更新、安全巡检与邮件报告。支持普通 SMTP 和 Gmail 应用专用密码。

## 当前状态：预览版（不要在生产环境直接切换）

一键安装入口已加入，但当前只部署文件，不启用新定时器。旧版巡检的完整功能尚未迁移，SSH 日志统计也需继续验证时区、日志轮转和事件去重。现阶段仅适合隔离测试机或经备份后的人工测试，不能代替生产版旧程序。

## 安装

```bash
curl -fsSL https://raw.githubusercontent.com/majunwuxi/vpscheckreport/main/install.sh | sudo bash
```

安装时选择普通 SMTP（STARTTLS/SSL）或 Gmail 应用专用密码（smtp.gmail.com:465）；配置保存在 /etc/vpscheckreport/mail.ini，权限 0600，不上传 GitHub。

**迁移提醒**：本版是基于现有部署脚本的部分源码重新实现，并非对旧版全部功能的逐字复制。旧版的 Docker 健康、证书到期、基线变更等专项检查尚未完整迁移。安装程序不覆盖旧版脚本，且无论是否检测到旧版，都不会自动启用新版定时器，以防重复更新和重复发信。

测试安全审计（不更新系统、不发邮件）：
```bash
sudo /usr/local/sbin/vpscheck-audit
```

测试邮件：
```bash
echo 'VPSCheckReport SMTP test' | sudo tee /tmp/vpscheck-mail-test.txt >/dev/null
sudo /usr/local/lib/vpscheckreport/mail-send.py --subject 'VPSCheckReport test' --body /tmp/vpscheck-mail-test.txt
```

**仅在完成代码审查、验证并确认旧版调度方式之后**，才能人工迁移：
```bash
sudo systemctl disable --now daily-apt-upgrade.timer
sudo systemctl enable --now vpscheckreport.timer
```

**攻击统计**：使用 journalctl SSH 日志，必要时回退 auth.log*，并读取 fail2ban.log*。统计窗口是北京时间前一天 01:00 到当天 01:00，窗口结束不包含。失败登录与封禁次数分开计算。100.64.0.0/10 为共享地址段（含 Tailscale），不作为公网来源排名。缺失数据报告“无法统计”，不假装是零。跨服务器排行榜需要从多台机器的结构化报告进一步汇总。

安全提示：禁止上传 /etc/msmtprc、mail.ini、密码、私钥与真实生产日志。
