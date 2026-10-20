# 旧版迁移核对清单（暂不允许自动切换）

依据 GreenCloud 上的两个生产脚本：
- `wellmax-vps-audit` v2.0.1，442 行
- `daily-apt-upgrade.sh`，212 行

## 旧版巡检必须完整保留
- SSH 实际生效配置：root 登录、密码认证、端口
- 防火墙：ufw / firewalld / nftables / iptables，支持 strict / warn / ignore
- Fail2ban、sshd jail、CrowdSec
- systemd 失败单元，按服务器配置忽略
- 磁盘、inode、内存、swap、load 阈值
- Docker unhealthy / restarting / dead、privileged、docker.sock、host network
- Let's Encrypt 证书到期：7 天 FAIL，21 天 WARN
- sudo 日志
- 网络监听端口、authorized_keys SHA256、SUID/SGID、capabilities 的**新增项基线告警**
- 排除容器镜像目录、旧版基线格式兼容、可人工接受基线
- 备份成功标记及最大允许时效
- reboot-required、报告 PASS/WARN/FAIL、latest.env、latest-mail.txt

## 旧版维护脚本必须完整保留
- 更新 apt-get update -> dist-upgrade（仅 update 成功时）-> autoremove -> clean
- apt 锁超时 1800 秒，保留本机现有 dpkg 配置，非交互升级
- flock 锁，安全巡检默认 240 秒超时
- IPv4 / IPv6 / 内网地址、内核前后版本、升级日志
- 巡检状态、PASS/WARN/FAIL、基线变化、重启需求进入日报
- 根据失败/警告/重启调整邮件主题
- 邮件 UTF-8、SMTP TLS；SMTP 与 Gmail 应用专用密码二选一
- 30 天日志保留，邮件失败明确返回错误

## 新增功能
- SSH 公网来源 IP 前十、北京时间 01:00 至次日 01:00 的闭开区间
- Fail2ban Ban 事件与 SSH 失败登录次数分别统计
- 排除私网、CGNAT/Tailscale；支持 IPv4 / IPv6
- journal/auth.log/轮转日志来源判定、避免双重统计；数据不足标明不可统计
- 机器可读 JSON 便于未来 9 台服务器汇总

## 迁移发布门槛
1. 不在生产服务器运行未经审查的一键安装脚本。
2. 所有旧版检查项目有对应的新版实现和回归测试。
3. 安装器需识别 systemd timer/service、cron、自定义路径，并保留备份。
4. 必须先测试邮件、日志、攻击统计、更新失败分支。
5. 迁移必须显式确认；启用新版前停止旧版调度，检查无并发运行。
6. 必须提供一键回滚、保留旧配置和原脚本。
7. 当前仓库属于预览版：**尚不满足以上门槛，禁止自动迁移**。
