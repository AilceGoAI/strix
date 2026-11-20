# 本地版（local-edition）

目标：把 Strix Cloud 的组织级能力在本机复刻，去掉云端调用与登录，作为独立分支发布。

## 非目标

- 多租户隔离、SSO、跨机同步
- 云端扫描、托管计费、远程上传

## 目录与状态

所有本地状态放在 `~/.strix/local/`，权限 0700：

```
~/.strix/local/
├─ local.toml        配置（角色、通知、调度开关）
├─ users.json        用户与角色（0600）
├─ runs.jsonl        运行索引（每行一条 run 摘要，append-only）
├─ intel/            威胁情报缓存
└─ schedules.json    调度登记表
```

## 命令面

全部挂在 `strix local` 下，不新增顶层子命令：

| 命令 | 作用 | 对应 Cloud 能力 |
|---|---|---|
| `strix local runs list/show/export` | 运行历史与发现共享 | 共享发现与运行历史 |
| `strix local users add/list/remove` | 本地角色（admin/operator/viewer） | 邀请成员、设置角色 |
| `strix local serve --port 8765` | 只读看板，复用 `strix view` 静态包 | 团队共享界面 |
| `strix local schedule add/list/remove` | 生成 launchd / cron 定时扫描 | 定时渗透测试 |
| `strix local intel update/lookup` | 本地 CVE/KEV 缓存 | 实时威胁情报 |
| `strix local notify --from-run <id>` | 推送 Slack/Jira/Linear | 三方集成 |

## 复用已有能力

- PR 安全审查：`strix -n --scope-mode diff --diff-base origin/main`，只需提供 Actions 模板
- 一键修复：白盒模式的 `fix_after` / `fix_pr_body` 已内建
- 攻击面监控：定时跑 `subfinder | httpx` 并与上次结果 diff

## 去掉的东西

- `strix cloud ...` 全部子命令与 `platform_cli` / `platform_identity` / `auth_cli`
- 遥测上报（`strix/telemetry/`）
- 登录态与 OAuth 回调

## 实现约定

1. 新代码放 `strix/local/`，不改 `strix/cloud/`（留着便于跟随上游）
2. CLI 注册集中在 `strix/local/cli.py`，由 `strix/interface/main.py` 挂载一次
3. 所有输出简体中文，技术标识保持原文
4. 每个模块自带 `--json` 输出，便于脚本与看板消费
5. 数据库不引第三方依赖：索引用 JSONL，配置用 TOML，缓存用目录
