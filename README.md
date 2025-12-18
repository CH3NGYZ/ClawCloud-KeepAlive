# ⭐ Star 星星走起 动动发财手点点 ⭐Star

![成功截图](./3.png)

## ⚠️ 注意

- 首次运行：可能需要设备验证，收到 TG 通知后 30 秒内批准
- REPO_TOKEN：需要有 Secrets 写入权限才能自动更新
- Cookie 有效期：每次运行都会更新，保持最新
  ![设备验证](./1.png)

## GitHub Actions 缓存支持

本项目现在支持使用 GitHub Actions Cache 来存储浏览器会话数据，包括 cookies、缓存和其他浏览数据。这样可以避免每次运行时都需要重新登录。

## 两步验证(2FA)处理

本项目支持智能两步验证处理，`GH_2FA_SECRET` 环境变量具有最高优先级：

### 验证逻辑

1. **GH_2FA_SECRET 已设置**：无论账户首选验证方式是什么，都优先使用 Authenticator App 进行验证
2. **GH_2FA_SECRET 未设置**：使用 GitHub Mobile 进行验证

#### 方式 1：Authenticator App (推荐)

当设置了 `GH_2FA_SECRET` 环境变量时：

- 自动点击 "More options"（如果需要）
- 选择 "Authenticator app" 选项
- 自动生成并填入 6 位验证码
- 自动提交验证

#### 方式 2：GitHub Mobile

当未设置 `GH_2FA_SECRET` 环境变量时：

- 自动点击 "More options"（如果需要）
- 选择 "GitHub Mobile" 选项
- 需要在手机上手动确认验证

### GitHub 仓库 Secrets 配置

| Secret 名称     | 说明                                                |
| --------------- | --------------------------------------------------- |
| `GH_USERNAME`   | GitHub 用户名                                       |
| `GH_PASSWORD`   | GitHub 密码                                         |
| `GH_2FA_SECRET` | GitHub TOTP SECRET（用于生成 6 位数字验证码），可选 |
| `GH_SESSION`    | Cookie（首次可为空）不用添加                        |
| `TG_BOT_TOKEN`  | Telegram Bot Token                                  |
| `TG_CHAT_ID`    | Telegram Chat ID                                    |
| `REPO_TOKEN`    | GitHub Token（用于自动更新 Secret）                 |

### GitHub 仓库 Variables 配置

你可以在 GitHub 仓库中设置以下 Variables 来配置浏览器行为：

1. 进入仓库 Settings → Actions → Variables
2. 添加以下 Variables：

| Variable 名称           | 说明                     | 示例值                                                                                                                          |
| ----------------------- | ------------------------ | ------------------------------------------------------------------------------------------------------------------------------- |
| `BROWSER_USER_DATA_DIR` | 浏览器用户数据目录路径   | `/tmp/browser-cache`                                                                                                            |
| `CUSTOM_USER_AGENT`     | 自定义 User Agent        | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0` |
| `BROWSER_HEADLESS`      | 是否以无头模式运行浏览器 | `true` 或 `false`                                                                                                               |

## 流程图

```
开始
  ↓
加载已保存的 Cookie（如果有）
  ↓
访问 ClawCloud
  ↓
已登录？ ─是→ 保活 → 提取新 Cookie → 保存 → 完成
  ↓否
点击 GitHub 登录
  ↓
Cookie 有效？ ─是→ 直接 OAuth 授权
  ↓否
输入用户名密码
  ↓
需要设备验证？ ─是→ 发送 TG 通知 → 等待 30 秒
  ↓
登录成功
  ↓
OAuth 授权
  ↓
重定向到 ClawCloud
  ↓
保活（访问控制台、应用页面）
  ↓
提取新的 Session Cookie
  ↓
自动更新 GH_SESSION Secret
  ↓
发送 Telegram 通知
  ↓
完成 ✅

```
