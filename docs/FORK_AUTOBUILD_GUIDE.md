# Fork: Asspp 自动签名与自动更新指南

本指南用于你自己的 fork 仓库，目标是：

- 监测 `Lakr233/Asspp` 的 `main` 更新
- 用你自己的开发者证书自动签名 iOS 安装包
- 自动发布 GitHub Release
- 通过 GitHub Pages 提供固定安装地址（手机可直接安装/更新）

相关文件：

- Workflow: `.github/workflows/upstream-signed-ios.yml`
- 输入生成脚本: `Resources/Scripts/generate.github.action.inputs.sh`

## 1. 前置条件

- 已付费 Apple Developer 账号
- 已创建证书和描述文件：
  - `Apple Distribution` 证书（.p12）
  - `Ad Hoc` 描述文件（.mobileprovision，必须包含目标设备 UDID）
- fork 仓库已启用 GitHub Actions 和 GitHub Pages
- OTA 场景建议仓库公开，确保安装链接可访问

## 2. 开启仓库权限

1. `Settings -> Actions -> General -> Workflow permissions`
2. 选择 `Read and write permissions`
3. `Settings -> Pages`
4. `Source` 选择 `GitHub Actions`

## 3. 准备证书文件（示例文件名）

你可以把文件放在任意路径，下面是示例：

- `./Certificates/apple_distribution.p12`
- `./Certificates/Asspp_AdHoc.mobileprovision`

## 4. 自动生成 GitHub Action 所需信息（推荐）

运行：

```bash
./Resources/Scripts/generate.github.action.inputs.sh \
  --p12 ./Certificates/apple_distribution.p12 \
  --p12-password 'your-p12-password' \
  --mobileprovision ./Certificates/Asspp_AdHoc.mobileprovision \
  --ota-base-url https://app.example.com
```

脚本会自动：

- 解析 Team ID / Bundle ID / 导出方式
- 生成 workflow 需要的 Secrets/Variables 文件
- 生成 `apply-with-gh.sh`（可一键写入 GitHub）

执行后按脚本输出继续：

```bash
export GITHUB_REPOSITORY="<owner>/<repo>"
<output-dir>/apply-with-gh.sh
```

如果你不想用 `gh` 自动写入，也可以手动把 `<output-dir>/secrets` 和 `<output-dir>/variables` 里的值填到 GitHub。

## 5. Secrets 与 Variables 对照

### Secrets

- `IOS_CERT_P12_BASE64`
- `IOS_CERT_PASSWORD`
- `IOS_PROVISIONING_PROFILE_BASE64`
- `IOS_KEYCHAIN_PASSWORD`
- `IOS_TEAM_ID`

### Variables

- `IOS_EXPORT_METHOD`
- `IOS_SIGNING_IDENTITY`
- `IOS_BUNDLE_ID`
- `IOS_OTA_BASE_URL`（可选，自定义域名时使用）

## 6. 首次运行验证

1. 打开 `Actions -> Upstream Signed iOS Build`
2. 点击 `Run workflow`
3. 成功后检查：
   - Release: `https://github.com/<owner>/<repo>/releases`
   - 安装页: `https://<owner>.github.io/<repo>/ios/latest/install.html`
   - Manifest: `https://<owner>.github.io/<repo>/ios/latest/manifest.plist`

如果仓库名本身是 `<owner>.github.io`，URL 中不会包含 `/<repo>`。

## 7. 日常使用

- Workflow 每 30 分钟轮询一次上游 `main`
- 检测到新 commit 后自动签名、发布、更新最新安装页
- 手机始终使用：`/ios/latest/install.html`

## 8. 手动触发并选择分支

在 `Actions -> Upstream Signed iOS Build -> Run workflow` 中：

- `source_kind`
  - `upstream`: 构建上游仓库
  - `fork`: 构建你自己 fork 仓库
- `source_branch`: 填要构建的分支名（例如 `main`、`feature/test`）
- `source_repo`: 当 `source_kind=upstream` 时可指定仓库（默认 `Lakr233/Asspp`）
- `force_build`: 默认 `true`，手动触发可直接打包

示例：

- 构建你 fork 的 `feature/sign-fix`：
  - `source_kind=fork`
  - `source_branch=feature/sign-fix`
- 构建上游 `develop`：
  - `source_kind=upstream`
  - `source_repo=Lakr233/Asspp`
  - `source_branch=develop`

## 9. 常见问题

- 安装按钮无反应：必须用 Safari 打开安装页
- 安装失败：设备 UDID 未加入 Ad Hoc 描述文件
- 签名报 Bundle ID 不匹配：检查 `IOS_BUNDLE_ID` 与描述文件的 App ID
- 页面可访问但无法安装：确认 `manifest.plist` 可公网访问且为 HTTPS
