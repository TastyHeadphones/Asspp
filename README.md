# Asspp

Seamless multi-account App Store management.

[简体中文 🇨🇳](./Resources/i18n/zh-Hans/README.md)

For a command-line or library version of Asspp, check out [ApplePackage](https://github.com/Lakr233/ApplePackage).

## 👀 Preview

![Preview](./Resources/Screenshots/README_PREVIEW_iPhone.png)
![Preview Mac](./Resources/Screenshots/README_PREVIEW_MAC.png)

## 🌟 Key Features

- **Multi-Account**: Supports multiple Apple IDs
- **Region Selection**: Choose your App Store region
- **App Search**: Search for apps by keywords
- **App Download**: Download apps from the App Store
- **IPA Install**: Install IPAs on non-jailbroken devices
- **IPA Sharing**: Share IPA files easily
- **Historical Versions**: Download previous app versions
- **Free App Purchase**: Purchase free apps

## 📝 Requirements

### Prerequisites

- [iOS App Signer](https://dantheman827.github.io/ios-app-signer/)
- Self-signed certificate for `app.localhost.qaq.wiki` (install in Settings)

### Troubleshooting

- For issues like [#1](https://github.com/Lakr233/Asspp/issues/1), use the provided signing tool.
- If installation fails, ensure the certificate is properly installed.
- For app crashes or exits, verify you've signed into your App Store account and that your device system version is supported.

### Installation Methods Comparison

| Aspect                  | Local Installation                     | AirDrop Installation                                                      |
| ----------------------- | -------------------------------------- | ------------------------------------------------------------------------- |
| Devices Required        | Single device                          | Two devices                                                               |
| App Store Compatibility | Undetectable\*                         | Compatible                                                                |
| Auto-Updates            | No                                     | Yes                                                                       |
| Prerequisites           | Install and trust certificate manually | Target device logged in with matching account, at least one app installed |
| Internet Required       | Yes                                    | No                                                                        |

- This installation method does not register the software with the App Store, so it cannot auto-update. Manual updates can retain data, but subsequent installations cannot use this software, and this method cannot overwrite existing apps.

## 🚀 Usage

# iPhone

- Visit the Releases page (https://github.com/Lakr233/Asspp/releases) and download the latest Asspp.ipa
- Re-sign the IPA with a signing tool, then install it
- Or use this Shortcut: https://www.icloud.com/shortcuts/d3c28f125b724a2da136d560fcf360dc
  > Copy the link and run it, or add the shortcut to your share sheet; when opening the link choose "Open in Sidestore"
- If you use your own fork with automated signing enabled, open your GitHub Pages install URL:
  `https://<owner>.github.io/<repo>/ios/latest/install.html`

# Mac

- Visit the Releases page (https://github.com/Lakr233/Asspp/releases) and download the latest Asspp.zip
- Unzip and open Asspp.app

### First Run and Trusting the App (Recommended)

1. Try double-clicking to open the app. If you see "App can’t be opened because the developer cannot be verified" or a similar message:
   - In Finder, locate Asspp.app, Control-click (or right-click) the app and choose "Open", then click "Open" again in the dialog. This will create a one-time trust exception for the app.
2. If Control-clicking does not work or the app is still blocked:
   - Open System Settings -> Privacy & Security (or System Preferences -> Security & Privacy on older macOS). In the General/Security section, look for the blocked app and click "Open Anyway" or "Allow". You may need to enter an administrator password.
3. Recommendation: Download from this repository's Releases and verify the release details to ensure the source is trusted before trusting and opening the app.

> These steps follow macOS Gatekeeper practices and help minimize security risks while allowing you to run unsigned or self-signed apps.


## 📋 Prebuilt Package

Check the [Releases](https://github.com/Lakr233/Asspp/releases) page.

## 🤖 Auto Signed iOS Build (GitHub Actions + GitHub Pages)

This repository includes workflow `.github/workflows/upstream-signed-ios.yml` that can:

- Poll `Lakr233/Asspp` `main` every 30 minutes
- Build and sign IPA with your own Apple Developer certificate/profile
- Publish each upstream commit as a GitHub Release
- Deploy a stable OTA install page via GitHub Pages

### 1. Prerequisites

- Paid Apple Developer account
- Ad Hoc provisioning profile with your iPhone/iPad UDID included
- A repository where GitHub Actions and GitHub Pages are enabled
- Publicly accessible Pages/Releases URLs (recommended to keep repo public for OTA install)

### 2. Enable GitHub Actions and GitHub Pages

1. Open `Settings -> Actions -> General -> Workflow permissions`
2. Set `Read and write permissions`
3. Open `Settings -> Pages`
4. Set `Source` to `GitHub Actions`

### 3. Prepare signing assets

1. In Apple Developer, create or reuse:
   - App ID (Bundle ID)
   - `Apple Distribution` certificate
   - `Ad Hoc` provisioning profile (include target devices)
2. Export certificate as `.p12` from Keychain Access with a password
3. Download `.mobileprovision`

### 4. Convert assets to base64

On macOS:

```bash
base64 -i your_cert.p12 | tr -d '\n'
base64 -i your_profile.mobileprovision | tr -d '\n'
```

### 5. Configure repository secrets

Set these in `Settings -> Secrets and variables -> Actions -> Secrets`:

| Name                              | Required | Description                                     |
| --------------------------------- | -------- | ----------------------------------------------- |
| `IOS_CERT_P12_BASE64`             | Yes      | Base64 string of your `.p12`                    |
| `IOS_CERT_PASSWORD`               | Yes      | Password used when exporting `.p12`             |
| `IOS_PROVISIONING_PROFILE_BASE64` | Yes      | Base64 string of your `.mobileprovision`        |
| `IOS_KEYCHAIN_PASSWORD`           | No       | Temporary keychain password on runner           |
| `IOS_TEAM_ID`                     | No       | Team ID override (auto-read from profile if not set) |

### 6. Configure repository variables

Set these in `Settings -> Secrets and variables -> Actions -> Variables`:

| Name                   | Required | Example                          | Description |
| ---------------------- | -------- | -------------------------------- | ----------- |
| `IOS_EXPORT_METHOD`    | No       | `ad-hoc`                         | Defaults to `ad-hoc` |
| `IOS_SIGNING_IDENTITY` | No       | `Apple Distribution`             | Auto-selected by export method if empty |
| `IOS_BUNDLE_ID`        | No       | `wiki.qaq.Asspp`                 | Override Bundle ID (must match profile) |
| `IOS_OTA_BASE_URL`     | No       | `https://app.example.com`        | Custom OTA base URL; defaults to GitHub Pages URL |

### 7. (Optional) Use custom domain for OTA URL

1. Add your custom domain in `Settings -> Pages`
2. Configure DNS for that domain to GitHub Pages
3. Set `IOS_OTA_BASE_URL` to your HTTPS domain (without trailing slash), for example:
   - `https://app.example.com`

### 8. Run and verify

1. Open `Actions -> Upstream Signed iOS Build`
2. Click `Run workflow` for first-time validation
3. After success, check:
   - Release page: `https://github.com/<owner>/<repo>/releases`
   - OTA install page: `https://<owner>.github.io/<repo>/ios/latest/install.html`
   - OTA manifest: `https://<owner>.github.io/<repo>/ios/latest/manifest.plist`

If your repository name is exactly `<owner>.github.io`, then URL does not include `/<repo>`.

### 9. Daily usage flow

- Workflow runs every 30 minutes
- When upstream `main` has a new commit, workflow builds and publishes automatically
- `ios/latest/install.html` always points to the newest signed build
- Install/update on iPhone by opening the install page in Safari

### 10. Common issues

- Install button does nothing: open install page in Safari, not in in-app webview
- Install fails immediately: your device UDID is not in provisioning profile
- App cannot be verified: trust your certificate/profile in iOS settings
- Signing error about Bundle ID: ensure `IOS_BUNDLE_ID` matches App ID in profile


## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=Lakr233/Asspp&type=date&legend=top-left)](https://www.star-history.com/#Lakr233/Asspp&type=date&legend=top-left)

## 🧑‍⚖️ License

Starting from version 2.2.16, the project is licensed under [MIT](./LICENSE).

## 🥰 Acknowledgments

- [ipatool](https://github.com/majd/ipatool)
- [ipatool-ios](https://github.com/dlevi309/ipatool-ios)
- [localhost.direct](https://get.localhost.direct/)

`ipatool-ios` and `localhost.direct` are no longer used in the project.

---

Copyright © 2025 Lakr Aream. All Rights Reserved.
