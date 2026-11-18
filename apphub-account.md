# App Hub 账号接入登记

Android 包名和签名指纹来自 GitHub [v0.3.3 测试版 APK](https://github.com/x-zyz/recite/releases/tag/v0.3.3)，已通过 APK 签名校验。接入生产前，以计划分发的 APK 再校对一次签名。包名、指纹与回调规划见 [apphub.json](apphub.json)。

源码确定后，在 Casdoor 的 App Hub 组织中登记 `recite-android`，使用系统浏览器和 Authorization Code + PKCE S256。Client ID 由生产 Casdoor 分配。用计划分发的签名证书配置 Android Digital Asset Links，真机验证域名关联、回跳、`state` 与登录取消。本仓库目前发布产品介绍和测试 APK，登录功能需要在应用源码中实现。
