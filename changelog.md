## 1.4.6 (270-a2d8618)

新增隐藏Strongbox功能，通过Duck detector检测。

- Zygisk 载荷在 system_server 的 SystemConfig.getAvailableFeatures 上移除 android.hardware.strongbox_keystore。
- keymint 按配置隐藏 StrongBox 安全级别。
- WebUI 开关位于「工具 → 系统功能」，保存后即时重启 keymint；提示条提供「立即软重启」（ksud soft-reboot）刷新系统特性列表。
