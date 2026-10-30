同步主线至 a2b2d31，优化注入器与 KeyMint 性能，完善电话 Binder 调用、Keybox 签名兼容和 vbmeta 回退处理。

保留定制 WebUI、本地 RKP 密钥一键导入和按应用选择远程 SOTER 转发。SOTER 私钥操作改用 BoringSSL，保留原有密钥文件与签名协议格式；更新 TLS、椭圆曲线及 ZIP 依赖，通过依赖安全检查。

验证：Android 14 ARM64 真机运行 19 个测试二进制，894 项通过、0 项失败、4 项原有忽略项；格式、Android Clippy、测试编译、cargo-deny 和 WebUI 构建通过。未执行真实微信支付或远程签发操作。
