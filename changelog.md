合并 PR #7：兼容 EC 签名密钥中附带的 Encrypt/Decrypt 用途，调整生物认证兼容配置默认值，并完善配置解析、回归测试和文档。

生物认证兼容开关 `force_skip_system_biometric_hat_verification` 默认开启，会跳过 System KeyMint 对认证令牌 MAC 的校验；已有配置中明确设置的 false 会保留。需要原有令牌验证时可显式设为 false。

已通过 Android ARM64 检查、A015 真机工作区测试及 WebUI 测试；未验证银行 APP 指纹登记或支付效果。
