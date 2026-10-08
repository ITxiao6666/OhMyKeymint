本次更新：

- 软件 TA 与远程 Soter 中继支持独立开启，保留服务互斥校验及已保存参数。
- 完善 Tencent Soter Beta 的软件测试签名、UID、密钥别名和会话状态处理。
- 修正 Soter 服务存在性判断。
- 优化首页设备诊断布局，移除内部背景块与分隔线，调整 Keybox证书链信息标题。

Tencent Soter Beta 使用公开的软件测试密钥，不提供真实 TEE、指纹或支付认证。

验证：本地构建 arm64-v8a Release；Android 15 真机测试 764 项通过、0 失败。
