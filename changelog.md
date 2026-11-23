## 1.4.6 (269-1f07138)

- 修复谷歌通行密钥，以及 Google 其他 APP 的 GRANT 跨后端问题：带 GRANT 描述符的请求先用 IOhMyKsService::isOmkGrant 做只读归属探测，OMK 持有则留在 OMK，否则前置路由到 System；安全级 carrier 记录其产出后端。
- 自助授权（APP 域密钥授予自身）不再要求 SELinux keystore2_key:grant 权限，GRANT 权限本身仍不可授予。
- 优化 SOTER 本地实现：新增 ISoterService 服务层应答（hasAskAlready / getAppSecureKey / getAuthKey / getDeviceId），使用身份账本中的真实密钥、签名与 device id。
- 守护进程改为单实例，KernelSU 软重启不再产生重复 keymint 崩溃循环。
