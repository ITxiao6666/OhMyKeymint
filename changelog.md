## 1.4.6 (271-0c66114)

修复开启隐藏 StrongBox 后 keymint 在开机 GC 阶段 panic 的问题。

- 开启掩码时 get_keymint_wrapper(STRONGBOX) 返回 Km(HARDWARE_TYPE_UNAVAILABLE)，GC 失效回调原本直接 unwrap，遇到残留 StrongBox blob 就 panic 并打死 GC 线程。
- 回调改为容错：安全级别不可用时记录 info 并跳过；to_security_level() 改为返回错误。
- 日志区分「HAL 缺失」与「配置禁用」。
