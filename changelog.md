- 修复自动 vb_key 变化可能导致旧 KeyBlob 无法解密的问题，持久化公开摘要并保留现有密钥数据。
- 完善 PIF v4.9-inject-s 兼容及三项独立开关：伪装 Build、伪装 Build（Play Store）、伪装 Props。
- 安全补丁属性写入改用 resetprop -n。
- 优化 PIF 配置显示、设备列表刷新及滚动圆角。

已在 Nothing A015（Android 15）验证两次重启后的快照复用和原临时密钥连续性。已因原派生值丢失而失效的 KeyBlob 不保证恢复。
