# lib.rs 重构计划

## 目标
将 lib.rs 从 829 行拆分为模块化结构，参照 proc-connector / sizefilter / timefilter 风格。

## 步骤

- [x] 1. 创建 `src/error.rs` — FanotifyError 枚举 + Display + From
- [x] 2. 创建 `src/sys.rs` — fanotify_init / fanotify_mark / open_mount 底层函数
- [x] 3. 创建 `src/builder.rs` — FanotifyBuilder 结构体 + 方法
- [x] 4. 创建 `src/fanotify.rs` — Fanotify 结构体 + 方法
- [x] 5. 精简 `src/lib.rs` — 只保留文档 + mod 声明 + pub use + 集成测试
- [x] 6. 运行测试验证 ✅ 63 tests passed
- [ ] 7. 提交代码
