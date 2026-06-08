# 测试迁移计划

## 目标
将 lib.rs 中 23 个测试移到 tests/ 目录或子模块，参照其他项目风格。

## 步骤

- [x] 1. 创建 tests/consts.rs — 常量测试 (4 tests)
- [x] 2. 创建 tests/error.rs — 错误类型测试 (6 tests)
- [x] 3. 创建 tests/types.rs — 类型测试 (6 tests)
- [x] 4. 创建 tests/api.rs — prelude 和 API 签名测试 (4 tests)
- [x] 5. 将 Builder 私有字段测试移到 src/builder.rs (3 tests)
- [x] 6. 精简 lib.rs — 删除所有测试
- [x] 7. 运行测试验证 ✅ 82 tests passed (44 unit + 24 integration + 12 doctest + 2 ignored)
- [ ] 8. 提交代码
