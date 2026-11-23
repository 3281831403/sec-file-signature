# sec-file-signature

## 题面

签名包在证书吊销之后照样能装，旧版本重放也没人拦：摘要只算文件前若干字节，尾部篡改漏检；解析包时只取第一个签名，其余被忽略；多签名求和而不是达阈值，重复签名可刷数量；阈值取自签名包自身，攻击者可改成 1；吊销检查只比对证书名不比对序列号；吊销检查不考虑吊销时间，吊销前签发的也被拒；时间戳只比较大小不校验区间，未来时间戳通过；策略校验不检查阈值是否为一；批量校验复用已验签结果，后一个包跳过校验；包内摘要与实际文件不比对，只校验签名本身。signer/verify.py 是核心，tests/unit/test_verify.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

## 运行方式

在仓库根目录执行：

```powershell
cd D:\gsb-20261119\sec-file-signature
python -m pytest tests -q
```

初始状态必须恰好为：

```text
15 failed
```

15 个失败必须全部来自 signer/verify.py 中 8 个只执行 raise NotImplementedError 的桩函数；不允许出现 collection error、import error、syntax error、跳过或 xfail。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

## 测试拆分布局

这是测试拆分布局，合计 15 条：

- tests/unit/test_verify.py：10 条契约测试，逐条对应题面中的 10 个缺陷；其中时间戳契约同时验证未来时间戳与旧包重放。
- tests/behaviour/test_verify_edge.py：5 条边界测试，覆盖单签名包通过、达阈值通过且不足拒绝、吊销证书被拒、摘要不符被拒、两批独立校验与单独校验相同。

15 条测试全部调用 signer/verify.py 的函数。tests 目录不可修改；不要加 skip 或 xfail，不要放宽断言，也不要用 monkeypatch 伪造结果，只实现 signer/verify.py。

## 目录

```text
sec-file-signature/
  README.md
  conftest.py
  signer/__init__.py
  signer/verify.py
  tests/unit/test_verify.py
  tests/behaviour/test_verify_edge.py
```

## 约束

- 只使用标准库 hashlib、hmac、json、base64 与 pytest，离线运行，不引入第三方依赖。
- signer/verify.py 恰好包含 8 个桩函数，当前全部只执行 raise NotImplementedError；函数契约写在各自 docstring 中，明确多签名、吊销列表、时间戳和容差 0。
- 不使用随机数；所有时间点由调用方显式传入，不读取系统时钟。
- 摘要覆盖完整文件，签名必须恒定时间比较，多签名按不同证书去重计数，吊销同时匹配证书名与序列号并考虑吊销时间，时间戳拒绝未来值并限制新鲜度，策略必须拒绝阈值 1，批量校验每个包独立重查，包摘要必须与实际文件一致。
- 修复顺序严格按题面列出的 10 个缺陷顺序推进；测试是唯一验收标准。
