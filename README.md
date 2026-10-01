# shopkeep

Kite A2A Coordination Extension v1 的 TypeScript 校验工具箱。

回答两类问题：

- **我的实现对不对** —— 回放官方全部八个离线向量集合（95 个用例），
  逐条对齐官方 Python runner 的断言口径；
- **这份文档能不能信** —— `check` 命令对任意一份 v1 协议文档做类型
  识别 + schema + 哈希承诺 + 签名恢复，抓包联调、审计、对接排障时用。

官方仓库的 Python `conformance/run.py` 只回放了八个集合里的五个
（canonical / signing / commands / receipts / settlement），funding、
proofs、errors 三个集合在官方侧没有断言逻辑——这个仓库把它们补齐了，
全部八个集合都在 TS 侧实现，并且新增了官方没有的单文档校验入口。

## 为什么自己写而不是包一层官方 runner

官方 runner 的价值在口径，不在覆盖。把它当依赖包起来，等于多了一层
永远追不上上游的翻译；按规范重写一遍，每条断言都能对着 spec.md 讲出
为什么，也才敢在 funding / proofs / errors 这些官方没跑的集合上给出
"通过"两个字。

签名恢复链路全部走 [@noble/curves](https://github.com/paulmillr/noble-curves)
+ [@noble/hashes](https://github.com/paulmillr/noble-hashes)：
secp256k1 恢复公钥、keccak256 取地址后 20 字节、EIP-712 摘要
（domainSeparator + structHash），以及 RFC 8785（JCS）规范化字节。

## 安装

需要 Node 20+。

```bash
git clone https://github.com/grippingsign/shopkeep
cd shopkeep
npm install
npm test          # 36 个测试：8 集合回放 + 单元 + check 路径
```

## 用法

### vectors —— 回放全部八个离线集合

```bash
npm run vectors               # 人读摘要
npm run vectors -- --strict   # 有跳过用例时非零退出，发布门禁用
npm run vectors -- --json     # 机器可读报告，CI 集成用
```

记账口径与官方一致：跑不了的用例永远记 skip，不算通过——一个把跑
不了的用例悄悄计成成功的套件，告诉你的是"符合规范"，检查的却是空气。
状态机转移与资金绑定是活体行为，离线跑不了，如实标注。

### check —— 校验一份文档

```bash
# 自动识别类型（funding-submission / agreement-command / transition-proof /
# transition-receipt / deal-contract / domain-error）
npm run check -- path/to/doc.json

# 校验 command 签名恢复到哪个地址（actor 的 EVM 地址）
npm run check -- command.json --signer 0x1563…

# 校验 receipt 的 Runtime 签名
npm run check -- receipt.json --signer 0x5cbd…   # Runtime 地址

# 校验 deal-contract 的 termsHash 派生
npm run check -- deal.json --expect-terms-hash sha256:feba…

# 机器可读输出
npm run check -- doc.json --json
```

每种类型的深度检查：

| 类型 | 检查内容 |
|---|---|
| agreement-command | payloadHash 是否承诺 canonical 化的 payload；`--signer` 给定时验证签名恢复 |
| transition-proof | 哈希链是否环环相扣；每条签名是否恢复到自带 signedBy（不需要外部输入） |
| transition-receipt | `--signer` 给 Runtime 地址时验证 runtimeSignature（preimage 按 receiptSignedFields 白名单构建） |
| deal-contract | `--expect-terms-hash` 给定时比对 JCS 规范化字节的 sha256 派生（签名与已声明 termsHash 剥离后） |
| domain-error | 错误码是否在官方目录；wire 上的 retriable 是否与目录一致 |
| funding-submission | buyer / seller 两个面的 schema 校验 |

不给 `--signer` / `--expect-terms-hash` 时对应检查记 skip 而不是通过，
报告里写清楚要补什么参数。

### capture —— 校验抓回来的 proofs 响应

```bash
npm run capture -- captured-agreement-proofs.json
```

## 目录

```
src/bytes.ts       字节工具：concat / utf8 / hex
src/secp.ts        secp256k1 验签、keccak256、地址派生
src/canonical.ts   RFC 8785 (JCS) 规范化、sha256 引用
src/proof.ts       proofHash / stateHash
src/eip712.ts      EIP-712 结算摘要
src/harness.ts     用例发现、装载、记账（Report）
src/sets.ts        八个集合的回放逻辑
src/check.ts       单文档校验（类型识别 + 深度检查）
src/capture.ts     抓包响应校验
src/cli.ts         命令行入口
vendor/            官方向量 + schemas（Apache-2.0，版权归原仓库）
tests/             36 个测试
```

## License

MIT（`vendor/` 下的官方向量与 schema 遵循原仓库的 Apache-2.0，见
`vendor/APACHE-2.0-LICENSE`）。
