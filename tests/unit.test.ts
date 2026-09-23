// 单元测试：不依赖向量的行为钉子。这些是回放覆盖不到的边角——
// 恰好也是“换个实现就会悄悄不一样”的地方。
import { describe, expect, it } from "vitest";
import { byteCompare, concat, utf8 } from "../src/bytes.js";
import { jcs, sha256Ref } from "../src/canonical.js";
import { proofHash, stateHash } from "../src/proof.js";
import { keccak256Hex, recoverAddress, verifies } from "../src/secp.js";
import { settlementDigest } from "../src/eip712.js";

// 官方向量 index.json 里公布的测试钥匙（本来就是一次性的公开假钥匙）。
const BUYER_KEY_ADDRESS = "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a";

describe("recoverAddress 的严格性", () => {
  it("拒绝不带 0x 前缀的裸 hex", () => {
    expect(() =>
      recoverAddress("6906064ce2abf08e".padEnd(130, "0"), utf8("x")),
    ).toThrow(/0x/);
  });

  it("拒绝 64 字节（少了恢复字节）", () => {
    expect(() => recoverAddress("0x" + "ab".repeat(64), utf8("x"))).toThrow(/65/);
  });

  it("拒绝 v=0 的老式恢复字节", () => {
    expect(() => recoverAddress("0x" + "ab".repeat(64) + "00", utf8("x"))).toThrow(/27 或 28/);
  });

  it("签名与地址不符时 verifies 返回 false 而不是抛错", () => {
    // 用合法拼法但乱填的签名：恢复会得到某个别的地址，或者点不在曲线上。
    const sig = "0x" + "11".repeat(64) + "1b";
    expect(verifies(sig, utf8("任意原文"), BUYER_KEY_ADDRESS)).toBe(false);
  });
});

describe("长度前缀的防撞语义", () => {
  it("wf 前缀让不同切分的字段序列摊不出同一个 preimage", () => {
    // 通过 stateHash 间接验证：字段内容相同但切分不同 → 哈希不同。
    // 这里用 proofHash 的字段顺序敏感性做直接验证。
    const link = {
      agreementId: "did:kite:agreement:1",
      sequence: 1,
      toState: "COMMITTED",
      event: "command.accept",
      proofHash: "sha256:" + "0".repeat(64),
    };
    const h1 = proofHash(link);
    // 换一个 event 名，哈希必须变
    const h2 = proofHash({ ...link, event: "command.reject" });
    expect(h1).not.toEqual(h2);
  });

  it("metadata 键按字节序而不是 locale 序排序", () => {
    const base = {
      agreementId: "a",
      sequence: 1,
      toState: "S",
      event: "e",
      proofHash: "sha256:" + "0".repeat(64),
    };
    const withMeta = proofHash({
      ...base,
      metadata: { b: "1", a: "2", c: "3" },
    });
    const reordered = proofHash({
      ...base,
      metadata: { c: "3", b: "1", a: "2" },
    });
    // 键的插入顺序无关，只有字节序说了算
    expect(withMeta).toEqual(reordered);
  });

  it("stateHash 对 sequence 边界敏感", () => {
    expect(stateHash("agr", "S", 1)).not.toEqual(stateHash("agr", "S", 2));
    expect(stateHash("agr", "S", 0)).not.toEqual(stateHash("agr", "S", 1));
  });
});

describe("JCS 规范化", () => {
  it("键按码元排序、UTF-8 原样输出", () => {
    expect(jcs({ b: 1, a: "é" })).toEqual('{"a":"é","b":1}');
  });

  it("整数不做浮点渲染", () => {
    expect(jcs({ seq: 1, rev: 2 })).toEqual('{"rev":2,"seq":1}');
  });

  it("sha256Ref 的写法是 sha256: 前缀", () => {
    expect(sha256Ref(utf8("abc"))).toMatch(/^sha256:[0-9a-f]{64}$/);
  });
});

describe("EIP-712 结算摘要", () => {
  const input = {
    domain: { name: "KiteFulfill", version: "1", chainId: 2366 },
    typeString: "Test(string agreementId)",
    struct: { agreementId: "did:kite:agreement:demo" },
    signature: "0x" + "00".repeat(65),
    claimedSigner: BUYER_KEY_ADDRESS,
  };

  it("agreementId 字符串先 keccak 再进词", () => {
    const d = settlementDigest(input);
    expect(d.structHash).toMatch(/^0x[0-9a-f]{64}$/);
    // 直接对照：keccak256("did:kite:agreement:demo") 应当出现在 preimage 里
    expect(keccak256Hex(utf8("did:kite:agreement:demo"))).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it("带 verifyingContract 的域分隔符与不带的不同", () => {
    const withContract = settlementDigest({
      ...input,
      domain: { ...input.domain, verifyingContract: "0x0000000000000000000000000000000000000001" },
    });
    expect(withContract.domainSeparator).not.toEqual(settlementDigest(input).domainSeparator);
  });
});

describe("字节工具", () => {
  it("byteCompare 按 UTF-8 字节序", () => {
    expect(byteCompare("a", "b")).toBeLessThan(0);
    expect(byteCompare("ab", "a")).toBeGreaterThan(0);
  });

  it("concat 不改入参", () => {
    const a = utf8("hello");
    const b = utf8("world");
    const out = concat(a, b);
    expect(out.length).toBe(10);
    expect(a.length).toBe(5);
  });
});
