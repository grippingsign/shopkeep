// §4.4 结算摘要：EIP-712 在 KiteFulfill 域下的手工编码。
//
// 不引以太坊全家桶——这里需要的只是三个词的编码规则：
//   uint256 → 32 字节大端；
//   address → 左补 12 个零字节；
//   bytes32 → 去掉 sha256:/0x 前缀后的 32 字节。
// 加上两条规范派生：agreementId/reasonCode/decisionId 字符串上链前
// 先过一次 keccak256。派生错了签出来的东西在金库里永远验不过，
// 所以向量把这些派生值一并钉死。
import { bytesToHex } from "@noble/hashes/utils.js";
import { concat, utf8 } from "./bytes.js";
import { keccak256 } from "./secp.js";

function wInt(n: number | bigint): Uint8Array {
  const v = BigInt(n);
  if (v < 0n || v >= 1n << 256n) {
    throw new Error(`整数超出 uint256 范围: ${n}`);
  }
  const out = new Uint8Array(32);
  let x = v;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

function wB32(s: string): Uint8Array {
  const h = s.replace(/^sha256:/, "").replace(/^0x/, "");
  if (!/^[0-9a-fA-F]{64}$/.test(h)) {
    throw new Error(`不是 32 字节: ${s}`);
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = parseInt(h.slice(2 * i, 2 * i + 2), 16);
  }
  return out;
}

function wAddr(a: string): Uint8Array {
  const h = a.replace(/^0x/, "");
  if (!/^[0-9a-fA-F]{40}$/.test(h)) {
    throw new Error(`不是地址: ${a}`);
  }
  return concat(new Uint8Array(12), wB32(h));
}

/** struct 里一个字段的 ABI 词。包含规范派生：agreementId、reasonHash、decisionId。 */
function settlementField(name: string, struct: Record<string, unknown>): Uint8Array {
  if (name === "agreementId") {
    return keccak256(utf8(String(struct.agreementId)));
  }
  if (name === "amount") {
    // §4.4 的双来源：Agreement 的 amount 由 decimal 价格派生（向量同时
    // 给了派生后的 base units 钉死这条链），Activation 的 amount 就是
    // 资金读取返回的 base units 整数本身。
    if ("amountBaseUnits" in struct) {
      return wInt(BigInt(String(struct.amountBaseUnits)));
    }
    return wInt(BigInt(String(struct.amount)));
  }
  if (name === "reasonHash") {
    return keccak256(utf8(String(struct.reasonCode)));
  }
  if (name === "decisionId") {
    return keccak256(utf8(String(struct.decisionId)));
  }
  const v = struct[name];
  if (typeof v === "number" || typeof v === "bigint") {
    return wInt(v);
  }
  const s = String(v);
  if (s.startsWith("0x") && s.length === 42) {
    return wAddr(s);
  }
  return wB32(s);
}

export interface SettlementInput {
  domain: {
    name: string;
    version: string;
    chainId: number;
    verifyingContract?: string;
  };
  typeString: string;
  struct: Record<string, unknown>;
  signature: string;
  claimedSigner: string;
}

export interface SettlementDigest {
  domainSeparator: string;
  structHash: string;
  digest: string;
}

export function settlementDigest(input: SettlementInput): SettlementDigest {
  const dom = input.domain;
  const withContract = "verifyingContract" in dom;
  const domainType = withContract
    ? "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    : "EIP712Domain(string name,string version,uint256 chainId)";
  const domainWords = [keccak256(utf8(dom.name)), keccak256(utf8(dom.version)), wInt(dom.chainId)];
  if (withContract) {
    domainWords.push(wAddr(String(dom.verifyingContract)));
  }
  const domain = keccak256(concat(keccak256(utf8(domainType)), ...domainWords));

  const ts = input.typeString;
  const inner = ts.slice(ts.indexOf("(") + 1, -1);
  const fields = inner.split(",").map((f) => f.split(" ")[1]);
  const structHash = keccak256(
    concat(keccak256(utf8(ts)), ...fields.map((f) => settlementField(f, input.struct))),
  );

  const digest = keccak256(concat(utf8("\x19\x01"), domain, structHash));
  return {
    domainSeparator: "0x" + bytesToHex(domain),
    structHash: "0x" + bytesToHex(structHash),
    digest: "0x" + bytesToHex(digest),
  };
}
