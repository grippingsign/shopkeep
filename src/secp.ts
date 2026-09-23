// secp256k1-keccak-v1 验签档案。
//
// 这个档案下签名只有一种拼法：0x 前缀、65 字节 r|s|v、v ∈ {27,28}。
// 除此之外的任何拼法都抛错。会“顺手修好”这些输入的验签器才是危险的：
// 它放过的不是一条签名，而是两套对“什么算合法签名”意见不一致的实现。
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { concat } from "./bytes.js";

export function keccak256(data: Uint8Array): Uint8Array {
  return keccak_256(data);
}

export function keccak256Hex(data: Uint8Array): string {
  return "0x" + bytesToHex(keccak_256(data));
}

/** 从签名恢复出以太坊风格地址。preimage 是签名前的原文（未哈希）。 */
export function recoverAddress(signature: string, preimage: Uint8Array): string {
  if (typeof signature !== "string" || !signature.startsWith("0x")) {
    throw new Error("签名必须以 0x 开头");
  }
  const body = hexToBytes(signature.slice(2));
  if (body.length !== 65) {
    throw new Error(`签名应为 65 字节，实际 ${body.length}`);
  }
  if (body[64] !== 27 && body[64] !== 28) {
    throw new Error(`恢复字节必须是 27 或 28，实际 ${body[64]}`);
  }
  const digest = keccak_256(preimage);
  // noble 的 recovered 签名格式：recid 在首字节，后跟 64 字节 r|s；
  // prehash:false 表示 digest 已经是 keccak 结果，别再哈希一次。
  const compressed = secp256k1.recoverPublicKey(
    concat(new Uint8Array([body[64] - 27]), body.subarray(0, 64)),
    digest,
    { prehash: false },
  );
  const uncompressed = secp256k1.Point.fromHex(bytesToHex(compressed)).toBytes(false);
  return "0x" + bytesToHex(keccak_256(uncompressed.subarray(1)).slice(-20));
}

/** 任何解码失败都按“不通过”处理——与官方 runner 的口径一致。 */
export function verifies(signature: string, preimage: Uint8Array, address: string): boolean {
  try {
    return recoverAddress(signature, preimage).toLowerCase() === address.toLowerCase();
  } catch {
    return false;
  }
}
