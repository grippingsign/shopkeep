// RFC 8785（JCS，JSON Canonicalization Scheme）规范化。
//
// 规范里三件事容易做错，这里逐一钉死：
//   1. 键按 UTF-16 码元排序（不是 locale，不是字节序）；
//   2. 字符串只做 JSON 规定的那几个转义，UTF-8 原样输出；
//   3. 数字按 ECMAScript Number::toString 输出——1e-7 是 "1e-7" 不是 "0.0000001"。
// canonicalize 包实现了全部三点，这里只做一层薄封装，把 undefined
// 这种根本不能规范化的值挡在门口。
import canonicalize from "canonicalize";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { utf8 } from "./bytes.js";

export function jcs(value: unknown): string {
  const out = canonicalize(value);
  if (out === undefined) {
    throw new Error("无法规范化：值里混进了 undefined 或函数");
  }
  return out;
}

export const jcsBytes = (value: unknown): Uint8Array => utf8(jcs(value));

/** 规范里哈希的引用写法："sha256:" + 十六进制。 */
export const sha256Ref = (data: Uint8Array): string => "sha256:" + bytesToHex(sha256(data));
