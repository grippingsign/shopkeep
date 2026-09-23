// 字节层的小工具。本仓库里凡是进哈希函数的东西都是 Uint8Array，
// 字符串一律显式 UTF-8 编码——不借助 Buffer 的隐式转换，
// 免得哪天换运行时行为悄悄变了。
export const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

export function concat(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

// 按 UTF-8 字节序比较两个字符串。
// 证明链里 metadata 的键要按字节排序，而 JS 字符串的默认比较是按
// UTF-16 码元——对含非 BMP 字符的键，两种顺序会给出不同结果。
export function byteCompare(a: string, b: string): number {
  const ba = utf8(a);
  const bb = utf8(b);
  const n = Math.min(ba.length, bb.length);
  for (let i = 0; i < n; i++) {
    if (ba[i] !== bb[i]) return ba[i] - bb[i];
  }
  return ba.length - bb.length;
}
