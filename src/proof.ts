// §6.3 的两个哈希：stateHash 与 proofHash。
//
// 字段以“十进制字节长度 + ':' + UTF-8 内容”为前缀拼接。这个前缀是
// 防撞机制：没有它，("ab", "c") 与 ("a", "bc") 会拼出同一个 preimage，
// 两组不同字段的哈希就此碰撞。字段顺序是冻结的，谁先谁后不是实现自由。
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { byteCompare, concat, utf8 } from "./bytes.js";

function wf(s: string): Uint8Array {
  const b = utf8(s);
  return concat(utf8(`${b.length}:`), b);
}

export function stateHash(agreementId: string, state: string, sequence: number): string {
  const h = sha256.create();
  for (const f of [agreementId, state, String(sequence)]) {
    h.update(wf(f));
  }
  return "sha256:" + bytesToHex(h.digest());
}

export interface ProofLink {
  agreementId: string;
  sequence: number;
  toState: string;
  event: string;
  proofHash: string;
  fromState?: string;
  previousStateHash?: string;
  nextStateHash?: string;
  previousProofHash?: string;
  actorId?: string;
  authorityRef?: string;
  commandId?: string;
  commandHash?: string;
  metadata?: Record<string, string>;
  evidenceRefs?: string[];
}

/**
 * §6.3.1 proofHash 的 preimage。
 *
 * 字段顺序冻结；metadata 的键按字节序；metadata 与 evidenceRefs 都带
 * 数量前缀。一个把时间戳重新渲染、或按自家 map 迭代顺序遍历的消费者，
 * 会在内容完全相同的情况下算出不同的摘要——这正是这个哈希存在的意义。
 */
export function proofHash(p: ProofLink): string {
  const h = sha256.create();
  const fields = [
    p.agreementId,
    String(p.sequence),
    p.fromState ?? "",
    p.toState,
    p.event,
    p.previousStateHash ?? "",
    p.nextStateHash ?? "",
    p.previousProofHash ?? "",
    p.actorId ?? "",
    p.authorityRef ?? "",
    p.commandId ?? "",
    p.commandHash ?? "",
  ];
  for (const f of fields) {
    h.update(wf(f));
  }
  const meta = p.metadata ?? {};
  const keys = Object.keys(meta).sort(byteCompare);
  h.update(wf(String(keys.length)));
  for (const k of keys) {
    h.update(wf(k));
    h.update(wf(meta[k]));
  }
  const refs = p.evidenceRefs ?? [];
  h.update(wf(String(refs.length)));
  for (const r of refs) {
    h.update(wf(r));
  }
  return "sha256:" + bytesToHex(h.digest());
}
