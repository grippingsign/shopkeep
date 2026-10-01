// check：对“你手上的那一份文档”做校验。
//
// vectors 回答的是“我的实现对不对”，check 回答的是“这份抓包/这份
// 对端发来的文档能不能信”。抓包联调、审计、对接排障时用得最多的是
// 后者，但官方 runner 只做了前者。
//
// 用法：
//   shopkeep check deal.json
//   shopkeep check command.json --signer 0x1563…
//   shopkeep check receipt.json --signer 0x5cbd…（Runtime 地址）
//   shopkeep check terms.json --expect-terms-hash sha256:…
//
// 签名恢复需要知道“应该恢复到谁”：proof 自带 signedBy，receipt 的
// 签名者是 Runtime，command 的签名者是发起 actor——后两者不在文档里，
// 由 --signer 提供。不提供就只做 schema 与哈希承诺检查，并在报告里
// 如实记账为 skip，而不是悄悄当通过。
import { readFileSync } from "node:fs";
import { concat, utf8 } from "./bytes.js";
import { jcs, jcsBytes, sha256Ref } from "./canonical.js";
import { Report, readSchema, readVectorIndex } from "./harness.js";
import { verifies } from "./secp.js";
import { validator } from "./sets.js";

export interface CheckOptions {
  /** 期望的签名恢复地址（EVM，0x 开头）。 */
  signer?: string;
  /** 期望的 termsHash（sha256:… 引用形式），用于 deal-contract。 */
  expectTermsHash?: string;
}

interface KindSpec {
  kind: string;
  validate: (doc: any) => boolean;
  run: (rep: Report, doc: any, opts: CheckOptions) => void;
}

/** 按窄到宽的顺序尝试；第一个 schema 命中的即为文档类型。 */
const KINDS: KindSpec[] = [
  {
    kind: "funding-submission (buyer)",
    validate: buyerValidator(),
    run: () => {},
  },
  {
    kind: "funding-submission (seller)",
    validate: sellerValidator(),
    run: () => {},
  },
  {
    kind: "agreement-command",
    validate: compile("agreement-command.schema.json"),
    run: checkCommand,
  },
  {
    kind: "transition-proof",
    // 向量与抓包里都有整包形状：{proofs:[…]} 或裸数组。单链和整包
    // 都算 transition-proof，由 checkProof 内部展开。
    validate: (doc: any) => {
      const links = Array.isArray(doc)
        ? doc
        : doc && typeof doc === "object" && Array.isArray(doc.proofs)
          ? doc.proofs
          : [doc];
      return links.every((l: any) => proofLinkSchema(l) === true);
    },
    run: checkProof,
  },
  {
    kind: "transition-receipt",
    validate: compile("transition-receipt.schema.json"),
    run: checkReceipt,
  },
  {
    kind: "deal-contract",
    validate: compile("deal-contract.schema.json"),
    run: checkDealContract,
  },
  {
    kind: "domain-error",
    validate: compile("domain-error.schema.json"),
    run: checkDomainError,
  },
];

function compile(name: string): (doc: any) => boolean {
  return validator(readSchema(name));
}

const proofLinkSchema = compile("transition-proof.schema.json");

function buyerValidator(): (doc: any) => boolean {
  const schema = readSchema("funding-submission.schema.json");
  return validator({ ...schema.$defs.buyerSubmission, $defs: schema.$defs });
}

function sellerValidator(): (doc: any) => boolean {
  const schema = readSchema("funding-submission.schema.json");
  return validator({ ...schema.$defs.sellerSubmission, $defs: schema.$defs });
}

export function runCheck(rep: Report, file: string, opts: CheckOptions = {}): void {
  let doc: any;
  try {
    doc = JSON.parse(readFileSync(file, "utf8"));
  } catch (err) {
    rep.fail(`read ${file}`, String(err));
    return;
  }

  const spec = KINDS.find((k) => k.validate(doc) === true);
  if (!spec) {
    rep.fail(
      "detect kind",
      "the document matches none of the v1 schemas (funding-submission, agreement-command, transition-proof, transition-receipt, deal-contract, domain-error)",
    );
    return;
  }
  rep.ok(`detect kind → ${spec.kind}`);
  spec.run(rep, doc, opts);
}

// ── agreement-command ───────────────────────────────────────────────────────

function checkCommand(rep: Report, doc: any, opts: CheckOptions): void {
  // payloadHash 必须承诺 canonical 化之后的 payload——这是文档自身
  // 就能验证的完整性，不依赖任何外部信息。
  const declared = doc.payloadHash;
  const computed = sha256Ref(jcsBytes(doc.payload));
  rep.check(
    "payloadHash commits to the canonical payload",
    declared === computed,
    `document declares ${declared}, canonical payload hashes to ${computed}`,
  );

  if (!doc.signature) {
    rep.skip("command signature", "the document carries no signature member");
    return;
  }
  if (!opts.signer) {
    rep.skip(
      "command signature",
      "pass --signer <address> to check who the signature recovers to",
    );
    return;
  }
  const { sig } = doc.signature;
  const unsigned = omit(doc, ["signature"]);
  const tag = readVectorIndex().domainTags.command;
  rep.check(
    "signature recovers to the given signer",
    verifies(sig, concat(utf8(tag), jcsBytes(unsigned)), opts.signer),
    `signature does not recover to ${opts.signer}`,
  );
}

// ── transition-proof ────────────────────────────────────────────────────────

const PROOF_TAG = "kite:fulfill:transition-proof:v1";

function checkProof(rep: Report, doc: any): void {
  const links: any[] = Array.isArray(doc) ? doc : "proofs" in doc ? doc.proofs : [doc];
  const ordered = [...links].sort((a, b) => a.sequence - b.sequence);
  rep.check(
    "hash chain links",
    !("previousProofHash" in ordered[0]) &&
      ordered.slice(1).every((later, i) => later.previousProofHash === ordered[i].proofHash),
    "a later link does not quote its predecessor's proofHash",
  );
  // signedBy 是文档自带的，签名恢复不需要外部输入。
  const ok = ordered.every((p) =>
    verifies(p.signature, concat(utf8(PROOF_TAG), utf8(p.proofHash)), p.signedBy),
  );
  rep.check(
    "proof signatures recover to signedBy",
    ok,
    "a Runtime proof signature does not recover to the address in signedBy",
  );
}

// ── transition-receipt ──────────────────────────────────────────────────────

function checkReceipt(rep: Report, doc: any, opts: CheckOptions): void {
  const index = readVectorIndex();
  if (!doc.runtimeSignature) {
    rep.skip("receipt signature", "the document carries no runtimeSignature member");
    return;
  }
  if (!opts.signer) {
    rep.skip(
      "receipt signature",
      "pass --signer <runtime-address> to check the Runtime signature",
    );
    return;
  }
  // preimage 由白名单构建，不是删字段——与 receipts 集合同一条规则。
  const signed: Record<string, unknown> = {};
  for (const f of index.receiptSignedFields) {
    if (doc[f] !== undefined && doc[f] !== null) signed[f] = doc[f];
  }
  const preimage = concat(utf8(index.domainTags.receipt), jcsBytes(signed));
  rep.check(
    "runtime signature recovers to the given Runtime",
    verifies(doc.runtimeSignature.sig, preimage, opts.signer),
    `signature does not recover to ${opts.signer}`,
  );
}

// ── deal-contract ───────────────────────────────────────────────────────────

function checkDealContract(rep: Report, doc: any, opts: CheckOptions): void {
  // termsHash 的派生口径与 canonical 集合一致：签过的东西和已声明的
  // termsHash 都剥掉，再对 JCS 字节取 sha256。
  const stripped = omit(doc, ["signatures", "termsHash"]);
  const computed = sha256Ref(utf8(jcs(stripped)));
  if (opts.expectTermsHash) {
    rep.check(
      "termsHash matches the canonical bytes",
      computed === opts.expectTermsHash,
      `document hashes to ${computed}, expected ${opts.expectTermsHash}`,
    );
  } else {
    rep.skip(
      "termsHash",
      `canonical bytes hash to ${computed} — pass --expect-terms-hash to compare`,
    );
  }
}

// ── domain-error ────────────────────────────────────────────────────────────

function checkDomainError(rep: Report, doc: any): void {
  const catalog: Record<string, boolean> = {};
  for (const e of readSchema("error-catalog.json").errors) {
    catalog[e.code] = e.retriable;
  }
  if (!(doc.code in catalog)) {
    rep.fail("error code is in the catalog", `unknown code ${doc.code}`);
    return;
  }
  rep.ok("error code is in the catalog");
  // wire 上抄的 retriable 与目录打架，是最值得当面对质的一条。
  rep.check(
    "retriable matches the catalog",
    doc.retriable === catalog[doc.code],
    `payload carries retriable=${doc.retriable}, catalog says ${catalog[doc.code]} for ${doc.code}`,
  );
}

// ── 公共小件 ────────────────────────────────────────────────────────────────

function omit(obj: Record<string, unknown>, keys: string[]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(obj)) {
    if (!keys.includes(k)) out[k] = v;
  }
  return out;
}
