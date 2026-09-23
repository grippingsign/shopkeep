// 八个离线向量集合的回放逻辑，逐条对齐官方 Python runner 的断言。
// 官方仓库的 examples 只回放了其中五个集合（canonical/signing/commands/
// receipts/settlement），funding、proofs、errors 三个在 TS 侧没有实现——
// 这就是这个仓库存在的理由之一。
import { Ajv2020 } from "ajv/dist/2020.js";
import { jcs, jcsBytes, sha256Ref } from "./canonical.js";
import { settlementDigest } from "./eip712.js";
import { Report, loadSet, readSchema, readVectorIndex } from "./harness.js";
import { proofHash } from "./proof.js";
import { keccak256Hex, verifies } from "./secp.js";
import { concat, utf8 } from "./bytes.js";
import type { ProofLink } from "./proof.js";

const ajv = new Ajv2020({ strict: false, allErrors: true });

// 与官方 Python runner 对齐：离线集合不开 format 断言（jsonschema 的
// FormatChecker 只在 capture 模式传入），这里注册的是宽松的形态检查，
// 仅供 schema 编译不报 unknown format。
ajv.addFormat("date-time", /^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$/);
ajv.addFormat("uri", true);

// ajv 的 ValidateFunction 是类型谓词（data is T），在条件里会把 any
// 收窄成 unknown，后面的属性访问就全报错了。这里把它当普通的
// (data) => boolean 用——校验结果本来就该由调用处自己判断。
function validator(schema: any): (data: any) => boolean {
  return ajv.compile(schema) as (data: any) => boolean;
}

function str(x: unknown): string {
  return typeof x === "string" ? x : String(x);
}

// ── canonical ───────────────────────────────────────────────────────────────

export function runCanonical(rep: Report): void {
  for (const { name, input, expected } of loadSet("canonical")) {
    const label = `canonical/${name}`;
    // termsHash 成员：签名与已声明的 termsHash 都要剥掉；
    // 其他成员（命令）：剥 signature。签过的东西不参与哈希。
    const drop =
      expected.member === "termsHash" ? ["signatures", "termsHash"] : ["signature"];
    const stripped = omit(input, drop);
    const canonical = jcs(stripped);
    // 两个断言都要：只对哈希会让一个行为不同的规范化器靠碰撞混过关。
    rep.check(
      `${label} [bytes]`,
      canonical === expected.canonical,
      `got ${canonical.slice(0, 120)}…`,
    );
    rep.check(
      `${label} [${expected.member}]`,
      sha256Ref(utf8(canonical)) === expected.hash,
      `got ${sha256Ref(utf8(canonical))}`,
    );
  }
}

// ── signing ─────────────────────────────────────────────────────────────────

export function runSigning(rep: Report): void {
  for (const { name, input, expected } of loadSet("signing")) {
    const tag = utf8(input.domainTag);
    const body =
      "signedValue" in input
        ? utf8(input.signedValue)
        : jcsBytes(omit(input.signedObject, ["signature"]));
    const got = verifies(input.signature, concat(tag, body), input.claimedSigner);
    const label = `signing/${name}`;
    rep.check(
      label,
      got === expected.valid,
      `expected valid=${expected.valid}` + (expected.valid ? "" : ` (reason: ${expected.reason})`),
    );
  }
}

// ── commands ────────────────────────────────────────────────────────────────

export function runCommands(rep: Report): void {
  const validate = validator(readSchema("agreement-command.schema.json"));
  const index = readVectorIndex();
  for (const { name, input, expected } of loadSet("commands")) {
    const label = `commands/${name}`;
    const bodies = "first" in input ? [input.first, input.second] : [input];

    for (const body of bodies) {
      const valid = validate(body) === true;
      rep.check(
        `${label} [schema]`,
        valid === expected.schemaValid,
        `schema said valid=${valid}, expected ${expected.schemaValid}`,
      );
      if (!expected.schemaValid) continue;

      rep.check(
        `${label} [payloadHash]`,
        body.payloadHash === sha256Ref(jcsBytes(body.payload)),
        "payloadHash must commit to the canonical payload",
      );

      if (expected.signatureValid) {
        const addr = index.keys[expected.actorRole].address;
        const unsigned = omit(body, ["signature"]);
        rep.check(
          `${label} [signature]`,
          verifies(body.signature.sig, concat(utf8("kite:a2a-agreement:command:v1"), jcsBytes(unsigned)), addr),
          "command signature did not recover to the actor's key",
        );
      }

      // §4.2 结算锚点：payload 里两个字符串成员上链前各过一次 keccak256。
      for (const [member, anchor] of [
        ["reasonCode", "reasonHash"],
        ["decisionId", "decisionId32"],
      ] as const) {
        if (expected.settlement && anchor in expected.settlement) {
          const got = keccak256Hex(utf8(str(body.payload[member])));
          rep.check(
            `${label} [settlement.${anchor}]`,
            got === expected.settlement[anchor],
            `keccak256(${member}) = ${got}, vector expects ${expected.settlement[anchor]}`,
          );
        }
      }
    }
  }
}

// ── funding ─────────────────────────────────────────────────────────────────

export function runFunding(rep: Report): void {
  const schema = readSchema("funding-submission.schema.json");
  const defs = schema.$defs;
  const roleValidator: Record<string, (data: any) => boolean> = {
    buyer: validator({ ...defs.buyerSubmission, $defs: defs }),
    seller: validator({ ...defs.sellerSubmission, $defs: defs }),
  };
  for (const { name, input, expected } of loadSet("funding")) {
    const role = expected.role;
    const valid = roleValidator[role](input) === true;
    rep.check(
      `funding/${name} [schema:${role}]`,
      valid === expected.schemaValid,
      `as a ${role} submission, schema said valid=${valid}, expected ${expected.schemaValid}`,
    );
  }
}

// ── proofs ──────────────────────────────────────────────────────────────────

const PROOF_TAG = "kite:fulfill:transition-proof:v1";

export function runProofs(rep: Report): void {
  const validate = validator(readSchema("transition-proof.schema.json"));
  for (const { name, input, expected } of loadSet("proofs")) {
    const label = `proofs/${name}`;
    // 合法用例带整个回复的数组；拒绝用例只有一条链。
    const links: any[] =
      typeof input === "object" && input !== null && "proofs" in input ? input.proofs : [input];
    const valid = links.every((link) => validate(link) === true);
    rep.check(
      `${label} [schema]`,
      valid === expected.schemaValid,
      `schema said valid=${valid}, expected ${expected.schemaValid}`,
    );
    if (!expected.schemaValid) continue;

    const ordered = [...links].sort((a, b) => a.sequence - b.sequence);
    rep.check(
      `${label} [order]`,
      ordered.map((p) => p.sequence).join(",") === expected.orderedBySequence.join(","),
      "sequence order does not match the expected chain",
    );
    // previousProofHash == 序列减一那条的 proofHash；首条没有这个成员。
    const linked =
      !("previousProofHash" in ordered[0]) &&
      ordered.slice(1).every((later, i) => later.previousProofHash === ordered[i].proofHash);
    rep.check(
      `${label} [chain]`,
      linked === expected.chainLinked,
      "the hash chain does not link as expected",
    );
    rep.check(
      `${label} [receiptHash]`,
      ordered[ordered.length - 1].proofHash === expected.receiptHashForNextCommand,
      "the newest proofHash is not the anchor the next command must quote",
    );

    // 链只证明这些链接彼此一致；重算才证明链接的内容是 Runtime
    // 真正认证过的内容。没有这一步，Runtime 想发什么载荷都行，
    // 只要哈希互相指得上。
    if (expected.proofHashesRecomputable) {
      rep.check(
        `${label} [proofHash-preimage]`,
        ordered.every((p) => proofHash(p as ProofLink) === p.proofHash),
        "a proofHash does not match the §6.3.1 preimage recomputed from the link's own members",
      );
    }
    if (expected.signaturesVerify) {
      const ok = ordered.every((p) =>
        verifies(p.signature, concat(utf8(PROOF_TAG), utf8(p.proofHash)), p.signedBy),
      );
      rep.check(
        `${label} [signature]`,
        ok,
        "a Runtime proof signature does not recover to signedBy",
      );
      rep.check(
        `${label} [signedBy]`,
        ordered.every((p) => String(p.signedBy).toLowerCase() === String(expected.signedBy).toLowerCase()),
        "signedBy is not the expected Runtime address — note it is an EVM address, not a DID or keyId",
      );
    }
  }
}

// ── receipts ────────────────────────────────────────────────────────────────

export function runReceipts(rep: Report): void {
  const validate = validator(readSchema("transition-receipt.schema.json"));
  const index = readVectorIndex();
  const signedFields: string[] = index.receiptSignedFields;
  const runtimeAddr = index.keys.runtime.address;

  for (const { name, input, expected } of loadSet("receipts")) {
    const label = `receipts/${name}`;
    // preimage 由白名单构建，不是删掉签名字段：以后 schema 加的成员
    // 不该悄悄混进签名内容里。
    const signed: Record<string, unknown> = {};
    for (const f of signedFields) {
      if (input[f] !== undefined && input[f] !== null) signed[f] = input[f];
    }
    const preimage = concat(utf8("kite:a2a-agreement:receipt:v1"), jcsBytes(signed));
    if ("signedPreimage" in expected) {
      rep.check(
        `${label} [preimage]`,
        jcs(signed) === expected.signedPreimage,
        "receipt preimage differs",
      );
    }
    if (expected.signatureValid !== undefined && expected.signatureValid !== null && validate(input) === true) {
      const sig = input.runtimeSignature;
      const got = Boolean(sig) && verifies(sig.sig, preimage, runtimeAddr);
      rep.check(
        `${label} [signature]`,
        got === expected.signatureValid,
        `expected signatureValid=${expected.signatureValid}` +
          (expected.reason ? ` (${expected.reason})` : ""),
      );
    }
  }
}

// ── settlement ──────────────────────────────────────────────────────────────

export function runSettlement(rep: Report): void {
  for (const { name, input, expected } of loadSet("settlement")) {
    const label = `settlement/${name}`;
    const digest = settlementDigest(input);
    rep.check(
      `${label} [structHash]`,
      digest.structHash === expected.structHash,
      `got ${digest.structHash}`,
    );
    rep.check(
      `${label} [digest]`,
      digest.digest === expected.digest,
      `got ${digest.digest}`,
    );
    rep.check(
      `${label} [signature]`,
      verifies(input.signature, eip712Preimage(input), input.claimedSigner) === expected.valid,
      "settlement signature did not recover to the claimed signer",
    );
  }
}

// ── errors ──────────────────────────────────────────────────────────────────

export function runErrors(rep: Report): void {
  const validate = validator(readSchema("domain-error.schema.json"));
  const catalog: Record<string, boolean> = {};
  for (const e of readSchema("error-catalog.json").errors) {
    catalog[e.code] = e.retriable;
  }
  for (const { name, input, expected } of loadSet("errors")) {
    const label = `errors/${name}`;
    const valid = validate(input) === true;
    rep.check(
      `${label} [schema]`,
      valid === expected.schemaValid,
      `schema said valid=${valid}, expected ${expected.schemaValid}`,
    );
    if (!valid) continue;

    // 目录才是重试语义的权威；wire 上的值只是给没内置目录的客户端
    // 抄的一份。抄的和源打架，正是这个检查要抓的。
    rep.check(
      `${label} [catalog]`,
      catalog[input.code] === expected.retriable,
      `catalog says retriable=${catalog[input.code]} for ${input.code}, case expects ${expected.retriable}`,
    );
    rep.check(
      `${label} [wire-matches-catalog]`,
      (input.retriable === expected.retriable) === expected.wireMatchesCatalog,
      `payload carries retriable=${input.retriable} for ${input.code}; catalog says ${expected.retriable}, and the case expects this comparison to be ${expected.wireMatchesCatalog}`,
    );
  }
}

// ── 公共小件 ────────────────────────────────────────────────────────────────

function omit(obj: Record<string, unknown>, keys: string[]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(obj)) {
    if (!keys.includes(k)) out[k] = v;
  }
  return out;
}

/** settlement 签名的 preimage = \x19\x01 + domain + structHash（原始字节）。 */
function eip712Preimage(input: any): Uint8Array {
  const digest = settlementDigest(input);
  return concat(
    utf8("\x19\x01"),
    fromHex(digest.domainSeparator),
    fromHex(digest.structHash),
  );
}

function fromHex(s: string): Uint8Array {
  const h = s.replace(/^0x/, "");
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(h.slice(2 * i, 2 * i + 2), 16);
  }
  return out;
}
