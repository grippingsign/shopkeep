// 校验一份从 Runtime 抓回来的 agreement-proofs 响应。
//
// 这和回放向量不是一回事：向量验证的是“文档对不对”，这里验证的是
// “这份证据链作为一个整体能不能信”。多查三样东西——序列从 1 起 contiguous、
// 整条链只有一个 agreementId、相邻链接的 fromState/toState 首尾相接，
// 以及 stateHash 双向核对。任何一条对不上，这条链就不能拿来当证据。
import { readFileSync } from "node:fs";
import { Ajv2020 } from "ajv/dist/2020.js";
import addFormatsModule from "ajv-formats";
import { Report, readSchema } from "./harness.js";
import { proofHash, stateHash, type ProofLink } from "./proof.js";
import { verifies } from "./secp.js";
import { concat, utf8 } from "./bytes.js";

const PROOF_TAG = "kite:fulfill:transition-proof:v1";
const addFormats = (addFormatsModule as any).default ?? addFormatsModule;

export function runProofCapture(rep: Report, path: string): void {
  const prefix = "capture/proofs";
  let payload: any;
  try {
    payload = JSON.parse(readFileSync(path, "utf8"));
  } catch (exc) {
    rep.fail(`${prefix} [payload]`, `cannot read ${path}: ${(exc as Error).message}`);
    return;
  }

  if (typeof payload !== "object" || payload === null || !Array.isArray(payload.proofs)) {
    rep.fail(`${prefix} [payload]`, "expected a decoded agreement-proofs object with a proofs array");
    return;
  }

  if ("kind" in payload) {
    rep.check(
      `${prefix} [envelope]`,
      payload.kind === "agreement-proofs" &&
        Object.keys(payload).length === 2 &&
        "proofs" in payload,
      "expected exactly kind=agreement-proofs and proofs in the response",
    );
  }

  const links: any[] = payload.proofs;
  if (links.length === 0) {
    rep.fail(`${prefix} [payload]`, "proofs must contain at least one link");
    return;
  }
  rep.ok(`${prefix} [payload]`);

  const ajv = new Ajv2020({ strict: false, allErrors: true });
  addFormats(ajv);
  const validate = ajv.compile(readSchema("transition-proof.schema.json"));
  const errors = links.flatMap((link, i) => {
    const ok = validate(link) === true;
    return ok ? [] : [`proofs[${i}]: ${ajv.errorsText(validate.errors)}`];
  });
  rep.check(`${prefix} [schema]`, errors.length === 0, errors[0] ?? "");
  if (errors.length > 0) return;

  const ordered = [...links].sort((a, b) => a.sequence - b.sequence);
  const sequences = ordered.map((p) => p.sequence);
  rep.check(
    `${prefix} [sequence]`,
    JSON.stringify(sequences) === JSON.stringify(range(1, ordered.length + 1)),
    `expected a contiguous chain beginning at 1, got ${JSON.stringify(sequences)}`,
  );

  const agreementIds = new Set(ordered.map((p) => p.agreementId));
  rep.check(
    `${prefix} [agreement]`,
    agreementIds.size === 1,
    `proofs span multiple agreements: ${JSON.stringify([...agreementIds].sort())}`,
  );

  const statesLink = ordered
    .slice(1)
    .every((later, i) => later.fromState === ordered[i].toState);
  rep.check(
    `${prefix} [stateLink]`,
    statesLink,
    "a later link's fromState does not match the earlier link's toState",
  );

  // stateHash 双向核对 + proofHash 重算 + Runtime 签名，一个都不能少。
  const stateHashesValid = ordered.every((p) => {
    const prevOk =
      !("previousStateHash" in p) ||
      (Boolean(p.fromState) &&
        p.previousStateHash === stateHash(p.agreementId, p.fromState, p.sequence - 1));
    const nextOk =
      !("nextStateHash" in p) ||
      p.nextStateHash === stateHash(p.agreementId, p.toState, p.sequence);
    return prevOk && nextOk;
  });
  rep.check(
    `${prefix} [stateHash]`,
    stateHashesValid,
    "a previousStateHash or nextStateHash does not match its state tuple",
  );

  rep.check(
    `${prefix} [proofHash]`,
    ordered.every((p) => proofHash(p as ProofLink) === p.proofHash),
    "a proofHash does not match the §6.3.1 preimage recomputed from its link",
  );

  const signaturesValid = ordered.every(
    (p) =>
      Boolean(p.signature && p.signedBy) &&
      verifies(p.signature, concat(utf8(PROOF_TAG), utf8(p.proofHash)), p.signedBy),
  );
  rep.check(
    `${prefix} [signature]`,
    signaturesValid,
    "a proof is unsigned or its Runtime signature does not recover to signedBy",
  );
}

function range(from: number, to: number): number[] {
  const out: number[] = [];
  for (let i = from; i < to; i++) out.push(i);
  return out;
}
