// check 子命令：对单份文档的校验路径。
//
// 用官方向量的 input 当真实文档喂进去——它们本来就是官方按各类型
// 造出来的样例，比手写的更贴近 wire 上的真实形状。
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { runCheck } from "../src/check.js";
import { Report, VECTORS } from "../src/harness.js";

const SELLER = "0x1563915e194d8cfba1943570603f7606a3115508";
const BUYER = "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a";
const RUNTIME = "0x5cbdd86a2fa8dc4bddd8a8f69dba48572eec07fb";

const tmp = mkdtempSync(join(tmpdir(), "shopkeep-check-"));
afterAll(() => {
  // tmpdir 由操作系统清理；这里不引入 rimraf 之类的依赖。
});

function withFile(doc: unknown): string {
  const file = join(tmp, `doc-${Math.random().toString(36).slice(2)}.json`);
  writeFileSync(file, JSON.stringify(doc));
  return file;
}

function vectorInput(set: string, name: string): string {
  return join(VECTORS, set, name, "input.json");
}

function run(file: string, opts = {}) {
  const rep = new Report();
  runCheck(rep, file, opts);
  return rep;
}

describe("check: 类型识别", () => {
  it("识别 agreement-command 并通过 payloadHash 承诺检查", () => {
    const rep = run(vectorInput("commands", "valid-delivered"));
    expect(rep.failed).toHaveLength(0);
    expect(rep.passed).toContain("detect kind → agreement-command");
    expect(rep.passed).toContain("payloadHash commits to the canonical payload");
  });

  it("识别 deal-contract，--expect-terms-hash 比对通过", () => {
    const rep = run(vectorInput("canonical", "deal-contract-minimal"), {
      expectTermsHash: "sha256:feba188b56c1e0deba060f0284f9e26772f20802a8e95578a3a52d028e6308d4",
    });
    expect(rep.failed).toHaveLength(0);
    expect(rep.passed).toContain("detect kind → deal-contract");
    expect(rep.passed).toContain("termsHash matches the canonical bytes");
  });

  it("deal-contract 的 termsHash 比对失败会被抓住", () => {
    const rep = run(vectorInput("canonical", "deal-contract-minimal"), {
      expectTermsHash: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    });
    expect(rep.failed.map((f) => f.name)).toContain("termsHash matches the canonical bytes");
  });

  it("识别 transition-receipt，--signer 给 Runtime 时签名恢复通过", () => {
    const rep = run(vectorInput("receipts", "valid-command-driven"), { signer: RUNTIME });
    expect(rep.failed).toHaveLength(0);
    expect(rep.passed).toContain("runtime signature recovers to the given Runtime");
  });

  it("receipt 签名恢复到非 Runtime 地址时失败", () => {
    const rep = run(vectorInput("receipts", "valid-command-driven"), { signer: SELLER });
    expect(rep.failed.map((f) => f.name)).toContain(
      "runtime signature recovers to the given Runtime",
    );
  });

  it("识别 domain-error 并检查目录一致性", () => {
    const rep = run(vectorInput("errors", "valid-deadline-exceeded"));
    expect(rep.failed).toHaveLength(0);
    expect(rep.passed).toContain("detect kind → domain-error");
    expect(rep.passed).toContain("error code is in the catalog");
  });

  it("识别 funding-submission（buyer/seller 两个面）", () => {
    const buyer = run(vectorInput("funding", "valid-buyer-submission"));
    expect(buyer.failed).toHaveLength(0);
    expect(buyer.passed[0]).toContain("funding-submission");
  });

  it("不认识的文档报 unknown kind，而不是乱猜", () => {
    const rep = run(withFile({ hello: "world" }));
    expect(rep.failed.map((f) => f.name)).toContain("detect kind");
  });

  it("坏 JSON 报读取失败", () => {
    const file = join(tmp, "broken.json");
    writeFileSync(file, "not json at all");
    const rep = run(file);
    expect(rep.failed.map((f) => f.name)).toContain(`read ${file}`);
  });
});

describe("check: 签名恢复", () => {
  it("command 签名恢复到正确的 actor 地址", () => {
    const rep = run(vectorInput("commands", "valid-delivered"), { signer: SELLER });
    expect(rep.failed).toHaveLength(0);
    expect(rep.skipped).toHaveLength(0); // 给了 signer，skip 分支不应出现
  });

  it("command 签名恢复到错误地址时失败", () => {
    const rep = run(vectorInput("commands", "valid-delivered"), { signer: BUYER });
    expect(rep.failed.map((f) => f.name)).toContain(
      "signature recovers to the given signer",
    );
  });

  it("不给 --signer 时如实 skip，不当成通过", () => {
    const rep = run(vectorInput("commands", "valid-delivered"));
    expect(rep.skipped.map((s) => s.name)).toContain("command signature");
  });

  it("proof 链的签名恢复用文档自带的 signedBy", () => {
    const rep = run(vectorInput("proofs", "valid-chain"));
    expect(rep.failed).toHaveLength(0);
    expect(rep.passed).toContain("proof signatures recover to signedBy");
    expect(rep.passed).toContain("hash chain links");
  });
});
