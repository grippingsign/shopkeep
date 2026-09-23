// 回放 vendor/vectors/v1 全部八个离线集合。
// 目标只有一个：0 失败。任何一个 FAIL 都意味着实现和规范向量
// 在某一点上意见不一致——那不是向量错了。
import { describe, expect, it } from "vitest";
import { Report } from "../src/harness.js";
import {
  runCanonical,
  runCommands,
  runErrors,
  runFunding,
  runProofs,
  runReceipts,
  runSettlement,
  runSigning,
} from "../src/sets.js";

const SETS: Array<[string, (rep: Report) => void, number]> = [
  // 每项至少要跑出这么多条断言——计数是防“空转通过”的护栏：
  // 一个因路径问题悄悄没加载到用例的集合，会在这里现形。
  ["canonical", runCanonical, 12],
  ["signing", runSigning, 12],
  ["commands", runCommands, 20],
  ["funding", runFunding, 9],
  ["proofs", runProofs, 10],
  ["receipts", runReceipts, 8],
  ["settlement", runSettlement, 30],
  ["errors", runErrors, 25],
];

describe("离线向量回放", () => {
  for (const [name, run, minChecks] of SETS) {
    it(`${name} 全部通过`, () => {
      const rep = new Report();
      run(rep);
      expect(
        rep.failed,
        `${name} 有失败项:\n${rep.failed.map((f) => `  ${f.name}: ${f.why}`).join("\n")}`,
      ).toEqual([]);
      expect(rep.passed.length, `${name} 断言数量异常，疑似未加载到用例`).toBeGreaterThanOrEqual(minChecks);
    });
  }

  it("八个集合加起来的断言总量在合理区间", () => {
    const rep = new Report();
    for (const [, run] of SETS) run(rep);
    expect(rep.failed).toEqual([]);
    expect(rep.passed.length).toBeGreaterThan(120);
  });
});
