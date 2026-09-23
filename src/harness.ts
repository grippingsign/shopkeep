// 回放骨架：发现用例、装载、记账。
//
// 记账规则抄自官方 Python runner，一条不差：
//   - 失败必须让进程以非零退出；
//   - 跳过的用例永远算“未检查”，不算“通过”——一个把跑不了的用例
//     悄悄计成成功的套件，告诉你的是“符合规范”，检查的却是空气。
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

export const ROOT = join(import.meta.dirname, "..");
export const VECTORS = join(ROOT, "vendor", "vectors", "v1");
export const SCHEMAS = join(ROOT, "vendor", "schemas", "v1");

export interface CaseDir {
  set: string;
  name: string;
  input: any;
  expected: any;
}

/** 一个集合下的全部用例，按目录名排序。点开头的目录不是用例。 */
export function loadSet(set: string): CaseDir[] {
  const dir = join(VECTORS, set);
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return [];
  }
  return entries
    .filter((e) => !e.startsWith("."))
    .sort()
    .map((name) => ({
      set,
      name,
      input: JSON.parse(readFileSync(join(dir, name, "input.json"), "utf8")),
      expected: JSON.parse(readFileSync(join(dir, name, "expected.json"), "utf8")),
    }));
}

export function readSchema(name: string): any {
  return JSON.parse(readFileSync(join(SCHEMAS, name), "utf8"));
}

export function readVectorIndex(): any {
  return JSON.parse(readFileSync(join(VECTORS, "index.json"), "utf8"));
}

export class Report {
  readonly passed: string[] = [];
  readonly failed: Array<{ name: string; why: string }> = [];
  readonly skipped: Array<{ name: string; why: string }> = [];

  ok(name: string): void {
    this.passed.push(name);
  }

  fail(name: string, why: string): void {
    this.failed.push({ name, why });
  }

  skip(name: string, why: string): void {
    this.skipped.push({ name, why });
  }

  check(name: string, condition: boolean, why = ""): void {
    if (condition) {
      this.ok(name);
    } else {
      this.fail(name, why);
    }
  }

  /** 与官方口径一致：有失败 → 1；有跳过 → 提示“未全部检查”。 */
  summary(strict = false): number {
    for (const f of this.failed) {
      console.error(`  FAIL  ${f.name}\n        ${f.why}`);
    }
    for (const s of this.skipped) {
      console.error(`  SKIP  ${s.name} — ${s.why}`);
    }
    console.error(
      `\n${this.passed.length} passed, ${this.failed.length} failed, ${this.skipped.length} skipped`,
    );
    if (this.failed.length > 0) return 1;
    if (this.skipped.length === 0) {
      console.error("CONFORMANCE PASS: every case was checked.");
      return 0;
    }
    console.error("NOT a conformance pass: skipped cases were not checked.");
    if (strict) return 2;
    return 0;
  }
}
