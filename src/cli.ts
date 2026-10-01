// shopkeep 的命令行入口。
//
// 三个命令：
//   vectors            回放 vendor/vectors 下的八个离线集合
//   capture <file>     校验一份抓回来的 agreement-proofs 响应
//   check <file>       校验任意一份 v1 协议文档（自动识别类型）
//
// 所有命令都接受 --json：输出机器可读报告而不是人读摘要，退出码不变。
//
// live 转移（状态机、actor 绑定、并发语义）不是文档能验证的东西，
// 需要真实 Runtime——本版本和官方 runner 一样，如实标注“未实现”，
// 不装作通过。
import { runCheck } from "./check.js";
import { runProofCapture } from "./capture.js";
import { Report } from "./harness.js";
import {
  runCanonical,
  runCommands,
  runErrors,
  runFunding,
  runProofs,
  runReceipts,
  runSettlement,
  runSigning,
} from "./sets.js";

const USAGE = `shopkeep — Kite A2A Coordination Extension v1 的 TS 校验工具箱

用法:
  shopkeep vectors [--only <set>] [--strict] [--json]   回放离线向量集合
  shopkeep capture <file.json> [--json]  校验一份抓取的 agreement-proofs 响应
  shopkeep check <file.json> [选项]      校验任意一份 v1 协议文档

check 选项:
  --signer <address>              期望的签名恢复地址（Runtime / actor）
  --expect-terms-hash <sha256:…>  与 deal-contract 的 canonical 派生比对

--strict: 有跳过的用例时以非零退出。发布门禁用它；不用的场合
          一次纯文档检查的运行会以 0 退出，别读成符合性信号。
--json:   输出机器可读报告（passed/failed/skipped + 原因），退出码不变。`;

const VECTOR_RUNNERS = {
  canonical: runCanonical,
  signing: runSigning,
  commands: runCommands,
  funding: runFunding,
  proofs: runProofs,
  receipts: runReceipts,
  settlement: runSettlement,
  errors: runErrors,
} as const;

function finish(rep: Report, strict: boolean, json: boolean): number {
  if (json) console.log(JSON.stringify(rep.toJSON(), null, 2));
  return rep.summary(strict);
}

function flag(rest: string[], name: string): string | undefined {
  const i = rest.indexOf(name);
  if (i === -1) return undefined;
  return rest[i + 1];
}

function main(argv: string[]): number {
  const [cmd, ...rest] = argv;

  if (cmd === "vectors" || cmd === undefined || cmd === "help" || cmd === "--help") {
    if (cmd !== "vectors") {
      console.log(USAGE);
      return 0;
    }
    const rep = new Report();
    const selected = flag(rest, "--only");
    if (selected && !(selected in VECTOR_RUNNERS)) {
      console.error(`未知向量集合: ${selected}；可选值: ${Object.keys(VECTOR_RUNNERS).join(", ")}`);
      return 1;
    }
    const runners = selected
      ? [[selected, VECTOR_RUNNERS[selected as keyof typeof VECTOR_RUNNERS]] as const]
      : Object.entries(VECTOR_RUNNERS);
    for (const [, run] of runners) run(rep);
    // 状态机转移与资金绑定是活体行为，离线跑不了，如实记账。
    if (!selected) {
      rep.skip(
        "transitions (live)",
        "needs a Runtime endpoint: these are properties of a live agreement, not of a document",
      );
      rep.skip(
        "funding/dealIdentity (live)",
        "needs a Runtime endpoint: refuse-before-broadcast is a property of a live Runtime",
      );
    }
    return finish(rep, rest.includes("--strict"), rest.includes("--json"));
  }

  if (cmd === "capture") {
    const file = rest.find((a) => !a.startsWith("--"));
    if (!file) {
      console.error("capture 需要一个文件参数");
      return 1;
    }
    const rep = new Report();
    runProofCapture(rep, file);
    return finish(rep, true, rest.includes("--json"));
  }

  if (cmd === "check") {
    const file = rest.find((a) => !a.startsWith("--"));
    if (!file) {
      console.error("check 需要一个文件参数\n");
      console.log(USAGE);
      return 1;
    }
    const rep = new Report();
    runCheck(rep, file, {
      signer: flag(rest, "--signer"),
      expectTermsHash: flag(rest, "--expect-terms-hash"),
    });
    return finish(rep, true, rest.includes("--json"));
  }

  console.error(`未知命令: ${cmd}\n`);
  console.log(USAGE);
  return 1;
}

// 直接执行时（tsx src/cli.ts ...）
if (process.argv[1] && process.argv[1].endsWith("cli.ts")) {
  process.exit(main(process.argv.slice(2)));
}

export { main };
