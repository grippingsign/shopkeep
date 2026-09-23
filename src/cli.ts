// shopkeep 的命令行入口。
//
// 两个命令：
//   vectors            回放 vendor/vectors 下的八个离线集合
//   capture <file>     校验一份抓回来的 agreement-proofs 响应
//
// live 转移（状态机、actor 绑定、并发语义）不是文档能验证的东西，
// 需要真实 Runtime——本版本和官方 runner 一样，如实标注“未实现”，
// 不装作通过。
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
  shopkeep vectors [--strict]    回放全部离线向量集合
  shopkeep capture <file.json>   校验一份抓取的 agreement-proofs 响应

--strict: 有跳过的用例时以非零退出。发布门禁用它；不用的场合
          一次纯文档检查的运行会以 0 退出，别读成符合性信号。`;

function main(argv: string[]): number {
  const [cmd, ...rest] = argv;

  if (cmd === "vectors" || cmd === undefined || cmd === "help" || cmd === "--help") {
    if (cmd !== "vectors") {
      console.log(USAGE);
      return 0;
    }
    const strict = rest.includes("--strict");
    const rep = new Report();
    runCanonical(rep);
    runSigning(rep);
    runCommands(rep);
    runFunding(rep);
    runProofs(rep);
    runReceipts(rep);
    runSettlement(rep);
    runErrors(rep);
    // 状态机转移与资金绑定是活体行为，离线跑不了，如实记账。
    rep.skip(
      "transitions (live)",
      "needs a Runtime endpoint: these are properties of a live agreement, not of a document",
    );
    rep.skip(
      "funding/dealIdentity (live)",
      "needs a Runtime endpoint: refuse-before-broadcast is a property of a live Runtime",
    );
    return rep.summary(strict);
  }

  if (cmd === "capture") {
    const file = rest[0];
    if (!file) {
      console.error("capture 需要一个文件参数");
      return 1;
    }
    const rep = new Report();
    runProofCapture(rep, file);
    return rep.summary(true);
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
