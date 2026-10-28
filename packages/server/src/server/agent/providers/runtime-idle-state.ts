import type { ChildProcess } from "node:child_process";
import { readFileSync, readdirSync } from "node:fs";

type ProcessHandle = Pick<ChildProcess, "pid" | "exitCode" | "signalCode">;

function processStart(pid: number): string {
  const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
  const start = stat.slice(stat.lastIndexOf(")") + 2).split(/\s+/)[19];
  if (!start) throw new Error("Runtime process identity unavailable");
  return start;
}

// A background shell can survive its tool response. Opaque wrappers and helper
// processes remain protected until the provider can establish their lifecycle.
export function createRuntimeIdleCheck(child: ProcessHandle): () => "idle" | "unknown" {
  let start: string | undefined;
  try {
    if (process.platform === "linux" && child.pid) start = processStart(child.pid);
  } catch {
    /* Missing identity is retained below. */
  }
  return () => {
    try {
      if (
        !start ||
        !child.pid ||
        child.exitCode !== null ||
        child.signalCode !== null ||
        processStart(child.pid) !== start
      )
        return "unknown";
      const root = `/proc/${child.pid}/task`;
      for (const tid of readdirSync(root)) {
        if (readFileSync(`${root}/${tid}/children`, "utf8").trim()) return "unknown";
      }
      return processStart(child.pid) === start ? "idle" : "unknown";
    } catch {
      return "unknown";
    }
  };
}
