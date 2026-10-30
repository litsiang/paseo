import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, expect, test, vi } from "vitest";
import pino from "pino";
import { spawnProcess, execCommand } from "./spawn.js";
import { buildProviderRegistry } from "../server/agent/provider-registry.js";
import { createTerminal } from "../terminal/terminal.js";
import { runPluginBuild } from "../server/plugins/preparation.js";
import { UnsupportedWorkerExecutionError } from "./worker-execution.js";

const logger = pino({ level: "silent" });
afterEach(() => vi.unstubAllEnvs());

test("all registered built-in and derived providers refuse create and catalog probes before an unsupported required transport executes", async () => {
  vi.stubEnv("LOOM_WORKER_ISOLATION", "");
  const registry = buildProviderRegistry(logger, {
    isDev: true,
    providerOverrides: {
      "custom-acp": {
        extends: "acp",
        label: "Custom ACP",
        command: [process.execPath, "-e", "process.exit(99)"],
      },
      "custom-claude": { extends: "claude", label: "Custom Claude" },
    },
  });
  vi.stubEnv("LOOM_WORKER_ISOLATION", "required");
  try {
    expect(Object.keys(registry)).toEqual(
      expect.arrayContaining([
        "claude",
        "codex",
        "copilot",
        "opencode",
        "pi",
        "omp",
        "custom-acp",
        "custom-claude",
      ]),
    );
    for (const definition of Object.values(registry)) {
      expect(() => definition.createClient(logger)).toThrow(UnsupportedWorkerExecutionError);
      await expect(definition.fetchCatalog({ scope: "global", force: false })).rejects.toThrow(
        UnsupportedWorkerExecutionError,
      );
    }
    expect(() => buildProviderRegistry(logger)).toThrow(UnsupportedWorkerExecutionError);
  } finally {
    vi.stubEnv("LOOM_WORKER_ISOLATION", "");
  }
});

test("required process, PTY and plugin-build exits reject before any project side effect", async () => {
  const directory = mkdtempSync(path.join(tmpdir(), "paseo-worker-exits-"));
  const marker = path.join(directory, "escaped");
  const command = ["-e", `require('fs').writeFileSync(${JSON.stringify(marker)},'owner')`];
  vi.stubEnv("LOOM_WORKER_ISOLATION", "required");
  try {
    expect(() => spawnProcess(process.execPath, command)).toThrow(UnsupportedWorkerExecutionError);
    await expect(execCommand(process.execPath, command)).rejects.toThrow(
      UnsupportedWorkerExecutionError,
    );
    await expect(createTerminal({ cwd: directory, workspaceId: "workspace" })).rejects.toThrow(
      UnsupportedWorkerExecutionError,
    );
    await expect(
      runPluginBuild(directory, [[process.execPath, ...command]], logger),
    ).rejects.toThrow(UnsupportedWorkerExecutionError);
    expect(existsSync(marker)).toBe(false);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("default mode preserves ordinary explicitly configured child execution", async () => {
  vi.stubEnv("LOOM_WORKER_ISOLATION", "");
  const result = await execCommand(process.execPath, [
    "-e",
    "process.stdout.write('legacy-default')",
  ]);
  expect(result.stdout).toBe("legacy-default");
});
