import { test, expect } from "vitest";
import { mkdtempSync, writeFileSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runtimeReclamationProtection } from "./runtime-reclamation-policy.js";

test(
  "host policy protects coordinators and unknown roles; labels cannot authorize unloading",
  { skip: process.platform === "win32" },
  () => {
    const root = mkdtempSync(join(tmpdir(), "paseo-unload-policy-"));
    const worker = "11111111-1111-4111-8111-111111111111";
    const coordinator = "22222222-2222-4222-8222-222222222222";
    try {
      expect(runtimeReclamationProtection(root, worker)).toBe("policy_unavailable");
      writeFileSync(
        join(root, "runtime-reclamation.json"),
        JSON.stringify({
          schemaVersion: 1,
          workerAgentIds: [worker, coordinator],
          protectedAgentIds: [coordinator],
        }),
        { mode: 0o600 },
      );
      expect(runtimeReclamationProtection(root, worker)).toBeNull();
      expect(runtimeReclamationProtection(root, coordinator)).toBe("protected_agent");
      expect(runtimeReclamationProtection(root, "33333333-3333-4333-8333-333333333333")).toBe(
        "unregistered_worker",
      );
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  },
);

test(
  "an untrusted or redirected policy cannot authorize runtime closure",
  { skip: process.platform === "win32" },
  () => {
    const root = mkdtempSync(join(tmpdir(), "paseo-unload-policy-"));
    const worker = "11111111-1111-4111-8111-111111111111";
    try {
      writeFileSync(
        join(root, "source.json"),
        JSON.stringify({ schemaVersion: 1, workerAgentIds: [worker], protectedAgentIds: [] }),
      );
      symlinkSync(join(root, "source.json"), join(root, "runtime-reclamation.json"));
      expect(runtimeReclamationProtection(root, worker)).toBe("policy_unavailable");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  },
);
