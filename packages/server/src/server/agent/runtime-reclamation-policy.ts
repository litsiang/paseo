import { lstatSync, readFileSync, realpathSync } from "node:fs";
import { join, resolve } from "node:path";

interface RuntimeReclamationPolicy {
  schemaVersion: 1;
  workerAgentIds: string[];
  protectedAgentIds: string[];
}

const agentId = (value: unknown): value is string =>
  typeof value === "string" &&
  /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(value);

// Eligibility is host-owned. Editable agent labels and titles never grant it.
export function runtimeReclamationProtection(paseoHome: string, id: string): string | null {
  try {
    const path = join(paseoHome, "runtime-reclamation.json");
    const stat = lstatSync(path);
    if (
      !stat.isFile() ||
      stat.isSymbolicLink() ||
      stat.size > 65536 ||
      (stat.mode & 0o022) !== 0 ||
      (process.getuid && stat.uid !== process.getuid()) ||
      realpathSync(path) !== resolve(path)
    )
      return "policy_unavailable";
    const policy: RuntimeReclamationPolicy = JSON.parse(readFileSync(path, "utf8"));
    if (
      policy?.schemaVersion !== 1 ||
      !Array.isArray(policy.workerAgentIds) ||
      !Array.isArray(policy.protectedAgentIds) ||
      policy.workerAgentIds.length > 256 ||
      policy.protectedAgentIds.length > 256 ||
      ![...policy.workerAgentIds, ...policy.protectedAgentIds].every(agentId)
    )
      return "policy_unavailable";
    if (policy.protectedAgentIds.includes(id)) return "protected_agent";
    return policy.workerAgentIds.includes(id) ? null : "unregistered_worker";
  } catch {
    return "policy_unavailable";
  }
}
