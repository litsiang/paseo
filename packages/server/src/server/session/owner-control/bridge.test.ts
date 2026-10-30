import { randomUUID } from "node:crypto";
import { chmod, readFile, readdir, symlink } from "node:fs/promises";
import path from "node:path";
import { afterEach, expect, test } from "vitest";
import { createExternalProcessEnv, buildSelfNodeCommand } from "../../paseo-env.js";
import { loadOwnerControlBridge } from "./bridge.js";
import { createOwnerControlFixture } from "./test-utils/fixture.js";
const cleanup: Array<() => Promise<void>> = [];
afterEach(async () => {
  for (const close of cleanup.splice(0).toReversed()) await close();
});
async function fixture() {
  const created = await createOwnerControlFixture();
  cleanup.push(created.close);
  return created;
}

test("defaults off and refuses enabled configuration without owner authentication", async () => {
  expect(
    await loadOwnerControlBridge({
      agentIsolationEnabled: true,
      configPath: undefined,
      auth: undefined,
    }),
  ).toBeNull();
  await expect(
    loadOwnerControlBridge({
      agentIsolationEnabled: true,
      configPath: "/missing",
      auth: undefined,
    }),
  ).rejects.toThrow("configured owner password");
});

test("uses a dedicated Unix bearer and returns durable idempotent exact operation receipts", async () => {
  const f = await fixture();
  const [first, concurrent] = await Promise.all([
    f.bridge.execute(f.input),
    f.bridge.execute(f.input),
  ]);
  expect(first.status).toBe("completed");
  expect(concurrent.operationId).toBe(first.operationId);
  expect(concurrent.replayed).toBe(true);
  expect(f.requests).toHaveLength(1);
  expect(f.requests[0]).not.toHaveProperty("principal");
  expect(f.requests[0].operationId).toBe(first.operationId);
  const rebuilt = await loadOwnerControlBridge({
    agentIsolationEnabled: true,
    configPath: f.configPath,
    auth: { password: "fixture-hash" },
  });
  if (!rebuilt) throw new Error("Expected bridge");
  expect(await rebuilt.execute(f.input)).toEqual({ ...first, replayed: true });
  expect(f.requests).toHaveLength(1);
  await expect(
    rebuilt.execute({ ...f.input, text: f.input.text.replace("existing-run", "changed-run") }),
  ).rejects.toThrow("different content");
});

test("retries an unknown network result with the persisted same envelope", async () => {
  const f = await fixture();
  f.disconnectNext();
  await expect(f.bridge.execute(f.input)).rejects.toThrow("outcome is unknown");
  const previous = f.requests[0];
  const rebuilt = await loadOwnerControlBridge({
    agentIsolationEnabled: true,
    configPath: f.configPath,
    auth: { password: "fixture-hash" },
  });
  if (!rebuilt) throw new Error("Expected bridge");
  await rebuilt.execute(f.input);
  expect(f.requests).toHaveLength(2);
  expect(f.requests[1]).toEqual(previous);
  expect((await readdir(f.journalDirectory)).filter((file) => file.endsWith(".json"))).toHaveLength(
    1,
  );
});

test("rejects non-owner origins, unknown consoles, malformed scopes and authority claims before dispatch", async () => {
  const f = await fixture();
  await expect(f.bridge.execute({ ...f.input, origin: { kind: "untrusted" } })).rejects.toThrow(
    "Authenticated owner",
  );
  await expect(f.bridge.execute({ ...f.input, consoleId: randomUUID() })).rejects.toThrow(
    "not registered",
  );
  await expect(f.bridge.execute({ ...f.input, messageId: undefined })).rejects.toThrow(
    "stable message ID",
  );
  const invalid = [
    '/loom query {"principal":"owner","target":{"kind":"run","runId":"r"},"payload":{"view":"status"}}',
    '/loom cancel {"target":{"kind":"issue","repository":"litsiang/Loom","number":93},"payload":{}}',
    '/loom demand {"target":{"kind":"issue","repository":"other/repo","number":93},"payload":{"text":"implement"}}',
    '/loom query {"target":{"kind":"run","runId":"r"},"payload":{"view":"status","shell":"id"}}',
    "/loom pause no-json",
  ];
  for (const text of invalid)
    await expect(f.bridge.execute({ ...f.input, text })).rejects.toThrow();
  expect(f.requests).toHaveLength(0);
});

test("rejects readable credentials, symlinked configuration and worker-writable parents", async () => {
  const f = await fixture();
  await chmod(f.tokenFile, 0o644);
  await expect(
    loadOwnerControlBridge({
      agentIsolationEnabled: true,
      configPath: f.configPath,
      auth: { password: "fixture" },
    }),
  ).rejects.toThrow("loaded safely");
  await chmod(f.tokenFile, 0o600);
  const link = path.join(f.directory, "linked-config");
  await symlink(f.configPath, link);
  await expect(
    loadOwnerControlBridge({
      agentIsolationEnabled: true,
      configPath: link,
      auth: { password: "fixture" },
    }),
  ).rejects.toThrow("loaded safely");
  await chmod(f.directory, 0o777);
  await expect(
    loadOwnerControlBridge({
      agentIsolationEnabled: true,
      configPath: f.configPath,
      auth: { password: "fixture" },
    }),
  ).rejects.toThrow("loaded safely");
  await chmod(f.directory, 0o700);
  expect((await readFile(f.configPath, "utf8")).includes(f.tokenFile)).toBe(true);
});

test("never exports protected bridge configuration through model command environment", () => {
  expect(
    createExternalProcessEnv({ PASEO_OWNER_CONTROL_CONFIG: "/protected/config", PATH: "/bin" }),
  ).toEqual({ PATH: "/bin" });
  expect(
    buildSelfNodeCommand([], { PASEO_OWNER_CONTROL_CONFIG: "/protected/config" }).env,
  ).not.toHaveProperty("PASEO_OWNER_CONTROL_CONFIG");
});

test("sends only the fixed project and exact supported operation payloads, preserving demand text", async () => {
  const f = await fixture();
  const commands = [
    '/loom pause {"target":{"kind":"run","runId":"existing-run"},"payload":{}}',
    '/loom cancel {"target":{"kind":"run","runId":"existing-run"},"payload":{}}',
    '/loom demand {"target":{"kind":"issue","repository":"litsiang/Loom","number":93},"payload":{"text":"  original demand  "}}',
    '/loom query {"target":{"kind":"request","requestId":"existing-request"},"payload":{"view":"status"}}',
  ];
  for (const text of commands)
    await f.bridge.execute({ ...f.input, messageId: randomUUID(), text });
  expect(f.requests.map((request) => request.operation)).toEqual([
    "pause",
    "cancel",
    "demand",
    "query",
  ]);
  expect(f.requests.map((request) => request.project)).toEqual(Array(4).fill("litsiang/Loom"));
  expect(f.requests[2].payload).toEqual({ text: "  original demand  " });
});

test("rejects mismatched backend receipts and unprotected sockets without changing operation identity", async () => {
  const f = await fixture();
  f.wrongTargetNext();
  await expect(f.bridge.execute(f.input)).rejects.toThrow("binding mismatch");
  await f.bridge.execute(f.input);
  expect(f.requests[1]).toEqual(f.requests[0]);
  const next = { ...f.input, messageId: randomUUID() };
  await chmod(f.config.socketPath, 0o666);
  await expect(f.bridge.execute(next)).rejects.toThrow("socket is not protected");
  expect(f.requests).toHaveLength(2);
});

test("concurrent bridge instances preserve one operation ID before any backend retry", async () => {
  const f = await fixture();
  const second = await loadOwnerControlBridge({
    agentIsolationEnabled: true,
    configPath: f.configPath,
    auth: { password: "fixture" },
  });
  if (!second) throw new Error("Expected bridge");
  const receipts = await Promise.all([f.bridge.execute(f.input), second.execute(f.input)]);
  expect(receipts[0].operationId).toBe(receipts[1].operationId);
  expect(new Set(f.requests.map((request) => request.operationId)).size).toBe(1);
});

test("configured owner bridge fails closed unless agent MCP isolation is enabled", async () => {
  const f = await fixture();
  await expect(
    loadOwnerControlBridge({
      configPath: f.configPath,
      auth: { password: "fixture" },
      agentIsolationEnabled: false,
    }),
  ).rejects.toThrow("require the agent isolation candidate");
  expect(
    await loadOwnerControlBridge({
      configPath: undefined,
      auth: undefined,
      agentIsolationEnabled: false,
    }),
  ).toBeNull();
});
