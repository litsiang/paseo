import { randomUUID } from "node:crypto";
import { createServer } from "node:http";
import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { z } from "zod";
import { loadOwnerControlBridge } from "../bridge.js";
export async function createOwnerControlFixture() {
  const cleanup: Array<() => Promise<void>> = [];
  const directory = await mkdtemp(path.join("/tmp", "owner-control-"));
  cleanup.push(() => rm(directory, { recursive: true, force: true }));
  const socketPath = path.join(directory, "backend.sock");
  const tokenFile = path.join(directory, "token");
  const configPath = path.join(directory, "config.json");
  const journalDirectory = path.join(directory, "journal");
  const consoleId = randomUUID();
  const token = "owner_bridge_test_credential_0123456789";
  await writeFile(tokenFile, token, { mode: 0o600 });
  await mkdir(journalDirectory, { mode: 0o700 });
  const uid = process.geteuid?.();
  if (uid === undefined) throw new Error("Unix fixture required");
  const config = {
    version: 1,
    project: "litsiang/Loom",
    repository: "litsiang/Loom",
    consoleIds: [consoleId],
    socketPath,
    backendUid: uid,
    tokenFile,
    journalDirectory,
  };
  await writeFile(configPath, JSON.stringify(config), { mode: 0o600 });
  const requests: Array<Record<string, unknown>> = [];
  let disconnectOnce = false;
  let wrongTargetOnce = false;
  const server = createServer(async (request, response) => {
    if (request.url !== "/v1/operations" || request.headers.authorization !== `Bearer ${token}`) {
      response.writeHead(401).end();
      return;
    }
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(Buffer.from(chunk));
    const body = z
      .record(z.string(), z.unknown())
      .parse(JSON.parse(Buffer.concat(chunks).toString("utf8")));
    requests.push(body);
    if (disconnectOnce) {
      disconnectOnce = false;
      response.destroy();
      return;
    }
    response.setHeader("Content-Type", "application/json");
    response.end(
      JSON.stringify({
        version: 1,
        operationId: body.operationId,
        operation: body.operation,
        project: body.project,
        target: wrongTargetOnce ? { kind: "run", runId: "wrong-target" } : body.target,
        status: "completed",
        result: { state: "idle" },
        replayed: false,
      }),
    );
    wrongTargetOnce = false;
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, resolve);
  });
  await chmod(socketPath, 0o600);
  cleanup.push(
    () =>
      new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      ),
  );
  const bridge = await loadOwnerControlBridge({
    agentIsolationEnabled: true,
    configPath,
    auth: { password: "fixture-hash" },
  });
  if (!bridge) throw new Error("Expected enabled bridge");
  const input = {
    origin: { kind: "authenticated-owner", principalId: "owner" } as const,
    consoleId,
    messageId: randomUUID(),
    text: '/loom query {"target":{"kind":"run","runId":"existing-run"},"payload":{"view":"status"}}',
  };
  return {
    directory,
    configPath,
    tokenFile,
    journalDirectory,
    config,
    bridge,
    input,
    requests,
    close: async () => {
      for (const close of cleanup.toReversed()) await close();
    },
    wrongTargetNext: () => {
      wrongTargetOnce = true;
    },
    disconnectNext: () => {
      disconnectOnce = true;
    },
  };
}
