import { createHash, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open, rename, unlink, link, type FileHandle } from "node:fs/promises";
import { request } from "node:http";
import path from "node:path";
import { z } from "zod";

const MAX_BYTES = 16384;
const Identifier = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}$/);
const RunTarget = z.strictObject({ kind: z.literal("run"), runId: Identifier });
const IssueTarget = z.strictObject({
  kind: z.literal("issue"),
  repository: Identifier,
  number: z.number().int().positive(),
});
const RequestTarget = z.strictObject({ kind: z.literal("request"), requestId: Identifier });
const Target = z.discriminatedUnion("kind", [RunTarget, IssueTarget, RequestTarget]);
const Command = z.discriminatedUnion("operation", [
  z.strictObject({
    operation: z.literal("query"),
    target: Target,
    payload: z.strictObject({ view: z.literal("status") }),
  }),
  z.strictObject({
    operation: z.literal("demand"),
    target: IssueTarget,
    payload: z.strictObject({
      text: z.string().refine((text) => text.trim().length > 0 && Buffer.byteLength(text) <= 8192),
    }),
  }),
  z.strictObject({
    operation: z.enum(["pause", "cancel"]),
    target: RunTarget,
    payload: z.strictObject({}),
  }),
]);
const Envelope = z.strictObject({
  version: z.literal(1),
  operationId: z.string().uuid(),
  operation: z.enum(["query", "demand", "pause", "cancel"]),
  project: Identifier,
  target: Target,
  payload: z.record(z.string(), z.unknown()),
  createdAt: z.number().int(),
  expiresAt: z.number().int(),
});
const Receipt = z.strictObject({
  version: z.literal(1),
  operationId: z.string().uuid(),
  operation: z.enum(["query", "demand", "pause", "cancel"]),
  project: Identifier,
  target: Target,
  status: z.enum(["completed", "accepted", "pending", "rejected"]),
  result: z.record(z.string(), z.unknown()),
  replayed: z.boolean(),
  error: z.strictObject({ code: z.string().max(128), message: z.string().max(512) }).optional(),
});
const Journal = z.strictObject({
  fingerprint: z.string(),
  envelope: Envelope,
  receipt: Receipt.nullable(),
});
const Config = z.strictObject({
  version: z.literal(1),
  project: Identifier,
  repository: Identifier,
  consoleIds: z.array(z.string().uuid()).min(1),
  socketPath: z.string().min(1),
  backendUid: z.number().int().nonnegative(),
  tokenFile: z.string().min(1),
  journalDirectory: z.string().min(1),
});
type Command = z.infer<typeof Command>;
type Envelope = z.infer<typeof Envelope>;
type Receipt = z.infer<typeof Receipt>;
type Journal = z.infer<typeof Journal>;
type Config = z.infer<typeof Config>;

export type OwnerControlOrigin =
  | { kind: "authenticated-owner"; principalId: "owner" }
  | { kind: "untrusted" };
interface OwnerControlInput {
  origin: OwnerControlOrigin;
  consoleId: string;
  messageId: string | undefined;
  text: string;
}
interface LoadOwnerControlInput {
  agentIsolationEnabled: boolean;
  configPath: string | undefined;
  auth: { password?: string } | undefined;
}

export class OwnerControlError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "OwnerControlError";
  }
}

export function isOwnerControlCommand(text: string): boolean {
  return /^\s*\/loom(?:\s|$)/u.test(text);
}

function parseCommand(text: string): Command {
  if (Buffer.byteLength(text) > MAX_BYTES)
    throw new OwnerControlError("invalid_command", "Owner command is too large");
  const match = /^\/loom (query|demand|pause|cancel) (\{[^]*\})$/u.exec(text.trim());
  if (!match)
    throw new OwnerControlError(
      "invalid_command",
      "Use /loom <query|demand|pause|cancel> followed by a JSON object containing target and payload",
    );
  let body: unknown;
  try {
    body = JSON.parse(match[2]);
  } catch {
    throw new OwnerControlError("invalid_command", "Invalid owner command JSON");
  }
  const fields = z.strictObject({ target: z.unknown(), payload: z.unknown() }).safeParse(body);
  if (!fields.success)
    throw new OwnerControlError("invalid_command", "Owner command accepts only target and payload");
  const command = Command.safeParse({ operation: match[1], ...fields.data });
  if (!command.success)
    throw new OwnerControlError("invalid_command", "Owner command target or payload is invalid");
  return command.data;
}

interface ProtectedParentInput {
  file: string;
  trustedUids: readonly number[];
}

async function withProtectedParent<T>(
  input: ProtectedParentInput,
  action: (file: string, directory: FileHandle) => Promise<T>,
): Promise<T> {
  if (
    process.platform !== "linux" ||
    !path.isAbsolute(input.file) ||
    path.normalize(input.file) !== input.file
  ) {
    throw new OwnerControlError(
      "unsafe_configuration",
      "Owner control requires protected Linux absolute paths",
    );
  }
  const flags = constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW;
  let directory = await open("/", flags);
  let current = "/";
  try {
    const root = await directory.stat();
    if (root.uid !== 0 || (root.mode & 0o022) !== 0) {
      throw new OwnerControlError(
        "unsafe_configuration",
        "Owner control requires an administrative filesystem root",
      );
    }
    for (const component of path.dirname(input.file).split("/").filter(Boolean)) {
      const next = await open(`/proc/self/fd/${directory.fd}/${component}`, flags);
      await directory.close();
      directory = next;
      current = path.join(current, component);
      const info = await directory.stat();
      const trusted = input.trustedUids.includes(info.uid);
      // The kernel sticky rule prevents another UID from replacing the next
      // owner-owned component. All following directories remain FD-anchored.
      const stickyTemporaryRoot =
        current === "/tmp" && info.uid === 0 && (info.mode & 0o1000) !== 0;
      if (!trusted || ((info.mode & 0o022) !== 0 && !stickyTemporaryRoot)) {
        throw new OwnerControlError("unsafe_configuration", "Owner control path is not protected");
      }
    }
    return await action(`/proc/self/fd/${directory.fd}/${path.basename(input.file)}`, directory);
  } finally {
    await directory.close();
  }
}

async function readProtectedFile(file: string, maxBytes = MAX_BYTES): Promise<string> {
  const ownerUid = process.geteuid?.();
  if (ownerUid === undefined)
    throw new OwnerControlError(
      "unsupported_host",
      "Owner controls require Unix identity separation",
    );
  return withProtectedParent({ file, trustedUids: [0, ownerUid] }, async (anchoredFile) => {
    const handle = await open(anchoredFile, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const info = await handle.stat();
      if (
        !info.isFile() ||
        ![0, ownerUid].includes(info.uid) ||
        (info.mode & 0o077) !== 0 ||
        info.size > maxBytes
      ) {
        throw new OwnerControlError("unsafe_configuration", "Owner control file is not protected");
      }
      return await handle.readFile("utf8");
    } finally {
      await handle.close();
    }
  });
}

interface JournalWriteInput {
  file: string;
  journal: Journal;
  createOnly: boolean;
}

async function writeJournal(input: JournalWriteInput): Promise<void> {
  const { file, journal, createOnly } = input;
  await withProtectedParent(
    { file, trustedUids: [0, process.geteuid?.() ?? -1] },
    async (anchoredFile, directory) => {
      const temporary = `${anchoredFile}.${randomUUID()}.tmp`;
      const handle = await open(temporary, "wx", 0o600);
      try {
        await handle.writeFile(JSON.stringify(journal));
        await handle.sync();
      } finally {
        await handle.close();
      }
      try {
        if (createOnly) {
          await link(temporary, anchoredFile);
          await unlink(temporary);
        } else {
          await rename(temporary, anchoredFile);
        }
      } catch (error) {
        await unlink(temporary);
        throw error;
      }
      await directory.sync();
    },
  );
}

function postOperation(config: Config, token: string, envelope: Envelope): Promise<Receipt> {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify(envelope);
    if (Buffer.byteLength(body) > MAX_BYTES) {
      reject(new OwnerControlError("invalid_command", "Owner command is too large"));
      return;
    }
    const connection = request(
      {
        socketPath: config.socketPath,
        agent: false,
        path: "/v1/operations",
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(body),
        },
      },
      (response) => {
        const chunks: Buffer[] = [];
        let size = 0;
        response.on("data", (chunk: Buffer) => {
          size += chunk.length;
          if (size > MAX_BYTES)
            connection.destroy(
              new OwnerControlError("invalid_receipt", "Owner control response is too large"),
            );
          else chunks.push(chunk);
        });
        response.on("end", () => {
          if (response.statusCode !== 200) {
            reject(
              new OwnerControlError(
                "backend_rejected",
                "Owner control backend rejected the request; retry the same message to retrieve its receipt",
              ),
            );
            return;
          }
          let parsed: unknown;
          try {
            parsed = JSON.parse(Buffer.concat(chunks).toString("utf8"));
          } catch {
            reject(new OwnerControlError("invalid_receipt", "Invalid owner control response"));
            return;
          }
          const receipt = Receipt.safeParse(parsed);
          if (!receipt.success) {
            reject(new OwnerControlError("invalid_receipt", "Invalid owner control response"));
            return;
          }
          const exactBinding =
            receipt.data.operationId === envelope.operationId &&
            receipt.data.operation === envelope.operation &&
            receipt.data.project === envelope.project &&
            JSON.stringify(receipt.data.target) === JSON.stringify(envelope.target);
          if (!exactBinding) {
            reject(
              new OwnerControlError("invalid_receipt", "Owner control response binding mismatch"),
            );
            return;
          }
          resolve(receipt.data);
        });
        response.on("error", () =>
          reject(
            new OwnerControlError(
              "outcome_unknown",
              "Owner control outcome is unknown; retry the same message",
            ),
          ),
        );
      },
    );
    connection.setTimeout(5000, () => connection.destroy());
    connection.on("error", () =>
      reject(
        new OwnerControlError(
          "outcome_unknown",
          "Owner control outcome is unknown; retry the same message",
        ),
      ),
    );
    connection.end(body);
  });
}

export class OwnerControlBridge {
  private readonly pending = new Map<string, Promise<Receipt>>();
  constructor(
    private readonly config: Config,
    private readonly token: string,
  ) {}

  async execute(input: OwnerControlInput): Promise<Receipt> {
    if (input.origin.kind !== "authenticated-owner" || input.origin.principalId !== "owner") {
      return Promise.reject(
        new OwnerControlError("owner_required", "Authenticated owner transport is required"),
      );
    }
    if (!this.config.consoleIds.includes(input.consoleId))
      return Promise.reject(
        new OwnerControlError("console_not_registered", "Owner console is not registered"),
      );
    if (!input.messageId || input.messageId.length > 256)
      return Promise.reject(
        new OwnerControlError("message_id_required", "Owner command requires a stable message ID"),
      );
    const command = parseCommand(input.text);
    if (command.target.kind === "issue" && command.target.repository !== this.config.repository) {
      return Promise.reject(
        new OwnerControlError(
          "target_not_registered",
          "Owner command target is outside the registered project",
        ),
      );
    }
    const key = createHash("sha256")
      .update(
        JSON.stringify([
          input.origin.principalId,
          this.config.project,
          input.consoleId,
          input.messageId,
        ]),
      )
      .digest("hex");
    const previous = this.pending.get(key) ?? Promise.resolve();
    const result = previous.catch(() => undefined).then(() => this.executeOnce(key, command));
    this.pending.set(key, result);
    void result
      .finally(() => {
        if (this.pending.get(key) === result) this.pending.delete(key);
      })
      .catch(() => undefined);
    return result;
  }

  private async executeOnce(key: string, command: Command): Promise<Receipt> {
    const file = path.join(this.config.journalDirectory, `${key}.json`);
    const fingerprint = createHash("sha256").update(JSON.stringify(command)).digest("hex");
    let journal: Journal;
    try {
      journal = Journal.parse(JSON.parse(await readProtectedFile(file, MAX_BYTES * 3)));
    } catch (error) {
      if (!(error instanceof Error && "code" in error && error.code === "ENOENT")) throw error;
      const createdAt = Date.now();
      journal = {
        fingerprint,
        envelope: {
          version: 1,
          operationId: randomUUID(),
          project: this.config.project,
          ...command,
          createdAt,
          expiresAt: createdAt + 60000,
        },
        receipt: null,
      };
      try {
        await writeJournal({ file, journal, createOnly: true });
      } catch (creationError) {
        if (
          !(
            creationError instanceof Error &&
            "code" in creationError &&
            creationError.code === "EEXIST"
          )
        )
          throw creationError;
        journal = Journal.parse(JSON.parse(await readProtectedFile(file, MAX_BYTES * 3)));
      }
    }
    if (journal.fingerprint !== fingerprint)
      throw new OwnerControlError(
        "message_conflict",
        "Owner message ID was already used for different content",
      );
    if (journal.receipt) return { ...journal.receipt, replayed: true };
    const ownerUid = process.geteuid?.();
    if (ownerUid === undefined)
      throw new OwnerControlError(
        "unsupported_host",
        "Owner controls require Unix identity separation",
      );
    const receipt = await withProtectedParent(
      {
        file: this.config.socketPath,
        trustedUids: [0, ownerUid, this.config.backendUid],
      },
      async (anchoredSocket) => {
        const socket = await lstat(anchoredSocket);
        if (
          !socket.isSocket() ||
          socket.uid !== this.config.backendUid ||
          (socket.mode & 0o007) !== 0
        ) {
          throw new OwnerControlError(
            "unsafe_configuration",
            "Owner control socket is not protected",
          );
        }
        return postOperation(
          { ...this.config, socketPath: anchoredSocket },
          this.token,
          journal.envelope,
        );
      },
    );
    await writeJournal({ file, journal: { ...journal, receipt }, createOnly: false });
    return receipt;
  }
}

export async function loadOwnerControlBridge(
  input: LoadOwnerControlInput,
): Promise<OwnerControlBridge | null> {
  if (!input.configPath) return null;
  if (!input.agentIsolationEnabled) {
    throw new OwnerControlError(
      "agent_isolation_required",
      "Owner controls require the agent isolation candidate",
    );
  }
  if (!input.auth?.password)
    throw new OwnerControlError(
      "owner_required",
      "Owner controls require configured owner password authentication",
    );
  try {
    const config = Config.parse(JSON.parse(await readProtectedFile(input.configPath)));
    const token = (await readProtectedFile(config.tokenFile)).trim();
    if (!/^[A-Za-z0-9_-]{32,256}$/u.test(token))
      throw new OwnerControlError(
        "unsafe_configuration",
        "Invalid owner control credential configuration",
      );
    await withProtectedParent(
      {
        file: path.join(config.journalDirectory, "receipt"),
        trustedUids: [0, process.geteuid?.() ?? -1],
      },
      async (_file, directory) => {
        const journal = await directory.stat();
        if (journal.uid !== process.geteuid?.() || (journal.mode & 0o077) !== 0) {
          throw new OwnerControlError(
            "unsafe_configuration",
            "Owner control journal is not protected",
          );
        }
      },
    );
    return new OwnerControlBridge(config, token);
  } catch {
    throw new OwnerControlError(
      "unsafe_configuration",
      "Owner control configuration cannot be loaded safely",
    );
  }
}
