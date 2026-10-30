import { EventEmitter } from "node:events";
import { randomUUID } from "node:crypto";
import { afterEach, expect, test, vi } from "vitest";
import { SessionInboundMessageSchema } from "@getpaseo/protocol/messages";
import { OWNER_PERMISSIONS } from "./authorization/index.js";
import { VoiceAssistantWebSocketServer } from "./websocket-server.js";
import { createOwnerControlFixture } from "./session/owner-control/test-utils/fixture.js";
import { createTestPaseoDaemon } from "./test-utils/paseo-daemon.js";
import { createTestAgentClients } from "./test-utils/fake-agent-client.js";
import { DaemonClient } from "./test-utils/daemon-client.js";
import type { SessionOutboundMessage } from "./messages.js";

const password = "$2b$12$OLxyuuP9uLK30Uzc4wQX0O6liuU/Q1t5P2b0Ebf36mULvpVK3DRZW";
afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

class ExternalSocket extends EventEmitter {
  readyState = 1;
  messages: unknown[] = [];
  send(data: string | Uint8Array | ArrayBuffer, callback?: (error?: Error) => void): void {
    this.messages.push(
      JSON.parse(
        typeof data === "string" ? data : Buffer.from(new Uint8Array(data)).toString("utf8"),
      ),
    );
    callback?.();
  }
  close(): void {
    this.readyState = 3;
    this.emit("close");
  }
}

test("authenticated owner controls emit UI notifications without starting or waking a provider; external owner labels and Hub cannot reuse owner authority", async () => {
  const fixture = await createOwnerControlFixture();
  vi.stubEnv("PASEO_OWNER_CONTROL_CONFIG", fixture.configPath);
  vi.stubEnv("PASEO_AGENT_ISOLATION_CANDIDATE", "1");
  const servers: VoiceAssistantWebSocketServer[] = [];
  const begin = VoiceAssistantWebSocketServer.prototype.beginAcceptingConnections;
  vi.spyOn(VoiceAssistantWebSocketServer.prototype, "beginAcceptingConnections").mockImplementation(
    function (this: VoiceAssistantWebSocketServer) {
      servers.push(this);
      begin.call(this);
    },
  );
  let modelTurns = 0;
  const handle = await createTestPaseoDaemon({
    auth: { password },
    agentClients: createTestAgentClients({
      onStartTurn: () => {
        modelTurns++;
      },
    }),
  });
  const client = new DaemonClient({
    url: `ws://127.0.0.1:${handle.port}/ws`,
    password: "correct-password",
    clientId: "owner-client",
  });
  const messages: SessionOutboundMessage[] = [];
  client.subscribeRawMessages((message) => messages.push(message));
  try {
    const agent = await handle.daemon.agentManager.createAgent(
      { provider: "codex", cwd: fixture.directory },
      fixture.input.consoleId,
      { workspaceId: undefined },
    );
    await handle.daemon.agentManager.closeAgent(agent.id);
    expect(handle.daemon.agentManager.getAgent(agent.id)).toBeNull();
    await client.connect();
    await client.sendAgentMessage(agent.id, fixture.input.text, {
      messageId: fixture.input.messageId,
    });
    expect(fixture.requests).toHaveLength(1);
    const notification = messages.find(
      (message) =>
        message.type === "agent_stream" &&
        message.payload.event.type === "timeline" &&
        message.payload.event.item.type === "notification",
    );
    expect(notification).toMatchObject({
      type: "agent_stream",
      payload: {
        agentId: agent.id,
        event: {
          type: "timeline",
          item: {
            type: "notification",
            level: "info",
            message: expect.stringContaining('"status":"completed"'),
          },
        },
      },
    });
    expect(handle.daemon.agentManager.getAgent(agent.id)).toBeNull();
    expect(modelTurns).toBe(0);
    await client.sendAgentMessage(agent.id, fixture.input.text, {
      messageId: fixture.input.messageId,
    });
    expect(fixture.requests).toHaveLength(1);
    expect(
      messages.filter((message) => message.type === "agent_stream").length,
    ).toBeGreaterThanOrEqual(2);
    const server = servers[0];
    if (!server) throw new Error("Expected actual WebSocket server");
    for (const principalId of ["owner", "hub-service", "agent-service"]) {
      const previous = server.listSessions();
      const external = new ExternalSocket();
      await server.attachExternalSocket(
        external,
        undefined,
        { principalId, permissions: OWNER_PERMISSIONS, authenticatedOwner: true },
        {
          type: "hello",
          clientId: "owner-client",
          clientType: "browser",
          protocolVersion: 1,
        },
      );
      const untrusted = server.listSessions().find((session) => !previous.includes(session));
      if (!untrusted)
        throw new Error("External principal must not reuse a password-authenticated session");
      await untrusted.handleMessage(
        SessionInboundMessageSchema.parse({
          type: "send_agent_message_request",
          requestId: randomUUID(),
          agentId: agent.id,
          text: fixture.input.text,
          messageId: randomUUID(),
          authenticatedOwner: true,
          ownerControlOrigin: { kind: "authenticated-owner", principalId: "owner" },
        }),
      );
      expect(external.messages).toContainEqual(
        expect.objectContaining({
          type: "session",
          message: expect.objectContaining({
            type: "send_agent_message_response",
            payload: expect.objectContaining({
              accepted: false,
              error: "Authenticated owner transport is required",
            }),
          }),
        }),
      );
      external.close();
    }
    expect(fixture.requests).toHaveLength(1);
    expect(modelTurns).toBe(0);
    expect(process.env.PASEO_OWNER_CONTROL_CONFIG).toBeUndefined();
  } finally {
    await client.close();
    await handle.close();
    await fixture.close();
  }
}, 60_000);

test("default unauthenticated owner-labelled UI keeps owner control disabled and never routes reserved commands into a model", async () => {
  let modelTurns = 0;
  const handle = await createTestPaseoDaemon({
    agentClients: createTestAgentClients({
      onStartTurn: () => {
        modelTurns++;
      },
    }),
  });
  const client = new DaemonClient({ url: `ws://127.0.0.1:${handle.port}/ws` });
  try {
    const agent = await handle.daemon.agentManager.createAgent(
      { provider: "codex", cwd: handle.paseoHome },
      undefined,
      { workspaceId: undefined },
    );
    await client.connect();
    await expect(
      client.sendAgentMessage(
        agent.id,
        '/loom query {"target":{"kind":"run","runId":"r"},"payload":{"view":"status"}}',
      ),
    ).rejects.toThrow("Owner controls are disabled");
    expect(modelTurns).toBe(0);
  } finally {
    await client.close();
    await handle.close();
  }
}, 60_000);
