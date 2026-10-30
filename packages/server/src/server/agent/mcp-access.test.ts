import { describe, expect, test } from "vitest";
import {
  AgentMcpAccess,
  createAgentMcpAccessCandidate,
  isAgentObservationTool,
} from "./mcp-access.js";

const password = "$2b$12$OLxyuuP9uLK30Uzc4wQX0O6liuU/Q1t5P2b0Ebf36mULvpVK3DRZW";

describe("agent MCP principals", () => {
  test("keeps the candidate disabled by default and requires owner auth before activation", () => {
    expect(createAgentMcpAccessCandidate({ enabled: false, password: undefined })).toBeNull();
    expect(() => createAgentMcpAccessCandidate({ enabled: true, password: undefined })).toThrow(
      "requires configured owner authentication",
    );
    expect(createAgentMcpAccessCandidate({ enabled: true, password })).toBeInstanceOf(
      AgentMcpAccess,
    );
  });
  test("binds identity to the issued token even when the query is omitted", async () => {
    const access = new AgentMcpAccess();
    const token = access.issue("agent-a");
    const input = { password, authorizationHeader: `Bearer ${token}`, callerAgentId: undefined };
    expect(await access.authenticate(input)).toEqual({ kind: "agent", agentId: "agent-a" });
    expect(await access.authenticate({ ...input, callerAgentId: "agent-a" })).toEqual({
      kind: "agent",
      agentId: "agent-a",
    });
    expect(await access.authenticate({ ...input, callerAgentId: "agent-b" })).toBeNull();
    expect(
      await access.authenticate({ ...input, callerAgentId: ["agent-a", "agent-b"] }),
    ).toBeNull();
  });

  test("rejects missing, unknown, rotated and revoked capabilities", async () => {
    const access = new AgentMcpAccess();
    const previous = access.issue("agent-a");
    const current = access.issue("agent-a");
    const input = { password, callerAgentId: undefined, authorizationHeader: undefined };
    expect(await access.authenticate(input)).toBeNull();
    expect(
      await access.authenticate({ ...input, authorizationHeader: "Bearer unknown" }),
    ).toBeNull();
    expect(
      await access.authenticate({ ...input, authorizationHeader: `Bearer ${previous}` }),
    ).toBeNull();
    expect(
      await access.authenticate({ ...input, authorizationHeader: `Bearer ${current}` }),
    ).toEqual({
      kind: "agent",
      agentId: "agent-a",
    });
    expect(
      await new AgentMcpAccess().authenticate({
        ...input,
        authorizationHeader: `Bearer ${current}`,
      }),
    ).toBeNull();
    access.revoke("agent-a");
    expect(
      await access.authenticate({ ...input, authorizationHeader: `Bearer ${current}` }),
    ).toBeNull();
  });

  test("keeps owner credentials distinct and fails closed without owner authentication", async () => {
    const access = new AgentMcpAccess();
    const input = {
      password,
      callerAgentId: undefined,
      authorizationHeader: "Bearer correct-password",
    };
    expect(await access.authenticate(input)).toEqual({ kind: "owner" });
    expect(await access.authenticate({ ...input, callerAgentId: "agent-a" })).toBeNull();
    expect(await access.authenticate({ ...input, password: "" })).toBeNull();
    expect(await access.authenticate({ ...input, authorizationHeader: "Bearer wrong" })).toBeNull();
  });

  test("allows only reviewed observation tools, including for future names", () => {
    expect(isAgentObservationTool("list_agents")).toBe(true);
    expect(isAgentObservationTool("get_agent_status")).toBe(true);
    for (const name of [
      "create_terminal",
      "send_terminal_keys",
      "respond_to_permission",
      "send_agent_prompt",
      "start_workspace_script",
      "update_agent",
      "create_schedule",
      "future_tool",
    ]) {
      expect(isAgentObservationTool(name)).toBe(false);
    }
  });
});
