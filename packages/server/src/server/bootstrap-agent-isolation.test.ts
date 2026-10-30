import { afterEach, describe, expect, test, vi } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type {
  AgentClient,
  AgentLaunchContext,
  AgentSessionConfig,
} from "./agent/agent-sdk-types.js";
import { createTestAgentClients } from "./test-utils/fake-agent-client.js";
import { createTestPaseoDaemon } from "./test-utils/paseo-daemon.js";

const password = "$2b$12$OLxyuuP9uLK30Uzc4wQX0O6liuU/Q1t5P2b0Ebf36mULvpVK3DRZW";
interface CapturedLaunch {
  config: AgentSessionConfig;
  context: AgentLaunchContext | undefined;
}

afterEach(() => vi.unstubAllEnvs());

describe("unactivated agent isolation candidate", () => {
  test("authenticates actual MCP requests and restricts HTTP and native catalogs to the caller", async () => {
    vi.stubEnv("PASEO_AGENT_ISOLATION_CANDIDATE", "1");
    const clients = createTestAgentClients({ supportsMcpServers: true });
    const delegate = clients.claude;
    const launches: CapturedLaunch[] = [];
    const client: AgentClient = {
      ...delegate,
      provider: delegate.provider,
      capabilities: { ...delegate.capabilities, supportsNativePaseoTools: true },
      createSession: async (config, context) => {
        launches.push({ config, context });
        return delegate.createSession(config, context);
      },
      resumeSession: delegate.resumeSession.bind(delegate),
      isAvailable: delegate.isAvailable.bind(delegate),
      fetchCatalog: delegate.fetchCatalog.bind(delegate),
    };
    const remoteLaunches: CapturedLaunch[] = [];
    const remoteDelegate = clients.codex;
    const remoteClient: AgentClient = {
      provider: remoteDelegate.provider,
      capabilities: remoteDelegate.capabilities,
      createSession: async (config, context) => {
        remoteLaunches.push({ config, context });
        const session = await remoteDelegate.createSession(config, context);
        session.getRuntimeProcessIdleState = () => "idle";
        session.getRuntimeIdleState = async () => "idle";
        return session;
      },
      resumeSession: async (persistence, overrides, context, options) => {
        remoteLaunches.push({ config: { ...remoteLaunches[0].config, ...overrides }, context });
        return remoteDelegate.resumeSession(persistence, overrides, context, options);
      },
      isAvailable: remoteDelegate.isAvailable.bind(remoteDelegate),
      fetchCatalog: remoteDelegate.fetchCatalog.bind(remoteDelegate),
    };
    const handle = await createTestPaseoDaemon({
      auth: { password },
      mcpEnabled: true,
      agentClients: { ...clients, claude: client, codex: remoteClient },
    });
    const connections: Client[] = [];
    async function connect(authorization: string, query = ""): Promise<Client> {
      const connection = new Client({ name: "isolation-test", version: "1" });
      connections.push(connection);
      await connection.connect(
        new StreamableHTTPClientTransport(
          new URL(`http://127.0.0.1:${handle.port}/mcp/agents${query}`),
          { requestInit: { headers: { Authorization: authorization } } },
        ),
      );
      return connection;
    }
    try {
      const agent = await handle.daemon.agentManager.createAgent(
        { provider: "claude", cwd: handle.paseoHome },
        undefined,
        { workspaceId: undefined },
      );
      const native = launches[0]?.context?.paseoTools;
      if (!native) throw new Error("Expected server-bound native catalog");
      expect([...native.tools.keys()].sort()).toEqual(["get_agent_status", "list_agents"]);
      await expect(native.executeTool("create_terminal", {})).rejects.toThrow(
        "Paseo tool not found",
      );
      await expect(
        native.executeTool("get_agent_status", { agentId: "another-agent" }),
      ).rejects.toThrow("cannot observe another agent");

      // Native providers strip the redundant HTTP config. A second provider
      // exercises the actual injected transport with the same server policy.
      const remoteAgent = await handle.daemon.agentManager.createAgent(
        { provider: "codex", cwd: handle.paseoHome },
        undefined,
        { workspaceId: undefined },
      );
      const tokenConfig = remoteLaunches[0]?.config.mcpServers?.paseo;
      if (!tokenConfig || tokenConfig.type !== "http" || !tokenConfig.headers?.Authorization) {
        throw new Error("Expected per-agent injected MCP credential");
      }
      const authorization = tokenConfig.headers.Authorization;
      const remote = await connect(authorization);
      const tools = await remote.listTools();
      expect(tools.tools.map((tool) => tool.name).sort()).toEqual([
        "get_agent_status",
        "list_agents",
      ]);
      const own = await remote.callTool({
        name: "get_agent_status",
        arguments: { agentId: remoteAgent.id },
      });
      expect(own.isError).not.toBe(true);
      const other = await remote.callTool({
        name: "get_agent_status",
        arguments: { agentId: agent.id },
      });
      expect(other.isError).toBe(true);
      const denied = await remote.callTool({ name: "create_terminal", arguments: {} });
      expect(denied.isError).toBe(true);
      const list = await remote.callTool({ name: "list_agents", arguments: {} });
      expect(list.structuredContent).toMatchObject({ agents: [{ id: remoteAgent.id }] });
      expect(JSON.stringify(list.structuredContent)).not.toContain(agent.id);
      await expect(connect(authorization, `?callerAgentId=${agent.id}`)).rejects.toThrow();
      const legacy = handle.daemon.agentManager.getMcpAuthToken();
      await expect(connect(`Bearer ${legacy}`)).rejects.toThrow();
      const unauthenticated = await fetch(`http://127.0.0.1:${handle.port}/mcp/agents`);
      expect(unauthenticated.status).toBe(401);
      const owner = await connect("Bearer correct-password");
      expect((await owner.listTools()).tools.some((tool) => tool.name === "create_terminal")).toBe(
        true,
      );
      const persistence = remoteAgent.persistence;
      if (!persistence) throw new Error("Expected a resumable test provider");
      expect(
        await handle.daemon.agentManager.unloadAgentIfIdle({
          agentId: remoteAgent.id,
          expectedUpdatedAt: remoteAgent.updatedAt.toISOString(),
          expectedRuntimeGeneration: remoteAgent.runtimeGeneration ?? "",
          idleForMs: 0,
          protection: () => null,
        }),
      ).toMatchObject({ status: "unloaded", agentId: remoteAgent.id });
      const resumed = await handle.daemon.agentManager.resumeAgentFromPersistence(
        persistence,
        remoteAgent.config,
        remoteAgent.id,
      );
      expect(resumed.id).toBe(remoteAgent.id);
      const resumedTokenConfig = remoteLaunches[1]?.config.mcpServers?.paseo;
      if (
        !resumedTokenConfig ||
        resumedTokenConfig.type !== "http" ||
        !resumedTokenConfig.headers?.Authorization
      ) {
        throw new Error("Expected replacement MCP credential after idle resume");
      }
      const resumedAuthorization = resumedTokenConfig.headers.Authorization;
      expect(resumedAuthorization).not.toBe(authorization);
      await expect(connect(authorization)).rejects.toThrow();
      const resumedConnection = await connect(resumedAuthorization);
      expect((await resumedConnection.listTools()).tools.map((tool) => tool.name).sort()).toEqual([
        "get_agent_status",
        "list_agents",
      ]);
      const resumedOther = await resumedConnection.callTool({
        name: "get_agent_status",
        arguments: { agentId: agent.id },
      });
      expect(resumedOther.isError).toBe(true);
      await handle.daemon.agentManager.archiveAgent(remoteAgent.id);
      await expect(connect(resumedAuthorization)).rejects.toThrow();
    } finally {
      await Promise.allSettled(connections.map((connection) => connection.close()));
      await handle.close();
    }
  }, 60_000);
});
