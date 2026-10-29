import { randomBytes, timingSafeEqual } from "node:crypto";
import { extractHttpBearerToken, isBearerTokenValidAsync } from "../auth.js";

export type AgentMcpPrincipal = { kind: "owner" } | { kind: "agent"; agentId: string };

interface AgentMcpAuthentication {
  password: string;
  authorizationHeader: string | undefined;
  callerAgentId: unknown;
}

interface AgentMcpCandidateOptions {
  enabled: boolean;
  password: string | undefined;
}

export class AgentMcpOwnerAuthRequiredError extends Error {
  constructor() {
    super("Agent isolation candidate requires configured owner authentication");
    this.name = "AgentMcpOwnerAuthRequiredError";
  }
}

export class AgentMcpScopeError extends Error {
  constructor() {
    super("Agent MCP capability cannot observe another agent");
    this.name = "AgentMcpScopeError";
  }
}

// A positive list also denies future tools until their authority is reviewed.
const AGENT_OBSERVATION_TOOLS = new Set(["list_agents", "get_agent_status"]);

export function isAgentObservationTool(name: string): boolean {
  return AGENT_OBSERVATION_TOOLS.has(name);
}

export class AgentMcpAccess {
  private readonly tokens = new Map<string, string>();

  issue(agentId: string): string {
    const token = randomBytes(32).toString("base64url");
    this.tokens.set(agentId, token);
    return token;
  }

  revoke(agentId: string): void {
    this.tokens.delete(agentId);
  }

  async authenticate(input: AgentMcpAuthentication): Promise<AgentMcpPrincipal | null> {
    const token = extractHttpBearerToken(input.authorizationHeader);
    if (!input.password || token === null) {
      return null;
    }
    const provided = Buffer.from(token);
    for (const [agentId, expectedToken] of this.tokens) {
      const expected = Buffer.from(expectedToken);
      if (provided.length !== expected.length || !timingSafeEqual(provided, expected)) {
        continue;
      }
      // Query parameters may attenuate identity, never select another principal.
      if (input.callerAgentId !== undefined && input.callerAgentId !== agentId) {
        return null;
      }
      return { kind: "agent", agentId };
    }
    const ownerAuthenticated = await isBearerTokenValidAsync({ password: input.password, token });
    if (!ownerAuthenticated || input.callerAgentId !== undefined) {
      return null;
    }
    return { kind: "owner" };
  }
}

export function createAgentMcpAccessCandidate(
  input: AgentMcpCandidateOptions,
): AgentMcpAccess | null {
  if (!input.enabled) return null;
  if (!input.password) throw new AgentMcpOwnerAuthRequiredError();
  return new AgentMcpAccess();
}
