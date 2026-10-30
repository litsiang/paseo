/** No Paseo transport is registered yet. Required mode must not silently execute
 * an unsupported provider, hook, terminal or host tool as the daemon owner. */
export interface WorkerExecutionRequest {
  exit: "provider" | "process" | "terminal" | "workspace-script" | "mcp" | "plugin";
  providerId?: string;
}

export class UnsupportedWorkerExecutionError extends Error {
  readonly code = "worker_execution_unsupported";
  constructor(readonly request: WorkerExecutionRequest) {
    super(
      `Required worker transport is not connected for ${request.exit}${request.providerId ? ` (${request.providerId})` : ""}`,
    );
    this.name = "UnsupportedWorkerExecutionError";
  }
}

export function assertWorkerExecutionSupported(request: WorkerExecutionRequest): void {
  if (process.env.LOOM_WORKER_ISOLATION === "required") {
    throw new UnsupportedWorkerExecutionError(request);
  }
}
