import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";

import { writeFileAtomic } from "./atomic.ts";
import type { McpServerSpec, StdioMcpSpec } from "./contracts.ts";
import { isRemoteMcpServer } from "./mcp-registry.ts";

const CONTRACT_VERSION = 1;
const PENDING_TTL_MS = 5 * 60_000;
const REQUEST_TIMEOUT_MS = 10_000;

interface MartaIdentity { userId: string | number; email: string; name: string; role: string }
interface MartaBinding {
  ombSessionId: string; botId: string; threadId: string; pbxSessionId: string;
  sessionExpiresAt: number; sessionGrant: string; identity: MartaIdentity;
}
interface PendingHandoff {
  ombSessionId: string; botId: string; threadId: string; verifier: string;
  next: string; expiresAt: number;
}
interface MartaFile { version: 1; bindings: MartaBinding[] }
interface Configuration {
  botId: string; mcpServer: string; publicOrigin: string; internalOrigin: string;
  connectPath: string; handoffToken: string;
}

export interface MartaBotPolicy {
  computer?: string; browser?: boolean; composio?: boolean; chiefOfStaff?: boolean;
  approvePeerComms?: boolean; managedSections?: string[]; peers?: string[];
  mcpServers?: string[]; autoApprove?: boolean; alwaysAllow?: string[];
}
export interface MartaTurnOptions {
  automationSource?: unknown; unattended?: boolean; peerAsk?: unknown;
  cardContinuation?: boolean; computerSelectionContinuation?: boolean;
  coordination?: unknown; runOn?: unknown; commsDepth?: number;
}
export interface MartaPbxSessionOptions {
  file: string; env?: NodeJS.ProcessEnv; fetch?: typeof fetch; now?: () => number;
}

function safePath(value: string | undefined, fallback = "/"): string {
  if (!value || !value.startsWith("/") || value.startsWith("//")) return fallback;
  try {
    const parsed = new URL(value, "http://local.invalid");
    return parsed.origin === "http://local.invalid" ? parsed.pathname + parsed.search + parsed.hash : fallback;
  } catch { return fallback; }
}
function origin(value: string | undefined, requireHttps: boolean): string | null {
  if (!value) return null;
  try {
    const parsed = new URL(value);
    if ((requireHttps && parsed.protocol !== "https:") ||
        (!requireHttps && parsed.protocol !== "https:" && parsed.protocol !== "http:") ||
        parsed.username || parsed.password || parsed.pathname !== "/" || parsed.search || parsed.hash) return null;
    return parsed.origin;
  } catch { return null; }
}
function validIdentity(value: unknown): value is MartaIdentity {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const row = value as Record<string, unknown>;
  return (typeof row.userId === "string" || typeof row.userId === "number") &&
    ["email", "name", "role"].every((key) => typeof row[key] === "string");
}
function expiryMs(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value !== "string") return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}
function equalSecret(a: string, b: string): boolean {
  const left = Buffer.from(a), right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

export class MartaPbxSessionManager {
  private readonly file: string;
  private readonly fetchImpl: typeof fetch;
  private readonly now: () => number;
  private readonly config: Configuration | null;
  private readonly targetBotId: string | null;
  private bindings: MartaBinding[] = [];
  private readonly pending = new Map<string, PendingHandoff>();

  constructor(options: MartaPbxSessionOptions) {
    this.file = options.file;
    this.fetchImpl = options.fetch ?? fetch;
    this.now = options.now ?? Date.now;
    const env = options.env ?? process.env;
    const publicOrigin = origin(env.OMB_MARTA_PBX_PUBLIC_URL, true);
    const internalOrigin = origin(env.OMB_MARTA_PBX_INTERNAL_URL, false);
    const botId = env.OMB_MARTA_BOT_ID?.trim() ?? "";
    this.targetBotId = /^[\w-]+$/.test(botId) ? botId : null;
    const mcpServer = env.OMB_MARTA_MCP_SERVER?.trim() || "marta-readonly";
    const handoffToken = env.MARTA_HANDOFF_TOKEN ?? "";
    this.config = publicOrigin && internalOrigin && /^[\w-]+$/.test(botId) &&
      /^[a-z][a-z0-9_-]{0,31}$/.test(mcpServer) && handoffToken.length >= 32
      ? { botId, mcpServer, publicOrigin, internalOrigin,
          connectPath: safePath(env.OMB_MARTA_PBX_CONNECT_PATH, "/marta-connect"), handoffToken }
      : null;
    mkdirSync(dirname(this.file), { recursive: true });
    this.load();
  }

  configured(): boolean { return this.config !== null; }
  isMartaBot(botId: string): boolean {
    return Boolean(this.targetBotId && equalSecret(botId, this.targetBotId));
  }

  private load(): void {
    if (!existsSync(this.file)) return;
    try {
      const parsed = JSON.parse(readFileSync(this.file, "utf8")) as Partial<MartaFile>;
      if (parsed.version !== 1 || !Array.isArray(parsed.bindings)) return;
      this.bindings = parsed.bindings.filter((row): row is MartaBinding =>
        Boolean(row && typeof row === "object" &&
          typeof row.ombSessionId === "string" && typeof row.botId === "string" &&
          typeof row.threadId === "string" && typeof row.pbxSessionId === "string" &&
          typeof row.sessionExpiresAt === "number" && typeof row.sessionGrant === "string" &&
          validIdentity(row.identity)));
      this.prune();
    } catch { this.bindings = []; }
  }
  private persist(): void {
    writeFileAtomic(this.file, JSON.stringify({ version: 1, bindings: this.bindings }, null, 2) + "\n", { mode: 0o600 });
  }
  private prune(): void {
    const now = this.now();
    const next = this.bindings.filter((row) => row.sessionExpiresAt > now);
    if (next.length !== this.bindings.length) { this.bindings = next; this.persist(); }
    for (const [state, row] of this.pending) if (row.expiresAt <= now) this.pending.delete(state);
  }
  private requireConfig(): Configuration {
    if (!this.config) throw Object.assign(new Error("Marta PBX identity is not configured on this server"), { status: 503 });
    return this.config;
  }
  private binding(ombSessionId: string, botId: string, threadId: string): MartaBinding | null {
    this.prune();
    return this.bindings.find((row) =>
      equalSecret(row.ombSessionId, ombSessionId) &&
      equalSecret(row.botId, botId) &&
      equalSecret(row.threadId, threadId)) ?? null;
  }

  status(ombSessionId: string, botId: string, threadId: string): Record<string, unknown> {
    if (!this.isMartaBot(botId)) return { applicable: false };
    if (!this.config) return { applicable: true, configured: false, connected: false, threadId };
    const binding = this.binding(ombSessionId, botId, threadId);
    return binding
      ? { applicable: true, configured: true, connected: true, identity: binding.identity,
          sessionExpiresAt: binding.sessionExpiresAt, threadId: binding.threadId }
      : { applicable: true, configured: true, connected: false, threadId };
  }

  start(ombSessionId: string, botId: string, threadId: string, next?: string): string {
    const config = this.requireConfig();
    if (!this.isMartaBot(botId)) throw Object.assign(new Error("PBX identity is available only for the configured Marta bot"), { status: 404 });
    if (!/^[\w-]+$/.test(threadId)) throw Object.assign(new Error("threadId must be a task id"), { status: 400 });
    this.prune();
    const state = randomBytes(32).toString("base64url");
    const verifier = randomBytes(32).toString("base64url");
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    this.pending.set(state, { ombSessionId, botId, threadId, verifier, next: safePath(next, "/"), expiresAt: this.now() + PENDING_TTL_MS });
    const url = new URL(config.connectPath, config.publicOrigin);
    url.searchParams.set("state", state);
    url.searchParams.set("challenge", challenge);
    url.searchParams.set("botId", botId);
    url.searchParams.set("threadId", threadId);
    return url.toString();
  }

  async consume(ombSessionId: string, state: string, code: string): Promise<string> {
    this.requireConfig();
    this.prune();
    const pending = this.pending.get(state);
    if (!pending || !equalSecret(pending.ombSessionId, ombSessionId)) {
      throw Object.assign(new Error("Marta connection request is invalid or expired"), { status: 400 });
    }
    this.pending.delete(state);
    if (!code || code.length > 512) throw Object.assign(new Error("Marta handoff code is invalid"), { status: 400 });
    const payload = await this.post("/api/marta/v1/handoff/consume", {
      contractVersion: CONTRACT_VERSION, code, verifier: pending.verifier,
      botId: pending.botId, threadId: pending.threadId,
    });
    const sessionExpiresAt = expiryMs(payload.sessionExpiresAt);
    if (!validIdentity(payload.identity) || typeof payload.sessionId !== "string" ||
        sessionExpiresAt === null || typeof payload.sessionGrant !== "string") {
      throw Object.assign(new Error("PBX returned an invalid Marta session"), { status: 502 });
    }
    this.bindings = this.bindings.filter((row) =>
      !(row.ombSessionId === ombSessionId && row.botId === pending.botId && row.threadId === pending.threadId));
    this.bindings.push({
      ombSessionId, botId: pending.botId, threadId: pending.threadId,
      pbxSessionId: payload.sessionId, sessionExpiresAt,
      sessionGrant: payload.sessionGrant, identity: payload.identity,
    });
    this.persist();
    return pending.next;
  }

  assertMessageAdmission(input: {
    ombSessionId?: string; botId: string; threadId: string; guarded: boolean;
    busy: boolean; bot: MartaBotPolicy; approvalMode: string;
  }): void {
    if (!this.isMartaBot(input.botId)) return;
    if (!input.ombSessionId) throw Object.assign(new Error("Sign in to OpenMausBot before using Marta"), { status: 401 });
    if (input.guarded) throw Object.assign(new Error("Marta accepts direct signed-in chat only"), { status: 409 });
    if (input.busy) throw Object.assign(new Error("Marta does not steer or queue messages; wait for this turn to finish"), { status: 409 });
    this.assertPolicy(input.bot, input.approvalMode);
    if (!this.binding(input.ombSessionId, input.botId, input.threadId)) {
      throw Object.assign(new Error("Connect your PBX identity for this Marta thread first"), { status: 409, code: "marta_identity_required" });
    }
  }

  assertTurn(input: {
    ombSessionId?: string; botId: string; threadId: string; bot: MartaBotPolicy;
    approvalMode: string; options?: MartaTurnOptions;
  }): boolean {
    if (!this.isMartaBot(input.botId)) return false;
    if (!input.ombSessionId) throw Object.assign(new Error("Marta turns require a signed-in PBX identity"), { status: 409 });
    const options = input.options ?? {};
    if (options.automationSource !== undefined || options.unattended || options.peerAsk ||
        options.cardContinuation || options.computerSelectionContinuation || options.coordination ||
        options.runOn !== undefined || (options.commsDepth ?? 0) > 0) {
      throw Object.assign(new Error("Marta permits direct interactive turns only; automation and bot delegation are disabled"), { status: 409 });
    }
    this.assertPolicy(input.bot, input.approvalMode);
    if (!this.binding(input.ombSessionId, input.botId, input.threadId)) {
      throw Object.assign(new Error("The PBX identity for this Marta thread is missing or expired"), { status: 409 });
    }
    return true;
  }

  private assertPolicy(bot: MartaBotPolicy, approvalMode: string): void {
    const config = this.requireConfig();
    const exactMcp = bot.mcpServers?.length === 1 && bot.mcpServers[0] === config.mcpServer;
    if (approvalMode !== "ask" || bot.autoApprove === true || Boolean(bot.alwaysAllow?.length) ||
        bot.computer !== "off" || bot.browser !== false || bot.composio !== false ||
        bot.chiefOfStaff === true || bot.approvePeerComms === true ||
        Boolean(bot.managedSections?.length) || Boolean(bot.peers?.length) || !exactMcp) {
      throw Object.assign(new Error(
        `Marta safety policy requires Ask, no remembered approvals, Works on Off, browser/apps/team access off, and only MCP server "${config.mcpServer}"`,
      ), { status: 409, code: "marta_policy" });
    }
  }

  async actorMcp(ombSessionId: string, botId: string, threadId: string,
    servers: Record<string, McpServerSpec>): Promise<Record<string, McpServerSpec>> {
    const config = this.requireConfig();
    const binding = this.binding(ombSessionId, botId, threadId);
    if (!binding) throw Object.assign(new Error("The PBX identity for this Marta thread is missing or expired"), { status: 409 });
    const server = servers[config.mcpServer];
    if (!server || isRemoteMcpServer(server)) {
      throw Object.assign(new Error(`Marta requires the local stdio MCP server "${config.mcpServer}"`), { status: 409 });
    }
    const payload = await this.post("/api/marta/v1/session/check", {
      contractVersion: CONTRACT_VERSION, sessionGrant: binding.sessionGrant, botId, threadId,
    });
    const sessionExpiresAt = expiryMs(payload.sessionExpiresAt);
    if (!validIdentity(payload.identity) || typeof payload.actorGrant !== "string" ||
        typeof payload.sessionId !== "string" || sessionExpiresAt === null ||
        !equalSecret(payload.sessionId, binding.pbxSessionId)) {
      throw Object.assign(new Error("PBX rejected or changed the Marta session"), { status: 401 });
    }
    binding.identity = payload.identity;
    binding.sessionExpiresAt = sessionExpiresAt;
    this.persist();
    const clone: StdioMcpSpec = {
      command: server.command, args: [...server.args],
      env: { ...server.env, MARTA_ACTOR_GRANT: payload.actorGrant },
    };
    return { [config.mcpServer]: clone };
  }

  async disconnect(ombSessionId: string, botId: string, threadId: string): Promise<boolean> {
    const rows = this.bindings.filter((row) =>
      row.ombSessionId === ombSessionId && row.botId === botId && row.threadId === threadId);
    if (!rows.length) return false;
    this.bindings = this.bindings.filter((row) => !rows.includes(row));
    this.persist();
    await Promise.allSettled(rows.map((row) => this.revoke(row)));
    return true;
  }
  async revokeForOmbSession(ombSessionId: string): Promise<void> {
    const rows = this.bindings.filter((row) => row.ombSessionId === ombSessionId);
    if (!rows.length) return;
    this.bindings = this.bindings.filter((row) => row.ombSessionId !== ombSessionId);
    this.persist();
    await Promise.allSettled(rows.map((row) => this.revoke(row)));
  }
  private async revoke(row: MartaBinding): Promise<void> {
    await this.post("/api/marta/v1/session/revoke", {
      contractVersion: CONTRACT_VERSION, sessionGrant: row.sessionGrant,
      botId: row.botId, threadId: row.threadId,
    });
  }
  private async post(path: string, body: Record<string, unknown>): Promise<Record<string, unknown>> {
    const config = this.requireConfig();
    let response: Response;
    try {
      response = await this.fetchImpl(new URL(path, config.internalOrigin), {
        method: "POST",
        headers: { authorization: `Bearer ${config.handoffToken}`, "content-type": "application/json" },
        body: JSON.stringify(body), signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
    } catch {
      throw Object.assign(new Error("PBX identity service is unavailable"), { status: 502 });
    }
    const payload = await response.json().catch(() => ({})) as Record<string, unknown>;
    if (!response.ok) {
      const message = typeof payload.error === "string" ? payload.error : "PBX identity request was refused";
      throw Object.assign(new Error(message), { status: response.status === 401 || response.status === 403 ? 401 : 502 });
    }
    return payload;
  }
}
