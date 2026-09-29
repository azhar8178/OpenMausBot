import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

import { MartaPbxSessionManager } from "./marta-pbx-session.ts";

const roots: string[] = [];
const env = {
  OMB_MARTA_BOT_ID: "marta",
  OMB_MARTA_MCP_SERVER: "marta-readonly",
  OMB_MARTA_PBX_PUBLIC_URL: "https://pbx.example.test",
  OMB_MARTA_PBX_INTERNAL_URL: "http://pbx-internal:3001",
  OMB_MARTA_PBX_CONNECT_PATH: "/marta-connect",
  MARTA_HANDOFF_TOKEN: "x".repeat(64),
};
function fixture(fetchImpl: typeof fetch, now = () => 1_800_000_000_000) {
  const root = mkdtempSync(join(tmpdir(), "omb-marta-")); roots.push(root);
  const file = join(root, "marta-pbx-sessions.json");
  return { file, manager: new MartaPbxSessionManager({ file, env, fetch: fetchImpl, now }) };
}
function response(body: Record<string, unknown>, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}
afterEach(() => {
  vi.restoreAllMocks();
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("Marta PBX session manager", () => {
  it("fails closed when configuration is incomplete", () => {
    const root = mkdtempSync(join(tmpdir(), "omb-marta-")); roots.push(root);
    const manager = new MartaPbxSessionManager({ file: join(root, "sessions.json"), env: {}, fetch: vi.fn() });
    expect(manager.configured()).toBe(false);
    expect(manager.status("omb", "marta", "thread")).toEqual({ applicable: false });
    expect(() => manager.start("omb", "marta", "thread")).toThrow(/not configured/);
  });

  it("binds PKCE state to one OpenMaus session and never persists turn secrets", async () => {
    const calls: Array<{ url: string; body: Record<string, unknown> }> = [];
    const fetchImpl = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      calls.push({ url: String(input), body: JSON.parse(String(init?.body)) });
      return response({
        identity: { userId: "7", email: "agent@example.test", name: "Agent", role: "marta_reader" },
        sessionId: "pbx-session", sessionExpiresAt: 1_800_000_600_000,
        sessionGrant: "session-grant", actorGrant: "actor-grant",
      });
    }) as unknown as typeof fetch;
    const { file, manager } = fixture(fetchImpl);
    const first = new URL(manager.start("omb-a", "marta", "thread-a", "/safe"));
    expect(first.origin).toBe("https://pbx.example.test");
    expect(first.searchParams.get("challenge")).toMatch(/^[A-Za-z0-9_-]{43}$/);
    await expect(manager.consume("omb-b", first.searchParams.get("state")!, "code")).rejects.toThrow(/invalid or expired/);
    expect(calls).toHaveLength(0);

    const second = new URL(manager.start("omb-a", "marta", "thread-a", "/safe"));
    expect(await manager.consume("omb-a", second.searchParams.get("state")!, "code")).toBe("/safe");
    expect(calls[0]).toMatchObject({
      url: "http://pbx-internal:3001/api/marta/v1/handoff/consume",
      body: { code: "code", botId: "marta", threadId: "thread-a" },
    });
    const stored = readFileSync(file, "utf8");
    expect(stored).toContain("session-grant");
    expect(stored).not.toContain("actor-grant");
    expect(stored).not.toContain("verifier");
    await expect(manager.consume("omb-a", second.searchParams.get("state")!, "code")).rejects.toThrow(/invalid or expired/);
  });

  it("injects a fresh actor grant into only the exact local Marta MCP server", async () => {
    const fetchImpl = vi.fn(async (input: string | URL | Request) => {
      const path = new URL(String(input)).pathname;
      return path.endsWith("/handoff/consume")
        ? response({ identity: { userId: "7", email: "agent@example.test", name: "Agent", role: "reader" },
            sessionId: "pbx-session", sessionExpiresAt: 1_800_000_600_000, sessionGrant: "session-grant" })
        : response({ identity: { userId: "7", email: "agent@example.test", name: "Agent", role: "reader" },
            sessionId: "pbx-session", sessionExpiresAt: 1_800_000_600_000, actorGrant: "turn-only" });
    }) as unknown as typeof fetch;
    const { manager } = fixture(fetchImpl);
    const start = new URL(manager.start("omb-a", "marta", "thread-a"));
    await manager.consume("omb-a", start.searchParams.get("state")!, "code");
    const original = { command: "node", args: ["/opt/marta/marta-mcp-stdio.mjs"], env: { SAFE: "1" } };
    const mounted = await manager.actorMcp("omb-a", "marta", "thread-a", {
      "marta-readonly": original, extra: { command: "node", args: ["extra.mjs"], env: {} },
    });
    expect(Object.keys(mounted)).toEqual(["marta-readonly"]);
    expect(mounted["marta-readonly"]).toEqual({
      command: "node", args: ["/opt/marta/marta-mcp-stdio.mjs"],
      env: { SAFE: "1", MARTA_ACTOR_GRANT: "turn-only" },
    });
    expect(original.env).toEqual({ SAFE: "1" });
  });

  it("rejects automation, unsafe policy, remote MCP and cross-thread reuse", async () => {
    const fetchImpl = vi.fn(async (input: string | URL | Request) => {
      const path = new URL(String(input)).pathname;
      return path.endsWith("/handoff/consume")
        ? response({ identity: { userId: "7", email: "a@b.test", name: "A", role: "reader" },
            sessionId: "pbx-session", sessionExpiresAt: 1_800_000_600_000, sessionGrant: "session-grant" })
        : response({ identity: { userId: "7", email: "a@b.test", name: "A", role: "reader" },
            sessionId: "pbx-session", sessionExpiresAt: 1_800_000_600_000, actorGrant: "turn-only" });
    }) as unknown as typeof fetch;
    const { manager } = fixture(fetchImpl);
    const start = new URL(manager.start("omb-a", "marta", "thread-a"));
    await manager.consume("omb-a", start.searchParams.get("state")!, "code");
    const safe = { computer: "off", browser: false, composio: false,
      mcpServers: ["marta-readonly"], peers: [], managedSections: [], alwaysAllow: [] };
    expect(() => manager.assertTurn({ ombSessionId: "omb-a", botId: "marta", threadId: "thread-a",
      bot: safe, approvalMode: "ask", options: { automationSource: "schedule" } })).toThrow(/direct interactive/);
    expect(() => manager.assertTurn({ ombSessionId: "omb-a", botId: "marta", threadId: "thread-b",
      bot: safe, approvalMode: "ask" })).toThrow(/missing or expired/);
    expect(() => manager.assertTurn({ ombSessionId: "omb-a", botId: "marta", threadId: "thread-a",
      bot: { ...safe, browser: true }, approvalMode: "ask" })).toThrow(/safety policy/);
    await expect(manager.actorMcp("omb-a", "marta", "thread-a", {
      "marta-readonly": { type: "http", url: "https://unsafe.example.test", headers: {} },
    })).rejects.toThrow(/local stdio/);
  });

  it("removes local grants and revokes PBX sessions", async () => {
    let revoked = false;
    const fetchImpl = vi.fn(async (input: string | URL | Request) => {
      const path = new URL(String(input)).pathname;
      if (path.endsWith("/handoff/consume")) return response({
        identity: { userId: "7", email: "a@b.test", name: "A", role: "reader" },
        sessionId: "pbx-session", sessionExpiresAt: 1_800_000_600_000, sessionGrant: "session-grant",
      });
      if (path.endsWith("/session/revoke")) revoked = true;
      return response({ ok: true });
    }) as unknown as typeof fetch;
    const { manager } = fixture(fetchImpl);
    const start = new URL(manager.start("omb-a", "marta", "thread-a"));
    await manager.consume("omb-a", start.searchParams.get("state")!, "code");
    await manager.revokeForOmbSession("omb-a");
    expect(revoked).toBe(true);
    expect(manager.status("omb-a", "marta", "thread-a")).toMatchObject({ connected: false });
  });
});
