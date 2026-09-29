import type { MartaPbxSessionManager } from "../marta-pbx-session.ts";
import { PASS, type RouteHandler } from "./table.ts";

export interface MartaPbxRouteDeps {
  manager: MartaPbxSessionManager;
  bot(id: string): { id: string; threadId: string; hidden?: boolean } | null | undefined;
}
function sessionId(auth: Parameters<RouteHandler>[0]["auth"]): string {
  if (auth.kind !== "session") throw Object.assign(new Error("A signed-in OpenMaus session is required"), { status: 401 });
  return auth.session.id;
}
function field(url: URL, name: string, max: number): string {
  const value = url.searchParams.get(name)?.trim() ?? "";
  if (!value || value.length > max) throw Object.assign(new Error(`${name} is required`), { status: 400 });
  return value;
}
export function createMartaPbxRoutes(deps: MartaPbxRouteDeps): RouteHandler {
  return async ({ req, res, url, path, method, auth, json, readBody }) => {
    if (path === "/api/auth/pbx/status" && method === "GET") {
      const botId = field(url, "botId", 128), threadId = field(url, "threadId", 128);
      res.setHeader("cache-control", "no-store");
      // Desktop-owner loopback sessions do not have a durable OpenMaus
      // session id to bind. Keep the card absent instead of surfacing an
      // authentication error on every non-hosted bot settings screen.
      if (auth.kind !== "session") return json(res, 200, { applicable: false });
      return json(res, 200, deps.manager.status(sessionId(auth), botId, threadId));
    }
    if (path === "/api/auth/pbx/start" && method === "GET") {
      const botId = field(url, "botId", 128), threadId = field(url, "threadId", 128);
      const bot = deps.bot(botId);
      if (!bot || bot.hidden || bot.threadId !== threadId) return json(res, 404, { error: "no such Marta thread" });
      const location = deps.manager.start(sessionId(auth), bot.id, threadId, url.searchParams.get("next") ?? "/");
      res.statusCode = 303; res.setHeader("cache-control", "no-store"); res.setHeader("location", location); res.end(); return;
    }
    if (path === "/api/auth/pbx/callback" && method === "GET") {
      const next = await deps.manager.consume(sessionId(auth), field(url, "state", 512), field(url, "code", 512));
      res.statusCode = 303; res.setHeader("cache-control", "no-store"); res.setHeader("location", next); res.end(); return;
    }
    if (path === "/api/auth/pbx/disconnect" && method === "POST") {
      const body = await readBody(req);
      if (!body || typeof body !== "object" || Array.isArray(body) ||
          typeof body.botId !== "string" || typeof body.threadId !== "string") {
        return json(res, 400, { error: "botId and threadId are required" });
      }
      await deps.manager.disconnect(sessionId(auth), body.botId, body.threadId);
      res.setHeader("cache-control", "no-store");
      return json(res, 200, { ok: true });
    }
    return PASS;
  };
}
