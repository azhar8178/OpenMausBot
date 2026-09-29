import { useEffect, useState } from "react";

interface MartaStatus {
  applicable: boolean;
  configured?: boolean;
  connected?: boolean;
  identity?: { name: string; email: string; role: string };
  sessionExpiresAt?: number;
  threadId?: string;
}
async function requestStatus(botId: string, threadId: string): Promise<MartaStatus> {
  const query = new URLSearchParams({ botId, threadId });
  const response = await fetch(`/api/auth/pbx/status?${query}`, { credentials: "same-origin" });
  if (!response.ok) throw new Error("Could not check PBX identity");
  return response.json() as Promise<MartaStatus>;
}
export function MartaConnectionCard({ botId, threadId }: { botId: string; threadId: string }) {
  const [status, setStatus] = useState<MartaStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const refresh = async () => {
    try { setError(null); setStatus(await requestStatus(botId, threadId)); }
    catch (cause) { setError(cause instanceof Error ? cause.message : String(cause)); }
  };
  useEffect(() => { void refresh(); }, [botId, threadId]);
  if (!status?.applicable && !error) return null;
  const disconnect = async () => {
    setBusy(true); setError(null);
    try {
      const response = await fetch("/api/auth/pbx/disconnect", {
        method: "POST", credentials: "same-origin", headers: { "content-type": "application/json" },
        body: JSON.stringify({ botId, threadId }),
      });
      if (!response.ok) throw new Error("Could not disconnect PBX identity");
      await refresh();
    } catch (cause) { setError(cause instanceof Error ? cause.message : String(cause)); }
    finally { setBusy(false); }
  };
  const connect = () => {
    const query = new URLSearchParams({ botId, threadId, next: "/" });
    window.location.assign(`/api/auth/pbx/start?${query}`);
  };
  return (
    <div className="rounded-xl bg-card p-4">
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="text-[15px] font-medium text-ink">PBX identity</div>
          <div className="mt-0.5 text-[13px] text-ink-secondary">
            {status?.configured === false
              ? "PBX identity is not fully configured on this Marta server."
              : status?.connected
              ? `Connected as ${status.identity?.name || status.identity?.email || "PBX user"} for this thread.`
              : "Connect your PBX account before Marta can read approved business data in this thread."}
          </div>
          {status?.connected && status.identity?.email && (
            <div className="mt-2 truncate text-[12px] text-ink-secondary">
              {status.identity.email} · {status.identity.role}
              {status.sessionExpiresAt ? ` · expires ${new Date(status.sessionExpiresAt).toLocaleString()}` : ""}
            </div>
          )}
          {error && <div className="mt-2 text-[12px] text-danger">{error}</div>}
        </div>
        <button type="button" disabled={busy || status?.configured === false} onClick={status?.connected ? disconnect : connect}
          className="shrink-0 rounded-lg bg-control px-3 py-2 text-[13px] text-ink hover:bg-raised-hover disabled:opacity-50">
          {busy ? "Working…" : status?.connected ? "Disconnect" : "Connect PBX"}
        </button>
      </div>
      <div className="mt-3 rounded-lg bg-inset px-3 py-2 text-[11.5px] leading-relaxed text-ink-secondary">
        PBX roles are checked again for every Marta turn. The browser never receives a PBX grant.
      </div>
    </div>
  );
}
