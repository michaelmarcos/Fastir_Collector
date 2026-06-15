import { motion } from "framer-motion";
import type { RunSummary } from "../types";
import { Dot, Panel } from "./ui";

function ago(iso: string): string {
  const d = new Date(iso).getTime();
  const s = Math.max(0, Math.round((Date.now() - d) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return new Date(iso).toLocaleDateString();
}

export function RunHistory({
  runs,
  activeId,
  onSelect,
}: {
  runs: RunSummary[];
  activeId: string | null;
  onSelect: (r: RunSummary) => void;
}) {
  return (
    <Panel
      title="Run history"
      className="flex h-full flex-col"
      right={<span className="font-mono text-[11px] text-slate-600">{runs.length}</span>}
    >
      <div className="flex-1 space-y-1.5 overflow-y-auto p-3">
        {runs.length === 0 && (
          <p className="px-1 py-6 text-center font-mono text-[11px] text-slate-600">
            No runs yet.
          </p>
        )}
        {runs.map((r) => {
          const tone = r.status === "running" ? "warn" : r.status === "completed" ? "ok" : "bad";
          const active = r.id === activeId;
          const pkgs = (r.options.packages as string[] | undefined) ?? [];
          return (
            <motion.button
              key={r.id}
              layout
              onClick={() => onSelect(r)}
              className={`block w-full rounded-lg border px-3 py-2.5 text-left transition-colors ${
                active
                  ? "border-acid/50 bg-acid/[0.06]"
                  : "border-ink-600/60 bg-ink-700/30 hover:border-ink-500"
              }`}
            >
              <div className="flex items-center justify-between gap-2">
                <span className="flex items-center gap-2 font-mono text-[11px] text-slate-300">
                  <Dot tone={tone} />
                  {r.id.slice(9)}
                </span>
                <span className="font-mono text-[10px] text-slate-600">{ago(r.created_at)}</span>
              </div>
              <div className="mt-1.5 flex flex-wrap gap-1">
                {pkgs.slice(0, 4).map((p) => (
                  <span
                    key={p}
                    className="rounded bg-ink-600/70 px-1.5 py-0.5 font-mono text-[10px] text-slate-400"
                  >
                    {p}
                  </span>
                ))}
                {pkgs.length > 4 && (
                  <span className="font-mono text-[10px] text-slate-600">+{pkgs.length - 4}</span>
                )}
              </div>
            </motion.button>
          );
        })}
      </div>
    </Panel>
  );
}
