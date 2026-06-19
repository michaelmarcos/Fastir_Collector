import { AnimatePresence, motion } from "framer-motion";
import { useEffect, useState } from "react";
import { api } from "../api";
import type { Artifact, ArtifactPreview, RunSummary } from "../types";
import { Button, bytes, Dot } from "./ui";

export function ArtifactBrowser({
  run,
  onClose,
}: {
  run: RunSummary | null;
  onClose: () => void;
}) {
  const artifacts = run?.artifacts ?? [];
  const [selected, setSelected] = useState<Artifact | null>(null);
  const [preview, setPreview] = useState<ArtifactPreview | null>(null);
  const [loading, setLoading] = useState(false);

  const [explain, setExplain] = useState<{ row: string[]; text: string; mode: string; loading: boolean } | null>(null);

  useEffect(() => {
    setSelected(artifacts[0] ?? null);
    setPreview(null);
    setExplain(null);
  }, [run?.id]);

  useEffect(() => {
    if (!run || !selected) return;
    setExplain(null);
    setLoading(true);
    api
      .preview(run.id, selected.rel)
      .then(setPreview)
      .catch(() => setPreview(null))
      .finally(() => setLoading(false));
  }, [run?.id, selected?.rel]);

  const explainRow = async (header: string[], row: string[]) => {
    if (!run || !selected) return;
    setExplain({ row, text: "", mode: "", loading: true });
    try {
      const res = await api.explain(run.id, selected.rel, header, row);
      setExplain({ row, text: res.explanation, mode: res.mode, loading: false });
    } catch (e) {
      setExplain({ row, text: `Could not explain: ${(e as Error).message}`, mode: "error", loading: false });
    }
  };

  return (
    <AnimatePresence>
      {run && (
        <motion.div
          className="fixed inset-0 z-40 flex justify-end bg-black/70"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          onClick={onClose}
        >
          <motion.div
            className="flex h-full w-full max-w-5xl flex-col border-l border-ink-600 bg-ink-800"
            initial={{ x: "100%" }}
            animate={{ x: 0 }}
            exit={{ x: "100%" }}
            transition={{ type: "spring", damping: 30, stiffness: 280 }}
            onClick={(e) => e.stopPropagation()}
          >
            <header className="flex items-center justify-between border-b border-ink-600 px-5 py-3">
              <div>
                <h2 className="font-mono text-sm text-slate-200">Artifacts · {run.id}</h2>
                <p className="font-mono text-[11px] text-slate-500">{run.output_dir}</p>
              </div>
              <Button variant="ghost" onClick={onClose}>
                ✕ Close
              </Button>
            </header>

            <div className="grid min-h-0 flex-1 grid-cols-[260px_1fr]">
              {/* file list */}
              <div className="overflow-y-auto border-r border-ink-600 p-2">
                {artifacts.length === 0 && (
                  <p className="p-4 text-center font-mono text-[11px] text-slate-600">
                    No artifacts were produced.
                  </p>
                )}
                {artifacts.map((a) => (
                  <button
                    key={a.rel}
                    onClick={() => setSelected(a)}
                    className={`mb-1 block w-full rounded-lg px-3 py-2 text-left transition-colors ${
                      selected?.rel === a.rel ? "bg-acid/[0.08]" : "hover:bg-ink-700/60"
                    }`}
                  >
                    <span className="flex items-center justify-between gap-2">
                      <span className="truncate font-mono text-[11px] text-slate-300">{a.name}</span>
                      <span className="shrink-0 rounded bg-ink-600 px-1.5 py-0.5 font-mono text-[9px] uppercase text-slate-400">
                        {a.ext || "bin"}
                      </span>
                    </span>
                    <span className="font-mono text-[10px] text-slate-600">{bytes(a.size)}</span>
                  </button>
                ))}
              </div>

              {/* preview */}
              <div className="flex min-w-0 flex-col">
                <div className="flex items-center justify-between border-b border-ink-600 px-4 py-2">
                  <span className="flex items-center gap-2 font-mono text-[11px] text-slate-400">
                    <Dot tone="ok" />
                    {selected?.rel ?? "—"}
                  </span>
                  {run && selected && (
                    <a
                      href={api.downloadUrl(run.id, selected.rel)}
                      className="font-mono text-[11px] text-acid hover:underline"
                    >
                      ↓ download
                    </a>
                  )}
                </div>
                <div className="min-h-0 flex-1 overflow-auto p-4">
                  {loading ? (
                    <p className="font-mono text-[11px] text-slate-500">loading…</p>
                  ) : (
                    <PreviewBody preview={preview} onExplainRow={explainRow} />
                  )}
                </div>
                {explain && (
                  <div className="max-h-[40%] shrink-0 overflow-auto border-t border-ink-600 bg-ink-900/50 p-4">
                    <div className="mb-1.5 flex items-center gap-2">
                      <span className="text-acid">⌬</span>
                      <span className="font-mono text-[11px] uppercase tracking-wider text-slate-400">
                        Explain row
                      </span>
                      {explain.mode && explain.mode !== "error" && (
                        <span className="font-mono text-[10px] text-slate-600">
                          ({explain.mode === "claude" ? "AI" : "heuristic"})
                        </span>
                      )}
                      <button
                        onClick={() => setExplain(null)}
                        className="ml-auto font-mono text-[11px] text-slate-500 hover:text-slate-300"
                      >
                        ✕
                      </button>
                    </div>
                    {explain.loading ? (
                      <p className="flex items-center gap-2 font-mono text-[11px] text-slate-500">
                        <span className="inline-block h-3 w-2 animate-blink bg-acid" /> analyzing this entry…
                      </p>
                    ) : (
                      <p className="whitespace-pre-wrap text-[12px] leading-relaxed text-slate-300">
                        {explain.text}
                      </p>
                    )}
                  </div>
                )}
              </div>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}

function PreviewBody({
  preview,
  onExplainRow,
}: {
  preview: ArtifactPreview | null;
  onExplainRow: (header: string[], row: string[]) => void;
}) {
  if (!preview) return <p className="font-mono text-[11px] text-slate-600">Select an artifact.</p>;

  if (preview.kind === "csv") {
    const header = preview.header ?? [];
    return (
      <div className="overflow-auto">
        <p className="mb-2 font-mono text-[10px] text-slate-600">Click any row to ask the AI to explain it.</p>
        <table className="w-full border-collapse font-mono text-[11px]">
          <thead className="sticky top-0">
            <tr>
              {header.map((h, i) => (
                <th
                  key={i}
                  className="border-b border-ink-500 bg-ink-700 px-2.5 py-1.5 text-left font-semibold text-acid/90"
                >
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {preview.rows?.map((row, i) => (
              <tr
                key={i}
                onClick={() => onExplainRow(header, row)}
                className="cursor-pointer odd:bg-ink-700/30 hover:bg-acid/[0.07]"
              >
                {row.map((cell, j) => (
                  <td key={j} className="border-b border-ink-600/50 px-2.5 py-1 text-slate-300">
                    {cell}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
        {preview.truncated && (
          <p className="mt-2 font-mono text-[10px] text-amber">Preview truncated. Download for full file.</p>
        )}
      </div>
    );
  }

  if (preview.kind === "json") {
    return (
      <pre className="whitespace-pre-wrap break-all font-mono text-[11px] text-slate-300">
        {JSON.stringify(preview.data, null, 2)}
      </pre>
    );
  }

  if (preview.kind === "text") {
    return (
      <pre className="whitespace-pre-wrap break-all font-mono text-[11px] text-slate-300">
        {preview.text}
      </pre>
    );
  }

  return <p className="font-mono text-[11px] text-slate-500">{preview.note ?? "Binary file."}</p>;
}
