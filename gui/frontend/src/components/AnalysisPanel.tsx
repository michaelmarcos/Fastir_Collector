import { AnimatePresence, motion } from "framer-motion";
import { marked } from "marked";
import { useEffect, useRef, useState } from "react";
import { api } from "../api";
import type { AnalysisInfo, AttackAssessment, RunSummary } from "../types";
import { Button, Dot, Pill } from "./ui";

marked.setOptions({ gfm: true, breaks: false });

export function AnalysisPanel({
  run,
  onClose,
}: {
  run: RunSummary | null;
  onClose: () => void;
}) {
  const [markdown, setMarkdown] = useState("");
  const [state, setState] = useState<"idle" | "thinking" | "streaming" | "done" | "error">("idle");
  const [meta, setMeta] = useState<AnalysisInfo | null>(null);
  const [assessment, setAssessment] = useState<AttackAssessment | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const esRef = useRef<EventSource | null>(null);
  const bodyRef = useRef<HTMLDivElement>(null);

  const start = (id: string) => {
    esRef.current?.close();
    setMarkdown("");
    setAssessment(null);
    setErrorMsg(null);
    setState("thinking");
    const es = new EventSource(api.analyzeStreamUrl(id));
    esRef.current = es;
    es.addEventListener("meta", (e) => setMeta(JSON.parse((e as MessageEvent).data)));
    es.addEventListener("structured", (e) => setAssessment(JSON.parse((e as MessageEvent).data)));
    es.addEventListener("delta", (e) => {
      setState("streaming");
      setMarkdown((prev) => prev + (JSON.parse((e as MessageEvent).data) as string));
    });
    es.addEventListener("done", () => {
      setState("done");
      es.close();
    });
    es.addEventListener("error", (e) => {
      const data = (e as MessageEvent).data;
      setErrorMsg(data ? JSON.parse(data) : "stream error");
      setState("error");
      es.close();
    });
    es.onerror = () => {
      if (state !== "done") setState((s) => (s === "streaming" || s === "done" ? s : "error"));
      es.close();
    };
  };

  useEffect(() => {
    if (run) start(run.id);
    return () => esRef.current?.close();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [run?.id]);

  useEffect(() => {
    bodyRef.current?.scrollTo({ top: bodyRef.current.scrollHeight });
  }, [markdown]);

  const cleanMd = markdown.replace(/<!--ATTACK_JSON[\s\S]*?-->/g, "").trimEnd();
  const html = cleanMd ? (marked.parse(cleanMd) as string) : "";

  const verdictTone =
    assessment?.verdict === "likely-malicious"
      ? "bad"
      : assessment?.verdict === "suspicious"
      ? "warn"
      : "ok";

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
            className="flex h-full w-full max-w-3xl flex-col border-l border-ink-600 bg-ink-800"
            initial={{ x: "100%" }}
            animate={{ x: 0 }}
            exit={{ x: "100%" }}
            transition={{ type: "spring", damping: 30, stiffness: 280 }}
            onClick={(e) => e.stopPropagation()}
          >
            <header className="flex items-center justify-between border-b border-ink-600 px-5 py-3">
              <div>
                <h2 className="flex items-center gap-2 font-mono text-sm text-slate-200">
                  <span className="text-acid">⌬</span> AI attack-chain analysis
                </h2>
                <p className="font-mono text-[11px] text-slate-500">{run.id}</p>
              </div>
              <div className="flex items-center gap-2">
                {meta && (
                  <Pill tone={meta.ai_ready ? "ok" : "warn"}>
                    <Dot tone={meta.ai_ready ? "ok" : "warn"} />
                    {meta.ai_ready ? meta.model : "heuristic"}
                  </Pill>
                )}
                <Button variant="ghost" onClick={() => start(run.id)} disabled={state === "streaming" || state === "thinking"}>
                  ↻ Re-run
                </Button>
                <Button variant="ghost" onClick={onClose}>
                  ✕
                </Button>
              </div>
            </header>

            {assessment && (
              <div className="border-b border-ink-600 bg-ink-900/40 px-5 py-3">
                <div className="mb-2 flex items-center gap-2">
                  <Pill tone={verdictTone}>
                    <Dot tone={verdictTone} />
                    {assessment.verdict}
                  </Pill>
                  <span className="font-mono text-[11px] text-slate-500">
                    confidence: {assessment.confidence} · {assessment.techniques.length} ATT&CK technique(s)
                  </span>
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {assessment.techniques.map((t, i) => (
                    <span
                      key={i}
                      title={`${t.tactic} · ${t.technique_name} — ${t.evidence} (confidence ${t.confidence})`}
                      className="inline-flex items-center gap-1.5 rounded-md border border-acid/30 bg-acid/[0.06] px-2 py-0.5 font-mono text-[10px] text-slate-300"
                    >
                      <span className="text-acid">{t.technique_id}</span>
                      <span className="text-slate-500">·</span>
                      {t.tactic}
                    </span>
                  ))}
                  {assessment.techniques.length === 0 && (
                    <span className="font-mono text-[10px] text-slate-600">no mapped techniques</span>
                  )}
                </div>
              </div>
            )}

            <div ref={bodyRef} className="prose-ir min-h-0 flex-1 overflow-y-auto px-6 py-5">
              {state === "thinking" && !markdown && (
                <div className="flex items-center gap-2 font-mono text-xs text-slate-500">
                  <span className="inline-block h-3 w-2 animate-blink bg-acid" />
                  {meta?.ai_ready ? "Claude is reasoning over the evidence…" : "Generating triage…"}
                </div>
              )}
              {errorMsg && (
                <p className="font-mono text-xs text-danger">Analysis error: {errorMsg}</p>
              )}
              <div dangerouslySetInnerHTML={{ __html: html }} />
              {state === "streaming" && <span className="inline-block h-3.5 w-2 animate-blink bg-acid align-middle" />}
            </div>

            {!meta?.ai_ready && state === "done" && (
              <div className="border-t border-ink-600 px-6 py-2.5 font-mono text-[11px] text-amber">
                Heuristic mode — set an Anthropic API key in ⚙ Settings for a full AI hypothesis.
              </div>
            )}
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
