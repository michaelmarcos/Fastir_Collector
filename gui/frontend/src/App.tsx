import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, type StartOptions } from "./api";
import { ArtifactBrowser } from "./components/ArtifactBrowser";
import { ConfigPanel, type Config } from "./components/ConfigPanel";
import { Console } from "./components/Console";
import { RunHistory } from "./components/RunHistory";
import { SettingsModal } from "./components/SettingsModal";
import { Button, Dot, Pill } from "./components/ui";
import type { CollectorStatus, Meta, RunSummary } from "./types";

const DEFAULT_CFG: Config = {
  packages: new Set(["fast"]),
  dump: new Set(["mft"]),
  output_type: "csv",
  output_dir: "",
  profile: "",
  homedrive: "",
};

function toOptions(cfg: Config): StartOptions {
  return {
    packages: [...cfg.packages],
    output_type: cfg.output_type,
    output_dir: cfg.output_dir.trim() || null,
    dump: [...cfg.dump],
    profile: cfg.profile.trim() || null,
    homedrive: cfg.homedrive.trim() || null,
  };
}

export default function App() {
  const [meta, setMeta] = useState<Meta | null>(null);
  const [status, setStatus] = useState<CollectorStatus | null>(null);
  const [cfg, setCfg] = useState<Config>(DEFAULT_CFG);
  const [command, setCommand] = useState<string | null>(null);

  const [runs, setRuns] = useState<RunSummary[]>([]);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [lines, setLines] = useState<string[]>([]);
  const [runStatus, setRunStatus] = useState<"idle" | "running" | "completed" | "failed">("idle");

  const [settingsOpen, setSettingsOpen] = useState(false);
  const [artifactRun, setArtifactRun] = useState<RunSummary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const esRef = useRef<EventSource | null>(null);

  // --- bootstrap ---
  const loadMeta = useCallback(async () => {
    const m = await api.meta();
    setMeta(m);
    setStatus(m.status);
  }, []);

  const loadRuns = useCallback(async () => {
    const { runs } = await api.list();
    setRuns(runs);
  }, []);

  useEffect(() => {
    loadMeta().catch((e) => setError((e as Error).message));
    loadRuns().catch(() => {});
  }, [loadMeta, loadRuns]);

  // --- live command preview (debounced) ---
  useEffect(() => {
    if (cfg.packages.size === 0) {
      setCommand(null);
      return;
    }
    const t = setTimeout(() => {
      api
        .previewCommand(toOptions(cfg))
        .then((r) => setCommand(r.command))
        .catch((e) => setCommand(`// ${(e as Error).message}`));
    }, 200);
    return () => clearTimeout(t);
  }, [cfg, status]);

  // --- stream a run via SSE ---
  const attachStream = useCallback(
    (id: string) => {
      esRef.current?.close();
      const es = new EventSource(`/api/collections/${id}/stream`);
      esRef.current = es;
      es.addEventListener("log", (e) => {
        const line = JSON.parse((e as MessageEvent).data) as string;
        setLines((prev) => [...prev, line]);
      });
      es.addEventListener("done", (e) => {
        const summary = JSON.parse((e as MessageEvent).data) as RunSummary;
        setRunStatus(summary.status === "completed" ? "completed" : "failed");
        es.close();
        loadRuns();
        api.get(id).then((full) => {
          setRuns((prev) => prev.map((r) => (r.id === id ? full : r)));
        });
      });
      es.onerror = () => es.close();
    },
    [loadRuns]
  );

  const onRun = async () => {
    setError(null);
    try {
      const summary = await api.start(toOptions(cfg));
      setLines([]);
      setActiveId(summary.id);
      setRunStatus("running");
      setRuns((prev) => [summary, ...prev]);
      attachStream(summary.id);
    } catch (e) {
      setError((e as Error).message);
    }
  };

  const onStop = async () => {
    if (activeId) await api.stop(activeId).catch(() => {});
  };

  const onSelectRun = async (r: RunSummary) => {
    esRef.current?.close();
    setActiveId(r.id);
    const full = await api.get(r.id);
    setLines(full.line_count ? await fetchLogLines(r.id) : []);
    if (full.status === "running") {
      setRunStatus("running");
      attachStream(r.id);
    } else {
      setRunStatus(full.status);
    }
  };

  const openArtifacts = async () => {
    if (!activeId) return;
    const full = await api.get(activeId);
    setArtifactRun(full);
  };

  const activeRun = useMemo(() => runs.find((r) => r.id === activeId) ?? null, [runs, activeId]);
  const statusTone = status?.runnable ? "ok" : status?.collector_found ? "warn" : "bad";

  if (!meta || !status) {
    return (
      <div className="flex h-full items-center justify-center font-mono text-sm text-slate-500">
        {error ? <span className="text-danger">{error}</span> : "initializing…"}
      </div>
    );
  }

  return (
    <div className="grid-bg flex h-full flex-col">
      {/* header */}
      <header className="flex items-center justify-between border-b border-ink-600/70 px-5 py-3">
        <div className="flex items-center gap-3">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-acid/40 bg-acid/10 font-mono text-acid">
            ⛬
          </div>
          <div>
            <h1 className="font-mono text-sm font-semibold tracking-wide text-slate-100">
              FastIR <span className="text-acid">//</span> Collector Console
            </h1>
            <p className="font-mono text-[10px] text-slate-500">live Windows incident-response artifact collection</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <Pill tone={statusTone}>
            <Dot tone={statusTone} />
            {status.runnable ? "ready" : status.collector_found ? "needs elevation / py2" : "collector missing"}
          </Pill>
          <Button variant="ghost" onClick={() => setSettingsOpen(true)}>
            ⚙ Settings
          </Button>
        </div>
      </header>

      {error && (
        <div className="border-b border-danger/30 bg-danger/10 px-5 py-2 font-mono text-[11px] text-danger">
          {error}
        </div>
      )}

      {/* body */}
      <main className="grid min-h-0 flex-1 grid-cols-12 gap-4 p-4">
        <div className="col-span-12 min-h-0 lg:col-span-3">
          <ConfigPanel
            meta={meta}
            cfg={cfg}
            setCfg={setCfg}
            command={command}
            running={runStatus === "running"}
            onRun={onRun}
            onStop={onStop}
          />
        </div>

        <div className="col-span-12 flex min-h-0 flex-col gap-4 lg:col-span-6">
          <div className="min-h-0 flex-1">
            <Console lines={lines} status={runStatus} runId={activeId} />
          </div>
          {activeRun && (activeRun.artifacts?.length || activeRun.status !== "running") && (
            <div className="flex items-center justify-between rounded-xl border border-ink-600/70 bg-ink-800/60 px-4 py-2.5">
              <span className="font-mono text-[11px] text-slate-400">
                {activeRun.status === "running"
                  ? "collecting…"
                  : `${activeRun.artifacts?.length ?? 0} artifact(s) · rc ${activeRun.return_code}`}
              </span>
              <Button variant="ghost" onClick={openArtifacts} disabled={activeRun.status === "running"}>
                ⌗ Browse artifacts
              </Button>
            </div>
          )}
        </div>

        <div className="col-span-12 min-h-0 lg:col-span-3">
          <RunHistory runs={runs} activeId={activeId} onSelect={onSelectRun} />
        </div>
      </main>

      <SettingsModal
        open={settingsOpen}
        status={status}
        onClose={() => setSettingsOpen(false)}
        onUpdated={(s) => setStatus(s)}
      />
      <ArtifactBrowser run={artifactRun} onClose={() => setArtifactRun(null)} />
    </div>
  );
}

async function fetchLogLines(id: string): Promise<string[]> {
  // The console.log is reconstructed from the run's stored lines via the stream
  // fallback; for finished runs we re-open the stream which replays from cursor 0.
  return new Promise((resolve) => {
    const es = new EventSource(`/api/collections/${id}/stream`);
    const out: string[] = [];
    es.addEventListener("log", (e) => out.push(JSON.parse((e as MessageEvent).data)));
    es.addEventListener("done", () => {
      es.close();
      resolve(out);
    });
    es.onerror = () => {
      es.close();
      resolve(out);
    };
  });
}
