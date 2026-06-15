import { AnimatePresence, motion } from "framer-motion";
import { useState } from "react";
import { api } from "../api";
import type { CollectorStatus } from "../types";
import { Button, Dot } from "./ui";

export function SettingsModal({
  open,
  status,
  onClose,
  onUpdated,
}: {
  open: boolean;
  status: CollectorStatus;
  onClose: () => void;
  onUpdated: (s: CollectorStatus) => void;
}) {
  const [collector, setCollector] = useState(status.collector_path);
  const [interpreter, setInterpreter] = useState(status.interpreter?.join(" ") ?? "");
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const save = async () => {
    setSaving(true);
    setErr(null);
    try {
      const interp = interpreter.trim() ? interpreter.trim().split(/\s+/) : null;
      const res = await api.updateSettings(collector.trim() || null, interp);
      onUpdated(res.status);
      onClose();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          onClick={onClose}
        >
          <motion.div
            className="w-full max-w-xl rounded-2xl border border-ink-600 bg-ink-800 p-6"
            initial={{ scale: 0.95, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0.95, opacity: 0 }}
            onClick={(e) => e.stopPropagation()}
          >
            <h2 className="font-mono text-sm uppercase tracking-[0.2em] text-slate-300">
              Collector settings
            </h2>
            <p className="mt-1 text-[12px] leading-relaxed text-slate-500">
              Point the GUI at the real FastIR collector. Default is{" "}
              <code className="text-slate-400">main.py</code> (Python 2). For a compiled binary, use a path
              to <code className="text-slate-400">fastIR_x64.exe</code> and leave the interpreter blank. To
              demo on any machine, use the bundled stub (see below).
            </p>

            <div className="mt-5 space-y-4">
              <Field label="Collector path">
                <input
                  value={collector}
                  onChange={(e) => setCollector(e.target.value)}
                  className="w-full rounded-lg border border-ink-600 bg-ink-900/60 px-3 py-2 font-mono text-xs text-slate-200 outline-none focus:border-acid/50"
                />
              </Field>
              <Field label="Interpreter (blank for .exe)">
                <input
                  value={interpreter}
                  onChange={(e) => setInterpreter(e.target.value)}
                  placeholder="py -2   ·   python2   ·   python"
                  className="w-full rounded-lg border border-ink-600 bg-ink-900/60 px-3 py-2 font-mono text-xs text-slate-200 outline-none placeholder:text-slate-600 focus:border-acid/50"
                />
              </Field>

              <button
                onClick={() => {
                  setCollector(status.collector_path.replace(/main\.py$/, "gui/backend/tests/stub_collector.py"));
                  setInterpreter("python");
                }}
                className="font-mono text-[11px] text-amber hover:underline"
              >
                ⚙ use bundled demo stub (python)
              </button>

              <div className="rounded-lg border border-ink-600/70 bg-ink-900/40 p-3">
                <div className="grid grid-cols-2 gap-y-1.5 font-mono text-[11px]">
                  <StatusRow ok={status.collector_found} label="collector found" />
                  <StatusRow ok={status.is_windows} label="windows host" />
                  <StatusRow ok={status.interpreter !== null || status.is_exe} label="interpreter ready" />
                  <StatusRow ok={status.is_admin} label="administrator" />
                </div>
                <div className="mt-2 border-t border-ink-600/60 pt-2 font-mono text-[10px] text-slate-500">
                  {status.notes.map((n, i) => (
                    <div key={i}>· {n}</div>
                  ))}
                </div>
              </div>

              {err && <p className="font-mono text-[11px] text-danger">{err}</p>}
            </div>

            <div className="mt-6 flex justify-end gap-2">
              <Button variant="ghost" onClick={onClose}>
                Cancel
              </Button>
              <Button onClick={save} disabled={saving}>
                {saving ? "Saving…" : "Save & re-detect"}
              </Button>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1.5 block font-mono text-[11px] uppercase tracking-[0.18em] text-slate-500">
        {label}
      </span>
      {children}
    </label>
  );
}

function StatusRow({ ok, label }: { ok: boolean; label: string }) {
  return (
    <span className="flex items-center gap-2 text-slate-400">
      <Dot tone={ok ? "ok" : "bad"} />
      {label}
    </span>
  );
}
