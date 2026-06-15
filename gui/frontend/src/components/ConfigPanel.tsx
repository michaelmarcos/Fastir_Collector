import { AnimatePresence, motion } from "framer-motion";
import type { Meta } from "../types";
import { Button, Panel } from "./ui";

export interface Config {
  packages: Set<string>;
  dump: Set<string>;
  output_type: string;
  output_dir: string;
  profile: string;
  homedrive: string;
}

export function ConfigPanel({
  meta,
  cfg,
  setCfg,
  command,
  running,
  onRun,
  onStop,
}: {
  meta: Meta;
  cfg: Config;
  setCfg: (c: Config) => void;
  command: string | null;
  running: boolean;
  onRun: () => void;
  onStop: () => void;
}) {
  const toggle = (key: "packages" | "dump", id: string) => {
    const next = new Set(cfg[key]);
    next.has(id) ? next.delete(id) : next.add(id);
    setCfg({ ...cfg, [key]: next });
  };

  const dumpSelected = cfg.packages.has(meta.dump_package);

  return (
    <Panel title="Collection plan" className="flex h-full flex-col">
      <div className="flex-1 space-y-5 overflow-y-auto p-4">
        {/* Packages */}
        <section>
          <Label>Packages</Label>
          <div className="grid gap-1.5">
            {meta.packages.map((p) => {
              const on = cfg.packages.has(p.id);
              return (
                <button
                  key={p.id}
                  onClick={() => toggle("packages", p.id)}
                  className={`group flex items-start gap-2.5 rounded-lg border px-3 py-2 text-left transition-colors ${
                    on
                      ? "border-acid/50 bg-acid/[0.07]"
                      : "border-ink-600/70 bg-ink-700/40 hover:border-ink-500"
                  }`}
                >
                  <span
                    className={`mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded border font-mono text-[10px] ${
                      on ? "border-acid bg-acid text-ink-900" : "border-ink-500 text-transparent"
                    }`}
                  >
                    ✓
                  </span>
                  <span className="min-w-0">
                    <span className="font-mono text-xs text-slate-200">{p.label}</span>
                    <span className="block text-[11px] leading-snug text-slate-500">{p.desc}</span>
                  </span>
                </button>
              );
            })}
          </div>
        </section>

        {/* Dump options (conditional) */}
        <AnimatePresence initial={false}>
          {dumpSelected && (
            <motion.section
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: "auto" }}
              exit={{ opacity: 0, height: 0 }}
              className="overflow-hidden"
            >
              <Label>
                Dump targets <span className="text-amber">· required for dump</span>
              </Label>
              <div className="flex flex-wrap gap-1.5">
                {meta.dump_options.map((d) => {
                  const on = cfg.dump.has(d.id);
                  return (
                    <button
                      key={d.id}
                      title={d.desc}
                      onClick={() => toggle("dump", d.id)}
                      className={`rounded-md border px-2.5 py-1 font-mono text-[11px] transition-colors ${
                        on
                          ? "border-amber/60 bg-amber/10 text-amber"
                          : "border-ink-600 bg-ink-700/40 text-slate-400 hover:border-ink-500"
                      }`}
                    >
                      {d.label}
                    </button>
                  );
                })}
              </div>
            </motion.section>
          )}
        </AnimatePresence>

        {/* Output type */}
        <section>
          <Label>Output format</Label>
          <div className="inline-flex rounded-lg border border-ink-600 p-0.5">
            {meta.output_types.map((t) => (
              <button
                key={t}
                onClick={() => setCfg({ ...cfg, output_type: t })}
                className={`rounded-md px-4 py-1.5 font-mono text-xs uppercase transition-colors ${
                  cfg.output_type === t ? "bg-acid text-ink-900" : "text-slate-400 hover:text-slate-200"
                }`}
              >
                {t}
              </button>
            ))}
          </div>
        </section>

        {/* Output dir */}
        <section>
          <Label>Output directory</Label>
          <Input
            value={cfg.output_dir}
            placeholder="(auto: per-run folder under _runs/)"
            onChange={(v) => setCfg({ ...cfg, output_dir: v })}
          />
        </section>

        {/* Advanced */}
        <details className="group">
          <summary className="cursor-pointer list-none font-mono text-[11px] uppercase tracking-[0.2em] text-slate-500 hover:text-slate-300">
            ▸ Advanced
          </summary>
          <div className="mt-3 space-y-3">
            <div>
              <Label>Profile (.conf)</Label>
              <Input
                value={cfg.profile}
                placeholder="path\to\profile.conf"
                onChange={(v) => setCfg({ ...cfg, profile: v })}
              />
            </div>
            <div>
              <Label>Homedrive</Label>
              <Input
                value={cfg.homedrive}
                placeholder="C:"
                onChange={(v) => setCfg({ ...cfg, homedrive: v })}
              />
            </div>
          </div>
        </details>
      </div>

      {/* Command preview + run */}
      <div className="border-t border-ink-600/60 p-4">
        <Label>Command preview</Label>
        <pre className="mb-3 max-h-24 overflow-auto rounded-lg border border-ink-600 bg-ink-900/80 p-2.5 font-mono text-[11px] leading-relaxed text-acid/90">
          {command ? `$ ${command}` : "// select packages to build a command"}
        </pre>
        {running ? (
          <Button variant="danger" className="w-full" onClick={onStop}>
            ■ Stop collection
          </Button>
        ) : (
          <Button className="w-full" onClick={onRun} disabled={cfg.packages.size === 0}>
            ▶ Run collection
          </Button>
        )}
      </div>
    </Panel>
  );
}

function Label({ children }: { children: React.ReactNode }) {
  return (
    <div className="mb-2 font-mono text-[11px] uppercase tracking-[0.18em] text-slate-500">
      {children}
    </div>
  );
}

function Input({
  value,
  onChange,
  placeholder,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
}) {
  return (
    <input
      value={value}
      placeholder={placeholder}
      onChange={(e) => onChange(e.target.value)}
      className="w-full rounded-lg border border-ink-600 bg-ink-900/60 px-3 py-2 font-mono text-xs text-slate-200 outline-none transition-colors placeholder:text-slate-600 focus:border-acid/50"
    />
  );
}
