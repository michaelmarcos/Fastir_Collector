import { useEffect, useRef } from "react";
import { Dot, Panel, Pill } from "./ui";

function lineTone(line: string): string {
  const l = line.toLowerCase();
  if (l.includes("[launcher]")) return "text-sky-400/80";
  if (l.includes("error") || l.includes("traceback") || l.includes("failed")) return "text-danger";
  if (l.includes("warn")) return "text-amber";
  if (l.includes(" info ") || l.includes("- info -")) return "text-acid/90";
  return "text-slate-400";
}

export function Console({
  lines,
  status,
  runId,
}: {
  lines: string[];
  status: "idle" | "running" | "completed" | "failed";
  runId: string | null;
}) {
  const endRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [lines.length]);

  const tone =
    status === "running" ? "warn" : status === "completed" ? "ok" : status === "failed" ? "bad" : "muted";

  return (
    <Panel
      title="Live console"
      className="scanlines flex h-full flex-col overflow-hidden"
      right={
        <div className="flex items-center gap-2">
          {runId && <span className="font-mono text-[10px] text-slate-600">{runId}</span>}
          <Pill tone={tone}>
            <Dot tone={tone} />
            {status}
          </Pill>
        </div>
      }
    >
      <div className="relative flex-1 overflow-y-auto bg-ink-900/70 p-4 font-mono text-xs leading-relaxed">
        {lines.length === 0 ? (
          <div className="flex h-full items-center justify-center text-center text-slate-600">
            <div>
              <pre className="text-acid/40">{BANNER}</pre>
              <p className="mt-3 text-[11px]">
                Configure a collection plan and press{" "}
                <span className="text-acid">▶ Run</span> to stream collector output here.
              </p>
            </div>
          </div>
        ) : (
          <>
            {lines.map((line, i) => (
              <div key={i} className="flex gap-3 whitespace-pre-wrap break-all">
                <span className="select-none text-ink-500">{String(i + 1).padStart(3, "0")}</span>
                <span className={lineTone(line)}>{line || " "}</span>
              </div>
            ))}
            {status === "running" && (
              <div className="flex gap-3">
                <span className="select-none text-ink-500">{String(lines.length + 1).padStart(3, "0")}</span>
                <span className="inline-block h-3.5 w-2 animate-blink bg-acid" />
              </div>
            )}
            <div ref={endRef} />
          </>
        )}
      </div>
    </Panel>
  );
}

const BANNER = `  ______        _   _____ _____
 |  ____|      | | |_   _|  __ \\
 | |__ __ _ ___| |_  | | | |__) |
 |  __/ _\` / __| __| | | |  _  /
 | | | (_| \\__ \\ |_ _| |_| | \\ \\
 |_|  \\__,_|___/\\__|_____|_|  \\_\\`;
