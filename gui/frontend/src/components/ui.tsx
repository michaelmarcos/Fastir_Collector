import type { ReactNode } from "react";

export function Panel({
  title,
  right,
  children,
  className = "",
}: {
  title?: string;
  right?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={`relative rounded-xl border border-ink-600/70 bg-ink-800/80 ${className}`}
    >
      {title && (
        <div className="flex items-center justify-between border-b border-ink-600/60 px-4 py-2.5">
          <h2 className="font-mono text-[11px] uppercase tracking-[0.2em] text-slate-400">{title}</h2>
          {right}
        </div>
      )}
      {children}
    </div>
  );
}

export function Pill({
  tone = "muted",
  children,
}: {
  tone?: "ok" | "warn" | "bad" | "muted";
  children: ReactNode;
}) {
  const tones: Record<string, string> = {
    ok: "border-acid/40 text-acid bg-acid/10",
    warn: "border-amber/40 text-amber bg-amber/10",
    bad: "border-danger/40 text-danger bg-danger/10",
    muted: "border-ink-500 text-slate-400 bg-ink-700/60",
  };
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 font-mono text-[11px] ${tones[tone]}`}
    >
      {children}
    </span>
  );
}

export function Dot({ tone = "muted" }: { tone?: "ok" | "warn" | "bad" | "muted" }) {
  const c: Record<string, string> = {
    ok: "bg-acid shadow-[0_0_8px] shadow-acid",
    warn: "bg-amber",
    bad: "bg-danger",
    muted: "bg-slate-500",
  };
  return <span className={`h-1.5 w-1.5 rounded-full ${c[tone]}`} />;
}

export function Button({
  children,
  onClick,
  variant = "primary",
  disabled,
  title,
  className = "",
}: {
  children: ReactNode;
  onClick?: () => void;
  variant?: "primary" | "ghost" | "danger";
  disabled?: boolean;
  title?: string;
  className?: string;
}) {
  const variants: Record<string, string> = {
    primary:
      "bg-acid/90 text-ink-900 hover:bg-acid disabled:bg-ink-600 disabled:text-slate-500 font-semibold shadow-glow disabled:shadow-none",
    ghost: "border border-ink-500 text-slate-300 hover:border-ink-500/0 hover:bg-ink-600/60",
    danger: "border border-danger/50 text-danger hover:bg-danger/10",
  };
  return (
    <button
      title={title}
      onClick={onClick}
      disabled={disabled}
      className={`inline-flex items-center justify-center gap-2 rounded-lg px-3.5 py-2 font-mono text-xs transition-all disabled:cursor-not-allowed ${variants[variant]} ${className}`}
    >
      {children}
    </button>
  );
}

export function bytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}
