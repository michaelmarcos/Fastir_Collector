import type { AnalysisInfo, ArtifactPreview, CollectorStatus, Meta, RunSummary } from "./types";

async function j<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let detail = res.statusText;
    try {
      detail = (await res.json()).detail ?? detail;
    } catch {
      /* ignore */
    }
    throw new Error(detail);
  }
  return res.json() as Promise<T>;
}

export interface StartOptions {
  packages: string[];
  engine: string;
  output_type: string;
  output_dir?: string | null;
  dump: string[];
  profile?: string | null;
  homedrive?: string | null;
}

export const api = {
  meta: () => fetch("/api/meta").then((r) => j<Meta>(r)),

  updateSettings: (
    collector_override: string | null,
    interpreter_override: string[] | null,
    analysis_api_key?: string | null
  ) =>
    fetch("/api/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ collector_override, interpreter_override, analysis_api_key }),
    }).then((r) => j<{ status: CollectorStatus; analysis: AnalysisInfo }>(r)),

  previewCommand: (opts: StartOptions) =>
    fetch("/api/preview-command", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(opts),
    }).then((r) => j<{ argv: string[]; command: string }>(r)),

  start: (opts: StartOptions) =>
    fetch("/api/collections", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(opts),
    }).then((r) => j<RunSummary>(r)),

  list: () => fetch("/api/collections").then((r) => j<{ runs: RunSummary[] }>(r)),

  get: (id: string) => fetch(`/api/collections/${id}`).then((r) => j<RunSummary>(r)),

  stop: (id: string) =>
    fetch(`/api/collections/${id}/stop`, { method: "POST" }).then((r) => j<{ stopped: boolean }>(r)),

  preview: (id: string, rel: string) =>
    fetch(`/api/collections/${id}/artifacts/preview?rel=${encodeURIComponent(rel)}`).then((r) =>
      j<ArtifactPreview>(r)
    ),

  downloadUrl: (id: string, rel: string) =>
    `/api/collections/${id}/artifacts/download?rel=${encodeURIComponent(rel)}`,

  analyzeStreamUrl: (id: string) => `/api/collections/${id}/analyze/stream`,
};
