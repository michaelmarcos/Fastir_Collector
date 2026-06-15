export interface PackageInfo {
  id: string;
  label: string;
  desc: string;
}

export interface DumpOption {
  id: string;
  label: string;
  desc: string;
}

export interface CollectorStatus {
  collector_path: string;
  collector_found: boolean;
  is_exe: boolean;
  interpreter: string[] | null;
  interpreter_label: string;
  platform: string;
  is_windows: boolean;
  is_admin: boolean;
  runnable: boolean;
  notes: string[];
}

export interface Meta {
  packages: PackageInfo[];
  dump_options: DumpOption[];
  output_types: string[];
  dump_package: string;
  status: CollectorStatus;
  repo_root: string;
}

export interface Artifact {
  name: string;
  rel: string;
  size: number;
  ext: string;
}

export interface RunSummary {
  id: string;
  command: string;
  argv: string[];
  options: Record<string, unknown>;
  output_dir: string;
  status: "running" | "completed" | "failed";
  return_code: number | null;
  created_at: string;
  finished_at: string | null;
  line_count: number;
  artifacts?: Artifact[];
}

export interface ArtifactPreview {
  rel: string;
  ext: string;
  size: number;
  kind: "csv" | "json" | "text" | "binary";
  header?: string[];
  rows?: string[][];
  data?: unknown;
  text?: string;
  note?: string;
  truncated?: boolean;
}
