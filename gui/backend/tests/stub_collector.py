"""
stub_collector.py - a tiny Python 3 stand-in for FastIR's main.py.

FastIR itself is Python 2 + Windows + admin only, so it cannot run on most dev
machines. This stub speaks the same CLI surface (--packages / --output_type /
--output_dir / --dump) and produces realistic-looking log output and CSV/JSON
artifacts. It lets you exercise the entire GUI -- live log streaming, run
history, the artifact browser -- on any OS without a real Windows IR host.

Point the GUI at it via the Settings panel:
    collector path : gui/backend/tests/stub_collector.py
    interpreter    : python

It is a TEST/DEMO harness only -- it collects nothing real.
"""
import argparse
import csv
import json
import os
import time


SAMPLE = {
    "health": ("processes", ["pid", "name", "user", "cmdline"], [
        ["4", "System", "NT AUTHORITY\\SYSTEM", ""],
        ["680", "svchost.exe", "NT AUTHORITY\\SYSTEM", "svchost.exe -k netsvcs"],
        ["1337", "powershell.exe", "WIN10\\analyst", "powershell -enc SQBFAFgA..."],
        ["2210", "rundll32.exe", "WIN10\\analyst", "rundll32 evil.dll,Start"],
    ]),
    "registry": ("autoruns", ["hive", "key", "value", "data"], [
        ["HKLM", "...\\Run", "OneDrive", "C:\\Users\\analyst\\OneDrive.exe"],
        ["HKCU", "...\\Run", "Updater", "C:\\Users\\analyst\\AppData\\update.exe"],
    ]),
    "fs": ("prefetch", ["name", "run_count", "last_run"], [
        ["CMD.EXE-12345678.pf", "9", "2026-06-14 22:11:03"],
        ["POWERSHELL.EXE-ABCDEF01.pf", "21", "2026-06-15 01:04:55"],
    ]),
    "memory": ("clipboard", ["format", "content"], [
        ["CF_UNICODETEXT", "net user backdoor P@ssw0rd /add"],
    ]),
    "evt": ("security_events", ["event_id", "time", "message"], [
        ["4624", "2026-06-15 01:02:00", "An account was successfully logged on"],
        ["4688", "2026-06-15 01:04:55", "A new process has been created: powershell.exe"],
    ]),
}


def write_artifact(out_dir, package, output_type):
    title, header, rows = SAMPLE.get(
        package, (package, ["field", "value"], [["note", "no sample for this package"]])
    )
    base = os.path.join(out_dir, f"{package}_{title}")
    if output_type == "json":
        records = [dict(zip(header, r)) for r in rows]
        with open(base + ".json", "w", encoding="utf-8") as f:
            json.dump(records, f, indent=2)
    else:
        with open(base + ".csv", "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(header)
            w.writerows(rows)


def main():
    parser = argparse.ArgumentParser(description="FastIR stub collector")
    parser.add_argument("--packages")
    parser.add_argument("--output_type", default="csv")
    parser.add_argument("--output_dir", required=True)
    parser.add_argument("--dump")
    parser.add_argument("--profile")
    parser.add_argument("--homedrive")
    args = parser.parse_args()

    print(r"""
  ______        _   _____ _____
 |  ____|      | | |_   _|  __ \
 | |__ __ _ ___| |_  | | | |__) |
 |  __/ _` / __| __| | | |  _  /
 | | | (_| \__ \ |_ _| |_| | \ \
 |_|  \__,_|___/\__|_____|_|  \_\

     FastIR stub collector (DEMO -- collects nothing real)
""", flush=True)

    os.makedirs(args.output_dir, exist_ok=True)
    requested = [p.strip() for p in (args.packages or "").split(",") if p.strip()]
    if "all" in requested or "fast" in requested:
        requested = list(SAMPLE.keys())

    print(f"FastIR - INFO - output directory: {args.output_dir}", flush=True)
    print(f"FastIR - INFO - output type: {args.output_type}", flush=True)
    print(f"FastIR - INFO - packages: {', '.join(requested) or '(none)'}", flush=True)
    time.sleep(0.4)

    for package in requested:
        print(f"FastIR - INFO - collecting package '{package}' ...", flush=True)
        time.sleep(0.6)
        if package in SAMPLE:
            write_artifact(args.output_dir, package, args.output_type)
            print(f"FastIR - INFO - wrote {package} artifact", flush=True)
        else:
            print(f"FastIR - INFO - package '{package}' has no stub sample", flush=True)

    if args.dump:
        for d in args.dump.split(","):
            print(f"FastIR - INFO - [dump] simulating {d} dump ...", flush=True)
            time.sleep(0.5)
            with open(os.path.join(args.output_dir, f"dump_{d}.txt"), "w", encoding="utf-8") as f:
                f.write(f"stub {d} dump placeholder\n")

    # Demo-only synthetic outputs so the AI/heuristic analysis has signal to chew on.
    # None of this is real — it is fabricated to exercise the analysis + matrix UI.
    write_demo_signal(args.output_dir, args.output_type)

    print(f"FastIR - INFO - Check here {os.path.abspath(args.output_dir)} for your results", flush=True)


# Fabricated triage findings (demo only — not real host data).
DEMO_INDICATORS = [
    ["high", "pshistory", "Suspicious PowerShell (-enc): powershell -nop -w hidden -enc SQBFAFgA...", "2026-06-19T01:04:55+00:00"],
    ["high", "defender", "Defender Paths exclusion set: C:\\ProgramData\\svc", "2026-06-19T01:05:10+00:00"],
    ["high", "crypto", "Browser wallet extension MetaMask in profile 'Default'", "2026-06-19T01:06:00+00:00"],
    ["medium", "bam", "Execution from suspicious path: C:\\Users\\Public\\runner.exe", "2026-06-19T01:02:00+00:00"],
    ["medium", "aiapps", "Local AI/LLM tool present: ollama (C:\\Users\\analyst\\.ollama)", "2026-06-18T22:10:00+00:00"],
    ["high", "recall", "Windows Recall is enabled and storing snapshots", "2026-06-19T00:00:00+00:00"],
]

DEMO_PSHISTORY = [
    ["analyst", "1", "whoami /all"],
    ["analyst", "2", "powershell -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0AC4ALgAu"],
    ["analyst", "3", "net user backdoor P@ssw0rd /add"],
    ["analyst", "4", "Add-MpPreference -ExclusionPath C:\\ProgramData\\svc"],
]


def write_demo_signal(out_dir, output_type):
    _write(out_dir, "_indicators", ["severity", "artifact", "detail", "timestamp_utc"],
           DEMO_INDICATORS, output_type)
    _write(out_dir, "powershell_history", ["user", "line", "command"],
           DEMO_PSHISTORY, output_type)
    high = sum(1 for i in DEMO_INDICATORS if i[0] == "high")
    print(f"FastIR - INFO - triage indicators: {len(DEMO_INDICATORS)} ({high} high-severity)", flush=True)


def _write(out_dir, name, header, rows, output_type):
    base = os.path.join(out_dir, name)
    if output_type == "json":
        with open(base + ".json", "w", encoding="utf-8") as f:
            json.dump([dict(zip(header, r)) for r in rows], f, indent=2)
    else:
        with open(base + ".csv", "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(header)
            w.writerows(rows)


if __name__ == "__main__":
    main()
