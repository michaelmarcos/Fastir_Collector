"""
modern_collector.py - a Python 3 collector for *modern* Windows forensic
artifacts that the original (2015-era) FastIR Collector does not cover.

FastIR collects: browser history, prefetch, recycle bin, startups, ARP/network/
processes/services/tasks, classic registry keys (autoruns, USB, userassist,
shellbags, MRU), clipboard/DLLs, and raw dumps.

This module adds the post-2015 DFIR staples FastIR misses, using only the Python
standard library (winreg / sqlite3 / struct), so it runs on the same Python 3
that powers the GUI -- no Python 2, and user-hive artifacts need no admin:

    bam          BAM/DAM  - per-user program execution with timestamps
    shimcache    AppCompatCache - program execution / presence (Win8/10/11)
    muicache     MUICache - executed application names
    recentapps   Search RecentApps - launched apps + counts + last access
    pshistory    PSReadLine console history - attacker command lines
    timeline     Windows Timeline (ActivitiesCache.db) - app activity history
    jumplists    Jump Lists - recently opened files per application
    defender     Microsoft Defender exclusions + detection history
    amcache      Amcache.hve - acquire hive for offline analysis
    srum         SRUDB.dat - acquire System Resource Usage Monitor DB

Every collection also writes ``_indicators`` - a heuristic triage list flagging
suspicious findings (executables in temp/appdata, encoded PowerShell, Defender
exclusions, etc.).

It mirrors FastIR's CLI surface so the GUI can drive it identically:
    python modern_collector.py --packages bam,muicache --output_type csv --output_dir DIR

This collects from the LIVE host. It is read-only and acquires nothing it cannot
open; locked/SYSTEM artifacts are reported rather than forced.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import struct
import sys
import traceback
from datetime import datetime, timedelta, timezone

IS_WINDOWS = os.name == "nt"
if IS_WINDOWS:
    import winreg

# Artifacts that require administrator / SYSTEM to read.
ADMIN_ARTIFACTS = {"bam", "shimcache", "amcache", "srum", "defender"}

PACKAGES = [
    {"id": "all", "label": "all", "desc": "Every modern artifact below"},
    {"id": "bam", "label": "BAM/DAM", "desc": "Background Activity Moderator: per-user execution + timestamps (admin)"},
    {"id": "shimcache", "label": "ShimCache", "desc": "AppCompatCache execution/presence evidence (admin)"},
    {"id": "muicache", "label": "MUICache", "desc": "Names of executed applications (current user)"},
    {"id": "recentapps", "label": "RecentApps", "desc": "Launched apps with counts + last access (current user)"},
    {"id": "pshistory", "label": "PS history", "desc": "PSReadLine console history - command lines"},
    {"id": "timeline", "label": "Timeline", "desc": "Windows Timeline activity history (ActivitiesCache.db)"},
    {"id": "jumplists", "label": "Jump Lists", "desc": "Recently opened files per application"},
    {"id": "defender", "label": "Defender", "desc": "Defender exclusions + detection history (admin)"},
    {"id": "amcache", "label": "Amcache", "desc": "Acquire Amcache.hve for offline analysis (admin)"},
    {"id": "srum", "label": "SRUM", "desc": "Acquire SRUDB.dat resource usage DB (admin)"},
    {"id": "aiapps", "label": "AI / LLM", "desc": "Local AI/LLM tools (Ollama, LM Studio, ChatGPT/Claude desktop) + leaked API keys"},
    {"id": "recall", "label": "Win Recall", "desc": "Windows 11 Recall snapshot database + image store"},
    {"id": "crypto", "label": "Crypto", "desc": "Cryptocurrency wallet files + browser wallet extensions"},
]
PACKAGE_IDS = [p["id"] for p in PACKAGES if p["id"] != "all"]

# Suspicious path fragments used by the indicator heuristics.
SUSPECT_DIRS = ("\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\", "\\downloads\\",
                "\\users\\public\\", "\\programdata\\", "\\$recycle.bin\\", "\\perflogs\\")
SUSPECT_PS = ("-enc", "-encodedcommand", "frombase64string", "downloadstring", "downloadfile",
              "iex", "invoke-expression", "invoke-webrequest", "webclient", "-w hidden",
              "-windowstyle hidden", "bypass", "-nop", "-noprofile", "certutil", "bitsadmin")


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def log(msg: str) -> None:
    print(f"ModernIR - INFO - {msg}", flush=True)


def filetime_to_iso(ft: int) -> str:
    """Convert a Windows FILETIME (100ns since 1601) to an ISO-8601 string."""
    if not ft:
        return ""
    try:
        return (datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ft / 10)).isoformat()
    except Exception:
        return ""


def epoch_to_iso(secs: float) -> str:
    if not secs:
        return ""
    try:
        return datetime.fromtimestamp(secs, tz=timezone.utc).isoformat()
    except Exception:
        return ""


def sha256_file(path: str, limit: int = 200_000_000) -> str:
    try:
        if os.path.getsize(path) > limit:
            return "(too large)"
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def is_admin() -> bool:
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def suspect_path(path: str) -> bool:
    p = (path or "").lower()
    return any(frag in p for frag in SUSPECT_DIRS)


class Result:
    """Container for one artifact's output rows + indicator findings."""

    def __init__(self, name: str, columns: list[str]):
        self.name = name
        self.columns = columns
        self.rows: list[list] = []

    def add(self, *values) -> None:
        self.rows.append(list(values))


# --------------------------------------------------------------------------- #
# collectors
# --------------------------------------------------------------------------- #

def collect_bam(indicators: list[dict]) -> Result:
    """HKLM\\SYSTEM\\CurrentControlSet\\Services\\{bam,dam}\\State\\UserSettings\\<SID>."""
    res = Result("bam_dam", ["source", "sid", "path", "last_execution_utc"])
    for service in ("bam", "dam"):
        base = rf"SYSTEM\CurrentControlSet\Services\{service}\State\UserSettings"
        try:
            root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base)
        except OSError:
            continue
        for i in range(_subkey_count(root)):
            try:
                sid = winreg.EnumKey(root, i)
            except OSError:
                break
            try:
                sk = winreg.OpenKey(root, sid)
            except OSError:
                continue
            for name, value, vtype in _iter_values(sk):
                if vtype != winreg.REG_BINARY or len(value) < 8:
                    continue
                ft = struct.unpack("<Q", value[:8])[0]
                ts = filetime_to_iso(ft)
                res.add(service, sid, name, ts)
                if suspect_path(name):
                    indicators.append(_ind("bam", "high", f"Execution from suspicious path: {name}", ts))
    return res


def collect_shimcache(indicators: list[dict]) -> Result:
    """AppCompatCache binary blob under Session Manager (Win8/10/11 parser)."""
    res = Result("shimcache", ["index", "path", "last_modified_utc"])
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache",
        )
        data, _ = winreg.QueryValueEx(key, "AppCompatCache")
    except OSError:
        log("shimcache: AppCompatCache value not accessible (needs admin)")
        return res

    entries = _parse_appcompat_win10(data)
    if entries is None:
        log("shimcache: unrecognised AppCompatCache format; skipped")
        return res
    for idx, (path, last_mod) in enumerate(entries):
        ts = filetime_to_iso(last_mod)
        res.add(idx, path, ts)
        if suspect_path(path):
            indicators.append(_ind("shimcache", "high", f"Cached execution from suspicious path: {path}", ts))
    return res


def _parse_appcompat_win10(data: bytes):
    """Parse the Windows 8.1/10/11 AppCompatCache format. Returns [(path, filetime)] or None."""
    if len(data) < 0x34:
        return None
    sig = struct.unpack("<I", data[0:4])[0]
    # Win10/11 header is 0x34; Win8.1 is 0x80; older Win8 0x30. Try the common ones.
    for header in (0x34, 0x30, 0x80):
        off = header
        out = []
        ok = True
        if off >= len(data):
            continue
        while off + 12 <= len(data):
            magic = data[off:off + 4]
            if magic != b"10ts":
                ok = bool(out)  # accept if we already parsed entries; else this header is wrong
                break
            off += 8  # magic + unknown/sequence
            try:
                ce_size = struct.unpack("<I", data[off:off + 4])[0]
            except struct.error:
                ok = bool(out)
                break
            off += 4
            entry_end = off + ce_size
            if entry_end > len(data):
                ok = bool(out)
                break
            path_len = struct.unpack("<H", data[off:off + 2])[0]
            off += 2
            path = data[off:off + path_len].decode("utf-16-le", "replace")
            off += path_len
            last_mod = struct.unpack("<Q", data[off:off + 8])[0]
            out.append((path, last_mod))
            off = entry_end
        if ok and out:
            return out
        # If header pointed straight at a 0x34 sig field, retry from the offset it names.
    # Last resort: header field itself is the offset to the first record.
    if sig and sig < len(data) and data[sig:sig + 4] == b"10ts":
        return _parse_appcompat_win10(data[:0] + data)  # avoid; handled above
    return None


def collect_muicache(indicators: list[dict]) -> Result:
    res = Result("muicache", ["executable", "application_name"])
    path = r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, path)
    except OSError:
        log("muicache: key not found for current user")
        return res
    for name, value, _ in _iter_values(key):
        if name.endswith(".FriendlyAppName") or name.endswith(".ApplicationCompany") or name.lower().endswith(".exe"):
            exe = name.rsplit(".FriendlyAppName", 1)[0].rsplit(".ApplicationCompany", 1)[0]
            res.add(exe, value)
            if suspect_path(exe):
                indicators.append(_ind("muicache", "medium", f"Executed app from suspicious path: {exe}", ""))
    return res


def collect_recentapps(indicators: list[dict]) -> Result:
    res = Result("recentapps", ["app_id", "app_path", "launch_count", "last_access_utc"])
    base = r"Software\Microsoft\Windows\CurrentVersion\Search\RecentApps"
    try:
        root = winreg.OpenKey(winreg.HKEY_CURRENT_USER, base)
    except OSError:
        log("recentapps: key not found")
        return res
    for i in range(_subkey_count(root)):
        try:
            guid = winreg.EnumKey(root, i)
            sk = winreg.OpenKey(root, guid)
        except OSError:
            continue
        appid = _val(sk, "AppId")
        path = _val(sk, "AppPath")
        count = _val(sk, "LaunchCount")
        last = _val(sk, "LastAccessedTime")
        ts = filetime_to_iso(int(last)) if isinstance(last, int) else ""
        res.add(appid, path, count, ts)
        if path and suspect_path(str(path)):
            indicators.append(_ind("recentapps", "medium", f"Recently launched from suspicious path: {path}", ts))
    return res


def collect_pshistory(indicators: list[dict]) -> Result:
    res = Result("powershell_history", ["user", "line", "command"])
    users_root = os.environ.get("SystemDrive", "C:") + "\\Users"
    rel = r"AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    targets = []
    if is_admin() and os.path.isdir(users_root):
        for user in os.listdir(users_root):
            p = os.path.join(users_root, user, rel)
            if os.path.isfile(p):
                targets.append((user, p))
    else:
        appdata = os.environ.get("APPDATA")
        if appdata:
            p = os.path.join(appdata, r"Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt")
            if os.path.isfile(p):
                targets.append((os.environ.get("USERNAME", "current"), p))
    for user, p in targets:
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                for n, line in enumerate(f, 1):
                    cmd = line.rstrip("\n")
                    res.add(user, n, cmd)
                    low = cmd.lower()
                    hits = [s for s in SUSPECT_PS if s in low]
                    if hits:
                        indicators.append(_ind("pshistory", "high",
                                               f"Suspicious PowerShell ({', '.join(hits)}): {cmd[:160]}", ""))
        except Exception:
            continue
    return res


def collect_timeline(indicators: list[dict]) -> Result:
    import sqlite3
    res = Result("windows_timeline", ["app_id", "activity_type", "start_utc", "end_utc", "display_text"])
    local = os.environ.get("LOCALAPPDATA")
    if not local:
        return res
    base = os.path.join(local, "ConnectedDevicesPlatform")
    if not os.path.isdir(base):
        log("timeline: ConnectedDevicesPlatform not present")
        return res
    for sub in os.listdir(base):
        db = os.path.join(base, sub, "ActivitiesCache.db")
        if not os.path.isfile(db):
            continue
        try:
            uri = f"file:{db}?mode=ro&immutable=1"
            con = sqlite3.connect(uri, uri=True)
            cur = con.cursor()
            cur.execute(
                "SELECT AppId, ActivityType, StartTime, EndTime, Payload "
                "FROM Activity ORDER BY StartTime DESC LIMIT 2000"
            )
            for appid_raw, atype, start, end, payload in cur.fetchall():
                appid = _timeline_appid(appid_raw)
                text = _timeline_text(payload)
                res.add(appid, atype, epoch_to_iso(start), epoch_to_iso(end), text)
                if suspect_path(appid):
                    indicators.append(_ind("timeline", "medium",
                                           f"Timeline activity for suspicious binary: {appid}",
                                           epoch_to_iso(start)))
            con.close()
        except Exception as exc:
            log(f"timeline: could not read {db}: {exc}")
    return res


def collect_jumplists(indicators: list[dict]) -> list[Result]:
    """Enumerate jump-list files AND parse the DestList stream for recent target paths."""
    files = Result("jumplists", ["type", "app_id", "known_app", "file", "size_bytes", "modified_utc", "sha256"])
    entries = Result("jumplist_entries",
                     ["app_id", "known_app", "entry", "access_count", "last_access_utc", "target_path"])
    lnks = Result("jumplist_lnk_targets",
                  ["app_id", "known_app", "stream", "target", "arguments", "working_dir",
                   "file_size", "write_time_utc", "creation_time_utc"])
    appdata = os.environ.get("APPDATA")
    if not appdata:
        return [files, entries, lnks]
    locations = [
        ("automatic", os.path.join(appdata, r"Microsoft\Windows\Recent\AutomaticDestinations")),
        ("custom", os.path.join(appdata, r"Microsoft\Windows\Recent\CustomDestinations")),
    ]
    for kind, folder in locations:
        if not os.path.isdir(folder):
            continue
        for name in os.listdir(folder):
            p = os.path.join(folder, name)
            if not os.path.isfile(p):
                continue
            appid = name.split(".")[0]
            known = JUMPLIST_APPIDS.get(appid, "")
            st = os.stat(p)
            files.add(kind, appid, known, name, st.st_size, epoch_to_iso(st.st_mtime), sha256_file(p))
            # Deep parse: AutomaticDestinations are OLE2 compound files. The DestList
            # stream holds the MRU index; the numbered streams are individual LNKs.
            if kind == "automatic":
                try:
                    destlist = _read_ole_stream(p, "DestList")
                    if destlist:
                        for e in _parse_destlist(destlist):
                            entries.add(appid, known, e["entry"], e["access_count"],
                                        e["last_access"], e["path"])
                            if suspect_path(e["path"]):
                                indicators.append(_ind("jumplists", "medium",
                                                       f"Recent file from suspicious path ({known or appid}): {e['path']}",
                                                       e["last_access"]))
                except Exception:
                    pass
                try:
                    streams = _read_ole_streams(p, lambda n: n != "DestList"
                                                and 0 < len(n) <= 10
                                                and all(c in "0123456789abcdef" for c in n.lower()))
                    for sname, blob in sorted(streams.items()):
                        info = _parse_lnk(blob)
                        if info and info.get("target"):
                            lnks.add(appid, known, sname, info["target"], info["arguments"],
                                     info["working_dir"], info["file_size"],
                                     info["write_time"], info["creation_time"])
                            blob_low = (info["target"] + " " + info["arguments"]).lower()
                            if suspect_path(info["target"]) or any(s in blob_low for s in SUSPECT_PS):
                                indicators.append(_ind("jumplists", "high",
                                                       f"Suspicious jump-list LNK ({known or appid}): "
                                                       f"{info['target']} {info['arguments']}".strip(),
                                                       info["write_time"]))
                except Exception:
                    pass
    return [files, entries, lnks]


def _parse_destlist(data: bytes) -> list[dict]:
    """Parse a Jump List DestList stream into MRU entries.

    Common fields (both layouts): entry number @0x58, access count @0x64,
    last-access FILETIME @0x68. The path-length offset and trailing padding
    differ by DestList version (header @0x00): v1 puts path_len @0x70 with no
    trailing field; v3/v4 add pin-status/unknown fields and put path_len @0x7C
    with a 4-byte trailer.
    """
    out: list[dict] = []
    if len(data) < 0x20:
        return out
    version = struct.unpack("<I", data[0:4])[0]
    # Field offsets shifted across DestList revisions:
    #   v1     : access@0x64 filetime@0x68 pathlen@0x70 (no trailer)
    #   v3/v4  : access@0x64 filetime@0x68 pathlen@0x7C (+4 trailer)
    #   v6+    : filetime@0x64 (no access count)        pathlen@0x80 (+4 trailer)
    if version >= 5:
        len_off, time_off, acc_off, trailer = 0x80, 0x64, None, 4
    elif version >= 3:
        len_off, time_off, acc_off, trailer = 0x7C, 0x68, 0x64, 4
    else:
        len_off, time_off, acc_off, trailer = 0x70, 0x68, 0x64, 0
    off = 0x20  # skip DestList header
    while off + len_off + 2 <= len(data):
        try:
            entry_no = struct.unpack("<I", data[off + 0x58:off + 0x5C])[0]
            last = struct.unpack("<Q", data[off + time_off:off + time_off + 8])[0]
            access = struct.unpack("<I", data[off + acc_off:off + acc_off + 4])[0] if acc_off else 0
            path_len = struct.unpack("<H", data[off + len_off:off + len_off + 2])[0]
        except struct.error:
            break
        path_start = off + len_off + 2
        path_end = path_start + path_len * 2
        if path_len == 0 or path_len > 2048 or path_end > len(data):
            break
        path = data[path_start:path_end].decode("utf-16-le", "replace")
        out.append({"entry": entry_no, "access_count": access,
                    "last_access": filetime_to_iso(last), "path": path})
        off = path_end + trailer
    return out


# --- minimal OLE2 / CFBF reader (stdlib only) -------------------------------

def _ole_index(data: bytes):
    """Parse an OLE2 compound file once; return (entries, read_stream_fn) or None.

    read_stream_fn(entry) returns the bytes of a directory stream entry, handling
    both the regular FAT and the mini-FAT (for streams below the mini cutoff).
    """
    if len(data) < 512 or data[:8] != b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return None
    sector_shift = struct.unpack("<H", data[0x1E:0x20])[0]
    mini_shift = struct.unpack("<H", data[0x20:0x22])[0]
    sector_size = 1 << sector_shift
    mini_size = 1 << mini_shift
    mini_cutoff = struct.unpack("<I", data[0x38:0x3C])[0]
    first_dir = struct.unpack("<i", data[0x30:0x34])[0]
    first_minifat = struct.unpack("<i", data[0x3C:0x40])[0]
    num_minifat = struct.unpack("<I", data[0x40:0x44])[0]

    def sector_bytes(sid: int) -> bytes:
        start = 512 + sid * sector_size
        return data[start:start + sector_size]

    # Assemble the FAT from the DIFAT (first 109 entries inline; ignore extra DIFAT
    # sectors — jump lists are small enough that 109 FAT sectors is plenty).
    fat: list[int] = []
    for i in range(109):
        sid = struct.unpack("<i", data[0x4C + i * 4:0x50 + i * 4])[0]
        if sid < 0:
            continue
        sec = sector_bytes(sid)
        fat.extend(struct.unpack("<%di" % (len(sec) // 4), sec))

    def chain(start: int, getter) -> bytes:
        out = bytearray()
        sid, seen = start, 0
        while sid >= 0 and seen < 100000:
            out += getter(sid)
            sid = fat[sid] if sid < len(fat) else -1
            seen += 1
        return bytes(out)

    dir_data = chain(first_dir, sector_bytes)
    entries = []
    for i in range(0, len(dir_data) - 128 + 1, 128):
        e = dir_data[i:i + 128]
        name_len = struct.unpack("<H", e[0x40:0x42])[0]
        if name_len == 0:
            continue
        entries.append({
            "name": e[:max(0, name_len - 2)].decode("utf-16-le", "replace"),
            "type": e[0x42],
            "start": struct.unpack("<i", e[0x74:0x78])[0],
            "size": struct.unpack("<I", e[0x78:0x7C])[0],
        })

    root = next((e for e in entries if e["type"] == 5), None)
    mini_container = chain(root["start"], sector_bytes) if root else b""
    minifat_data = chain(first_minifat, sector_bytes) if num_minifat else b""
    minifat = struct.unpack("<%di" % (len(minifat_data) // 4), minifat_data) if minifat_data else ()

    def read_stream(entry) -> bytes:
        if entry["size"] >= mini_cutoff:
            return chain(entry["start"], sector_bytes)[:entry["size"]]
        out = bytearray()
        sid, seen = entry["start"], 0
        while sid >= 0 and seen < 100000:
            out += mini_container[sid * mini_size:(sid + 1) * mini_size]
            sid = minifat[sid] if sid < len(minifat) else -1
            seen += 1
        return bytes(out[:entry["size"]])

    return entries, read_stream


def _read_ole_stream(file_path: str, stream_name: str) -> bytes | None:
    """Extract one named stream from an OLE2 compound file. Returns None if absent."""
    with open(file_path, "rb") as f:
        idx = _ole_index(f.read())
    if not idx:
        return None
    entries, read = idx
    target = next((e for e in entries if e["name"] == stream_name and e["type"] == 2), None)
    return read(target) if target else None


def _read_ole_streams(file_path: str, predicate) -> dict:
    """Return {name: bytes} for every stream whose name satisfies `predicate`."""
    with open(file_path, "rb") as f:
        idx = _ole_index(f.read())
    if not idx:
        return {}
    entries, read = idx
    return {e["name"]: read(e) for e in entries if e["type"] == 2 and predicate(e["name"])}


def _parse_lnk(data: bytes) -> dict | None:
    """Parse a Windows Shell Link (MS-SHLLINK) for target, arguments, and timestamps."""
    if len(data) < 0x4C or data[0:4] != b"\x4c\x00\x00\x00":
        return None
    try:
        flags = struct.unpack("<I", data[0x14:0x18])[0]
        ctime = struct.unpack("<Q", data[0x1C:0x24])[0]
        wtime = struct.unpack("<Q", data[0x2C:0x34])[0]
        fsize = struct.unpack("<I", data[0x34:0x38])[0]
        off = 0x4C

        # HasLinkTargetIDList (0x01): skip the shell item id list.
        if flags & 0x01:
            off += 2 + struct.unpack("<H", data[off:off + 2])[0]

        # HasLinkInfo (0x02): the LinkInfo structure carries the local base path.
        target = ""
        if flags & 0x02:
            li = off
            li_size = struct.unpack("<I", data[li:li + 4])[0]
            li_header = struct.unpack("<I", data[li + 4:li + 8])[0]
            li_flags = struct.unpack("<I", data[li + 8:li + 12])[0]
            if li_flags & 0x01:  # VolumeIDAndLocalBasePath present
                if li_header >= 0x24:  # unicode local base path
                    uoff = struct.unpack("<I", data[li + 0x1C:li + 0x20])[0]
                    if uoff:
                        s = li + uoff
                        end = data.find(b"\x00\x00", s)
                        target = data[s:end if end > 0 else s].decode("utf-16-le", "replace")
                if not target:  # ANSI local base path
                    boff = struct.unpack("<I", data[li + 0x10:li + 0x14])[0]
                    if boff:
                        s = li + boff
                        end = data.find(b"\x00", s)
                        enc = "mbcs" if os.name == "nt" else "latin-1"
                        target = data[s:end if end > 0 else s].decode(enc, "replace")
            off = li + li_size

        # StringData, in spec order: NAME / RELATIVE_PATH / WORKING_DIR / ARGUMENTS / ICON.
        unicode_strs = bool(flags & 0x80)

        def read_str() -> str:
            nonlocal off
            cnt = struct.unpack("<H", data[off:off + 2])[0]
            off += 2
            if unicode_strs:
                s = data[off:off + cnt * 2].decode("utf-16-le", "replace"); off += cnt * 2
            else:
                s = data[off:off + cnt].decode("latin-1", "replace"); off += cnt
            return s

        name = read_str() if flags & 0x04 else ""
        relative = read_str() if flags & 0x08 else ""
        working = read_str() if flags & 0x10 else ""
        args = read_str() if flags & 0x20 else ""
        if not target:
            target = relative or working
        return {"target": target, "arguments": args, "working_dir": working, "name": name,
                "file_size": fsize, "creation_time": filetime_to_iso(ctime),
                "write_time": filetime_to_iso(wtime)}
    except Exception:
        return None


def collect_defender(indicators: list[dict]) -> Result:
    res = Result("defender", ["category", "name", "value"])
    # Exclusions (tampering indicator).
    for cat in ("Paths", "Extensions", "Processes"):
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                 rf"SOFTWARE\Microsoft\Windows Defender\Exclusions\{cat}")
            for name, value, _ in _iter_values(key):
                res.add(f"exclusion:{cat}", name, value)
                indicators.append(_ind("defender", "high", f"Defender {cat} exclusion set: {name}", ""))
        except OSError:
            continue
    # Detection history files.
    hist = r"C:\ProgramData\Microsoft\Windows Defender\Scans\History\Service\Detections"
    if os.path.isdir(hist):
        for root_dir, _dirs, files in os.walk(hist):
            for fn in files:
                fp = os.path.join(root_dir, fn)
                try:
                    st = os.stat(fp)
                    res.add("detection_file", fp, f"{st.st_size} bytes @ {epoch_to_iso(st.st_mtime)}")
                    indicators.append(_ind("defender", "medium", f"Defender detection record: {fp}", ""))
                except OSError:
                    continue
    if not res.rows:
        log("defender: no exclusions/detections accessible (needs admin)")
    return res


def collect_acquire(name: str, src: str) -> Result:
    """Acquire a locked/binary artifact file (Amcache / SRUM) for offline analysis."""
    res = Result(name, ["artifact", "source_path", "size_bytes", "sha256", "status"])
    if not os.path.isfile(src):
        res.add(name, src, "", "", "not present")
        return res
    try:
        size = os.path.getsize(src)
        digest = sha256_file(src)
        res.add(name, src, size, digest, "readable - copy via VSS for full acquisition")
    except PermissionError:
        res.add(name, src, "", "", "locked/SYSTEM - acquire via VSS or offline (needs admin)")
    except Exception as exc:
        res.add(name, src, "", "", f"error: {exc}")
    return res


# --------------------------------------------------------------------------- #
# modern: AI / LLM, Windows Recall, cryptocurrency
# --------------------------------------------------------------------------- #

# Local AI/LLM tool footprints: (category, env-relative path).
AI_FOOTPRINTS = [
    ("ollama", "%USERPROFILE%\\.ollama"),
    ("ollama", "%LOCALAPPDATA%\\Programs\\Ollama"),
    ("lm_studio", "%USERPROFILE%\\.lmstudio"),
    ("lm_studio", "%APPDATA%\\LM Studio"),
    ("lm_studio", "%USERPROFILE%\\.cache\\lm-studio"),
    ("gpt4all", "%APPDATA%\\nomic.ai\\GPT4All"),
    ("gpt4all", "%LOCALAPPDATA%\\nomic.ai"),
    ("jan", "%USERPROFILE%\\jan"),
    ("jan", "%APPDATA%\\jan"),
    ("anythingllm", "%APPDATA%\\anythingllm-desktop"),
    ("msty", "%APPDATA%\\Msty"),
    ("claude_desktop", "%APPDATA%\\Claude"),
    ("chatgpt_desktop", "%APPDATA%\\ChatGPT"),
    ("chatgpt_desktop", "%LOCALAPPDATA%\\OpenAI"),
    ("copilot", "%LOCALAPPDATA%\\Microsoft\\Copilot"),
    ("perplexity", "%APPDATA%\\Perplexity"),
    ("cursor", "%APPDATA%\\Cursor"),
    ("text_gen_webui", "%USERPROFILE%\\text-generation-webui"),
]

# Config files worth scanning for leaked API keys (kept small + text only).
AI_KEY_FILES = [
    "%USERPROFILE%\\.env",
    "%USERPROFILE%\\.bashrc",
    "%USERPROFILE%\\.zshrc",
    "%USERPROFILE%\\.profile",
    "%USERPROFILE%\\.aws\\credentials",
    "%USERPROFILE%\\.config\\openai\\auth.json",
    "%APPDATA%\\Claude\\claude_desktop_config.json",
    "%USERPROFILE%\\.continue\\config.json",
    "%USERPROFILE%\\.ollama\\history",
]

# (provider, compiled-ish prefix). We never emit the full secret -- only redacted.
API_KEY_PATTERNS = [
    ("OpenAI", "sk-proj-"),
    ("OpenAI", "sk-"),
    ("Anthropic", "sk-ant-"),
    ("AWS", "AKIA"),
    ("Google", "AIza"),
    ("HuggingFace", "hf_"),
    ("GitHub", "ghp_"),
    ("Slack", "xoxb-"),
]


def _redact(secret: str) -> str:
    secret = secret.strip().strip("\"'")
    if len(secret) <= 10:
        return secret[:2] + "***"
    return f"{secret[:6]}...{secret[-4:]} (len {len(secret)})"


def collect_aiapps(indicators: list[dict]) -> Result:
    res = Result("ai_applications", ["category", "kind", "artifact", "detail", "modified_utc"])

    for category, raw in AI_FOOTPRINTS:
        path = os.path.expandvars(raw)
        if os.path.exists(path):
            try:
                st = os.stat(path)
                kind = "dir" if os.path.isdir(path) else "file"
                detail = ""
                if os.path.isdir(path):
                    try:
                        detail = f"{len(os.listdir(path))} item(s)"
                    except OSError:
                        detail = ""
                res.add(category, kind, path, detail, epoch_to_iso(st.st_mtime))
                indicators.append(_ind("aiapps", "medium", f"Local AI/LLM tool present: {category} ({path})",
                                       epoch_to_iso(st.st_mtime)))
            except OSError:
                continue

    # Ollama: enumerate pulled models from the manifest tree.
    ollama_manifests = os.path.expandvars("%USERPROFILE%\\.ollama\\models\\manifests")
    if os.path.isdir(ollama_manifests):
        for root_dir, _dirs, files in os.walk(ollama_manifests):
            for fn in files:
                model = os.path.relpath(os.path.join(root_dir, fn), ollama_manifests).replace("\\", "/")
                res.add("ollama", "model", model, "pulled model", "")

    # API key hunting (redacted) across known config files + discovered AI dirs.
    scanned = set()
    for raw in AI_KEY_FILES:
        _scan_keys(os.path.expandvars(raw), res, indicators, scanned)
    # Environment variables holding provider keys.
    for var in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "AWS_SECRET_ACCESS_KEY",
                "HUGGINGFACE_TOKEN", "HF_TOKEN", "GOOGLE_API_KEY", "GEMINI_API_KEY"):
        val = os.environ.get(var)
        if val:
            res.add("api_key", "env", var, _redact(val), "")
            indicators.append(_ind("aiapps", "high", f"API key in environment variable {var} ({_redact(val)})", ""))
    return res


def _scan_keys(path: str, res: Result, indicators: list[dict], scanned: set) -> None:
    if path in scanned or not os.path.isfile(path):
        return
    scanned.add(path)
    try:
        if os.path.getsize(path) > 1_000_000:
            return
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except Exception:
        return
    import re
    for provider, prefix in API_KEY_PATTERNS:
        for m in re.finditer(re.escape(prefix) + r"[A-Za-z0-9_\-]{12,}", text):
            secret = m.group(0)
            res.add("api_key", "file", path, f"{provider}: {_redact(secret)}", "")
            indicators.append(_ind("aiapps", "high", f"{provider} API key leaked in {path} ({_redact(secret)})", ""))
            break  # one finding per provider per file is enough


def collect_recall(indicators: list[dict]) -> list[Result]:
    """Windows 11 Recall: %LOCALAPPDATA%\\CoreAIPlatform.00\\UKP\\<guid>\\ukg.db + ImageStore."""
    meta = Result("windows_recall", ["artifact", "path", "detail", "modified_utc"])
    captures = Result("recall_window_captures", ["window_title", "app", "captured_utc", "ocr_excerpt"])
    local = os.environ.get("LOCALAPPDATA")
    if not local:
        return [meta, captures]
    base = os.path.join(local, "CoreAIPlatform.00", "UKP")
    if not os.path.isdir(base):
        log("recall: Windows Recall data not present on this host")
        return [meta, captures]

    indicators.append(_ind("recall", "high", "Windows Recall is enabled and storing snapshots (privacy/forensic goldmine)", ""))
    for guid in os.listdir(base):
        folder = os.path.join(base, guid)
        db = os.path.join(folder, "ukg.db")
        if os.path.isfile(db):
            st = os.stat(db)
            meta.add("ukg.db", db, f"{st.st_size} bytes, sha256={sha256_file(db)}", epoch_to_iso(st.st_mtime))
            _recall_parse(db, meta, captures, indicators)
        store = os.path.join(folder, "ImageStore")
        if os.path.isdir(store):
            try:
                imgs = [f for f in os.listdir(store) if os.path.isfile(os.path.join(store, f))]
                meta.add("ImageStore", store, f"{len(imgs)} captured screenshot(s)", "")
                indicators.append(_ind("recall", "high", f"Recall has captured {len(imgs)} screenshots in {store}", ""))
            except OSError:
                pass
    return [meta, captures]


def _recall_parse(db: str, meta: Result, captures: Result, indicators: list[dict]) -> None:
    """Read Recall window-capture rows + OCR text read-only without locking the live DB."""
    import sqlite3
    try:
        con = sqlite3.connect(f"file:{db}?mode=ro&immutable=1", uri=True)
        cur = con.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {r[0] for r in cur.fetchall()}
        for t in ("WindowCapture", "App", "WindowCaptureTextIndex_content"):
            if t in tables:
                try:
                    cur.execute(f"SELECT COUNT(*) FROM {t}")
                    meta.add("ukg.db:table", t, f"{cur.fetchone()[0]} row(s)", "")
                except sqlite3.Error:
                    pass

        # OCR text lives in an FTS content table; map it back to window captures by rowid.
        ocr = {}
        if "WindowCaptureTextIndex_content" in tables:
            try:
                cols = [c[1] for c in cur.execute("PRAGMA table_info(WindowCaptureTextIndex_content)")]
                textcol = next((c for c in cols if c.startswith("c")), None)
                if textcol:
                    for rid, text in cur.execute(f"SELECT id, {textcol} FROM WindowCaptureTextIndex_content"):
                        if text:
                            ocr[rid] = str(text)
            except sqlite3.Error:
                pass

        if "WindowCapture" in tables:
            wc_cols = {c[1] for c in cur.execute("PRAGMA table_info(WindowCapture)")}
            title_col = "WindowTitle" if "WindowTitle" in wc_cols else ("Name" if "Name" in wc_cols else None)
            time_col = next((c for c in ("TimeStamp", "Timestamp", "CaptureTime") if c in wc_cols), None)
            select = f"Id, {title_col or 'NULL'}, {time_col or 'NULL'} FROM WindowCapture ORDER BY Id DESC LIMIT 2000"
            for rid, title, ts in cur.execute("SELECT " + select):
                when = ""
                if ts:
                    try:
                        when = epoch_to_iso(int(ts) / 1000) if int(ts) > 1e12 else epoch_to_iso(int(ts))
                    except (ValueError, TypeError):
                        when = str(ts)
                excerpt = (ocr.get(rid, "") or "")[:300]
                captures.add(title or "", "", when, excerpt)
            if captures.rows:
                indicators.append(_ind("recall", "high",
                                       f"Extracted {len(captures.rows)} Recall window captures with OCR text", ""))
        con.close()
    except Exception as exc:
        meta.add("ukg.db", db, f"locked/unreadable live: {exc}", "")


# Cryptocurrency wallet footprints: (coin/app, env-relative path, is_wallet_file).
CRYPTO_FOOTPRINTS = [
    ("Bitcoin Core", "%APPDATA%\\Bitcoin\\wallet.dat", True),
    ("Electrum", "%APPDATA%\\Electrum\\wallets", True),
    ("Exodus", "%APPDATA%\\Exodus", True),
    ("Atomic", "%APPDATA%\\atomic", True),
    ("Ethereum keystore", "%APPDATA%\\Ethereum\\keystore", True),
    ("Litecoin", "%APPDATA%\\Litecoin\\wallet.dat", True),
    ("Dogecoin", "%APPDATA%\\Dogecoin\\wallet.dat", True),
    ("Monero", "%USERPROFILE%\\Documents\\Monero\\wallets", True),
    ("Ledger Live", "%APPDATA%\\Ledger Live", False),
    ("Trezor Suite", "%APPDATA%\\@trezor\\suite-desktop", False),
    ("Coinomi", "%LOCALAPPDATA%\\Coinomi\\Coinomi\\wallets", True),
    ("Guarda", "%APPDATA%\\Guarda", False),
    ("Jaxx Liberty", "%APPDATA%\\com.liberty.jaxx", False),
    ("Daedalus", "%APPDATA%\\Daedalus Mainnet", False),
]

# Browser-extension wallets: extension id -> name. Found under each Chromium profile's
# "Local Extension Settings\\<id>".
WALLET_EXTENSIONS = {
    "nkbihfbeogaeaoehlefnkodbefgpgknn": "MetaMask",
    "bfnaelmomeimhlpmgjnjophhpkkoljpa": "Phantom",
    "hnfanknocfeofbddgcijnmhnfnkdnaad": "Coinbase Wallet",
    "egjidjbpglichdcondbcbdnbeeppgdph": "Trust Wallet",
    "fhbohimaelbohpjbbldcngcnapndodjp": "Binance Wallet",
    "ibnejdfjmmkpcnlpebklmnkoeoihofec": "TronLink",
    "aiifbnbfobpmeekipheeijimdpnlpgpp": "Station (Terra)",
    "fnjhmkhhmkbjkkabndcnnogagogbneec": "Ronin Wallet",
}

# Chromium-family profile roots to inspect for wallet extensions.
CHROMIUM_PROFILE_ROOTS = [
    "%LOCALAPPDATA%\\Google\\Chrome\\User Data",
    "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data",
    "%LOCALAPPDATA%\\BraveSoftware\\Brave-Browser\\User Data",
    "%APPDATA%\\Opera Software\\Opera Stable",
]


def collect_crypto(indicators: list[dict]) -> Result:
    res = Result("cryptocurrency", ["category", "wallet", "path", "detail", "modified_utc"])

    for name, raw, is_wallet in CRYPTO_FOOTPRINTS:
        path = os.path.expandvars(raw)
        if os.path.exists(path):
            try:
                st = os.stat(path)
                detail = ""
                if os.path.isdir(path):
                    try:
                        detail = f"{len(os.listdir(path))} item(s)"
                    except OSError:
                        pass
                else:
                    detail = f"{st.st_size} bytes, sha256={sha256_file(path)}"
                res.add("wallet_app", name, path, detail, epoch_to_iso(st.st_mtime))
                sev = "high" if is_wallet else "medium"
                indicators.append(_ind("crypto", sev, f"Crypto wallet present: {name} ({path})",
                                       epoch_to_iso(st.st_mtime)))
            except OSError:
                continue

    # Browser-extension wallets.
    for raw_root in CHROMIUM_PROFILE_ROOTS:
        root = os.path.expandvars(raw_root)
        if not os.path.isdir(root):
            continue
        for profile in os.listdir(root):
            les = os.path.join(root, profile, "Local Extension Settings")
            if not os.path.isdir(les):
                continue
            for ext_id in os.listdir(les):
                if ext_id in WALLET_EXTENSIONS:
                    ext_path = os.path.join(les, ext_id)
                    try:
                        st = os.stat(ext_path)
                        mtime = epoch_to_iso(st.st_mtime)
                    except OSError:
                        mtime = ""
                    res.add("browser_wallet", WALLET_EXTENSIONS[ext_id],
                            ext_path, f"profile: {profile}", mtime)
                    indicators.append(_ind("crypto", "high",
                                           f"Browser wallet extension {WALLET_EXTENSIONS[ext_id]} in profile '{profile}'",
                                           mtime))
    return res


# --------------------------------------------------------------------------- #
# small registry / parsing utilities
# --------------------------------------------------------------------------- #

def _subkey_count(key) -> int:
    try:
        return winreg.QueryInfoKey(key)[0]
    except OSError:
        return 0


def _iter_values(key):
    i = 0
    while True:
        try:
            name, value, vtype = winreg.EnumValue(key, i)
        except OSError:
            break
        yield name, value, vtype
        i += 1


def _val(key, name):
    try:
        return winreg.QueryValueEx(key, name)[0]
    except OSError:
        return ""


def _ind(artifact: str, severity: str, detail: str, when: str) -> dict:
    return {"artifact": artifact, "severity": severity, "detail": detail, "timestamp_utc": when}


def _timeline_appid(raw) -> str:
    try:
        arr = json.loads(raw)
        for item in arr:
            app = item.get("application") or item.get("packageId")
            if app:
                return app
    except Exception:
        pass
    return str(raw)[:200]


def _timeline_text(payload) -> str:
    try:
        data = json.loads(payload)
        for k in ("displayText", "appDisplayName", "description"):
            if data.get(k):
                return str(data[k])[:300]
    except Exception:
        pass
    return ""


# A few well-known Jump List AppIDs (there are hundreds; this is a useful subset).
JUMPLIST_APPIDS = {
    "1bc392b8e104a00e": "Remote Desktop (mstsc.exe)",
    "5f7b5f1e01b83767": "Quick Access / Explorer",
    "9b9cdc69c1c24e2b": "Notepad",
    "12dc1ea8e34b5a6": "Windows Explorer",
    "f01b4d95cf55d32a": "Windows Explorer (pinned)",
    "7e4dca80246863e3": "Control Panel",
    "9839aff5631089f6": "Internet Explorer",
    "918e0ecb43d17e23": "Word",
    "a7bd71699cd38d1c": "PowerShell",
    "b8ffb8911e6c5c71": "Command Prompt",
}


# --------------------------------------------------------------------------- #
# output
# --------------------------------------------------------------------------- #

def write_result(res: Result, out_dir: str, output_type: str) -> None:
    if output_type == "json":
        records = [dict(zip(res.columns, r)) for r in res.rows]
        with open(os.path.join(out_dir, res.name + ".json"), "w", encoding="utf-8") as f:
            json.dump(records, f, indent=2, default=str)
    else:
        with open(os.path.join(out_dir, res.name + ".csv"), "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(res.columns)
            w.writerows(res.rows)


def write_indicators(indicators: list[dict], out_dir: str, output_type: str) -> None:
    cols = ["severity", "artifact", "detail", "timestamp_utc"]
    order = {"high": 0, "medium": 1, "low": 2}
    indicators = sorted(indicators, key=lambda d: order.get(d["severity"], 9))
    if output_type == "json":
        with open(os.path.join(out_dir, "_indicators.json"), "w", encoding="utf-8") as f:
            json.dump(indicators, f, indent=2)
    else:
        with open(os.path.join(out_dir, "_indicators.csv"), "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(cols)
            for ind in indicators:
                w.writerow([ind[c] for c in cols])


COLLECTORS = {
    "bam": lambda ind: collect_bam(ind),
    "shimcache": lambda ind: collect_shimcache(ind),
    "muicache": lambda ind: collect_muicache(ind),
    "recentapps": lambda ind: collect_recentapps(ind),
    "pshistory": lambda ind: collect_pshistory(ind),
    "timeline": lambda ind: collect_timeline(ind),
    "jumplists": lambda ind: collect_jumplists(ind),
    "defender": lambda ind: collect_defender(ind),
    "amcache": lambda ind: collect_acquire("amcache", r"C:\Windows\AppCompat\Programs\Amcache.hve"),
    "srum": lambda ind: collect_acquire("srum", r"C:\Windows\System32\sru\SRUDB.dat"),
    "aiapps": lambda ind: collect_aiapps(ind),
    "recall": lambda ind: collect_recall(ind),
    "crypto": lambda ind: collect_crypto(ind),
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Modern Windows artifact collector (Python 3)")
    parser.add_argument("--packages", required=True,
                        help="comma list: " + ",".join(PACKAGE_IDS) + " (or 'all')")
    parser.add_argument("--output_type", default="csv", choices=["csv", "json"])
    parser.add_argument("--output_dir", required=True)
    # accepted for CLI parity with FastIR; unused here
    parser.add_argument("--profile")
    parser.add_argument("--homedrive")
    parser.add_argument("--dump")
    args = parser.parse_args()

    print(r"""
  __  __         _              ___ ____
 |  \/  | ___   __| | ___ _ __ |_ _|  _ \
 | |\/| |/ _ \ / _` |/ _ \ '__| | || |_) |
 | |  | | (_) | (_| |  __/ |    | ||  _ <
 |_|  |_|\___/ \__,_|\___|_|   |___|_| \_\

   Modern Windows artifact collector (extends FastIR)
""", flush=True)

    if not IS_WINDOWS:
        log("WARNING: not running on Windows - live artifacts are unavailable on this host.")

    requested = [p.strip().lower() for p in args.packages.split(",") if p.strip()]
    if "all" in requested:
        requested = PACKAGE_IDS

    os.makedirs(args.output_dir, exist_ok=True)
    admin = is_admin()
    log(f"output directory: {args.output_dir}")
    log(f"output type: {args.output_type}")
    log(f"administrator: {admin}")
    log(f"packages: {', '.join(requested)}")

    indicators: list[dict] = []
    for pkg in requested:
        if pkg not in COLLECTORS:
            log(f"unknown package '{pkg}' - skipped")
            continue
        if pkg in ADMIN_ARTIFACTS and not admin:
            log(f"collecting '{pkg}' (note: best results require administrator)")
        else:
            log(f"collecting '{pkg}' ...")
        try:
            res = COLLECTORS[pkg](indicators)
            for r in (res if isinstance(res, list) else [res]):
                write_result(r, args.output_dir, args.output_type)
                log(f"wrote {r.name}: {len(r.rows)} row(s)")
        except Exception:
            log(f"ERROR collecting {pkg}:")
            print(traceback.format_exc(), flush=True)

    write_indicators(indicators, args.output_dir, args.output_type)
    high = sum(1 for i in indicators if i["severity"] == "high")
    log(f"triage indicators: {len(indicators)} ({high} high-severity)")
    log(f"Check here {os.path.abspath(args.output_dir)} for your results")
    return 0


if __name__ == "__main__":
    sys.exit(main())
