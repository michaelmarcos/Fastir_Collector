"""Tests for modern_collector.py — pure parsers and heuristics (no live host needed)."""
import struct

import modern_collector as m


# --- helpers / heuristics ---------------------------------------------------

def test_filetime_conversion():
    assert m.filetime_to_iso(0) == ""
    iso = m.filetime_to_iso(132_223_104_000_000_000)  # ~2020
    assert iso.startswith("20") and "T" in iso


def test_epoch_conversion():
    assert m.epoch_to_iso(0) == ""
    assert m.epoch_to_iso(1_600_000_000).startswith("2020")


def test_suspect_path_and_exec():
    assert m.suspect_path(r"C:\Users\x\Downloads\a.iso") is True
    assert m.suspect_path(r"C:\Windows\System32\cmd.exe") is False
    # a document in a suspect dir is NOT flagged as exec; a script/binary is
    assert m.suspect_exec(r"C:\Users\x\Downloads\report.pdf") is False
    assert m.suspect_exec(r"C:\Users\x\Downloads\evil.exe") is True
    assert m.suspect_exec(r"C:\Users\x\AppData\Local\Temp\drop.ps1") is True


def test_redact_never_leaks_full_secret():
    red = m._redact("sk-ant-1234567890ABCDEFG")
    assert "1234567890ABCDEFG" not in red
    assert red.startswith("sk-ant") and "..." in red


# --- DestList parser (v1 layout) --------------------------------------------

def _build_destlist_v1(path: str, entry_no=7, access=5, ft=132_223_104_000_000_000) -> bytes:
    path_bytes = path.encode("utf-16-le")
    base = 0x20
    buf = bytearray(base + 0x72 + len(path_bytes))
    struct.pack_into("<I", buf, 0x00, 1)              # version 1
    struct.pack_into("<I", buf, 0x04, 1)              # 1 entry
    struct.pack_into("<I", buf, base + 0x58, entry_no)
    struct.pack_into("<I", buf, base + 0x64, access)
    struct.pack_into("<Q", buf, base + 0x68, ft)
    struct.pack_into("<H", buf, base + 0x70, len(path))
    buf[base + 0x72:base + 0x72 + len(path_bytes)] = path_bytes
    return bytes(buf)


def test_parse_destlist_v1():
    data = _build_destlist_v1(r"C:\Users\x\Downloads\evil.exe")
    out = m._parse_destlist(data)
    assert len(out) == 1
    e = out[0]
    assert e["entry"] == 7
    assert e["access_count"] == 5
    assert e["path"] == r"C:\Users\x\Downloads\evil.exe"
    assert e["last_access"].startswith("20")


def test_parse_destlist_empty_or_garbage():
    assert m._parse_destlist(b"") == []
    assert m._parse_destlist(b"\x06\x00\x00\x00" + b"\x00" * 8) == []


# --- LNK parser (no LinkInfo → falls back to relative path) -----------------

def _build_lnk_relative(rel: str, fsize=1234) -> bytes:
    HEADER = 0x4C
    buf = bytearray(HEADER)
    buf[0:4] = b"\x4c\x00\x00\x00"                    # ShellLinkHeader size/magic
    flags = 0x08 | 0x80                                # HasRelativePath | IsUnicode
    struct.pack_into("<I", buf, 0x14, flags)
    struct.pack_into("<I", buf, 0x34, fsize)          # FileSize
    rb = rel.encode("utf-16-le")
    buf += struct.pack("<H", len(rel)) + rb            # StringData: RELATIVE_PATH
    return bytes(buf)


def test_parse_lnk_relative_target():
    data = _build_lnk_relative(r"..\..\Downloads\payload.exe", fsize=4096)
    info = m._parse_lnk(data)
    assert info is not None
    assert info["target"] == r"..\..\Downloads\payload.exe"
    assert info["file_size"] == 4096


def test_parse_lnk_rejects_non_lnk():
    assert m._parse_lnk(b"not a shell link at all") is None


# --- package registry -------------------------------------------------------

def test_collectors_cover_all_packages():
    assert set(m.COLLECTORS) == set(m.PACKAGE_IDS)


def test_admin_artifacts_are_known():
    assert m.ADMIN_ARTIFACTS <= set(m.PACKAGE_IDS)
