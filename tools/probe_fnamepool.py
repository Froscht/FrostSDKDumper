#!/usr/bin/env python3
"""Probe live ARC Raiders for FNamePool / FName key table candidates.

Reads from candidate RVAs, classifies each by structural shape:
- FNamePool: chunks array at +0xC8 stride 0x40, each chunk has heap (+0xD0 rel)
  and module-cache (+0xD8 rel) pointers.
- FName key table: 64 uint16, >=50 nonzero, no value repeating more than 6x.

Run as root (needs /dev/memreader).
"""
from __future__ import annotations

import json
import os
import struct
import sys
from collections import Counter
from pathlib import Path

ToolsDir = Path(__file__).resolve().parent
sys.path.insert(0, str(ToolsDir))
from memreader import MemReader, find_pid

ModuleBase = 0x140000000

FNamePoolCandidates = [
    ("config", 0xDBB3F80),
    ("old_20260428", 0xDB5BE80),
]
KeyTableCandidates = [
    ("sigscan", 0xDA4F130),
    ("config", 0xDB5D0B0),
]


def LooksLikeKeyTable(Buf128: bytes) -> tuple[bool, dict]:
    Words = struct.unpack("<128H", Buf128[:256])
    Nz = sum(1 for W in Words if W != 0)
    Counts = Counter(Words)
    Peak = max(Counts.values())
    PeakValue, _ = Counts.most_common(1)[0]
    return (Nz >= 50 and Peak <= 6), {
        "nonzero_of_128": Nz,
        "max_repeat": Peak,
        "peak_value_hex": f"0x{PeakValue:04X}",
        "first_8_u16": [f"0x{W:04X}" for W in Words[:8]],
    }


def ProbeFNamePool(Mr: MemReader, Va: int) -> dict:
    """Read up to 16 chunk slots starting at +0xC8 stride 0x40 and classify."""
    Result = {
        "va": f"0x{Va:X}",
        "header_first_8_qwords": [],
        "count_at_98": None,
        "chunks": [],
        "valid_chunks": 0,
        "is_fnamepool": False,
    }
    try:
        Header = Mr.read(Va, 0x100)
    except Exception as Exc:
        Result["error"] = f"read header: {Exc!r}"
        return Result
    Result["header_first_8_qwords"] = [
        f"0x{Q:016X}" for Q in struct.unpack("<8Q", Header[:64])
    ]
    Result["count_at_98"] = struct.unpack_from("<Q", Header, 0x98)[0]

    for I in range(16):
        Off = 0xC8 + I * 0x40
        try:
            Chunk = Mr.read(Va + Off, 0x40)
        except Exception:
            break
        CountLo, Maxn = struct.unpack_from("<II", Chunk, 0x00)
        HeapPtr, ModCache = struct.unpack_from("<QQ", Chunk, 0x08)
        Entry = {
            "index": I,
            "rel_offset": f"0x{Off:X}",
            "count_lo": CountLo,
            "max": Maxn,
            "heap_ptr": f"0x{HeapPtr:X}",
            "module_cache_ptr": f"0x{ModCache:X}",
        }
        # Validity: heap_ptr should look like a heap address (>= 0x10000000000) or
        # module address (~0x14xxxxxxxx). We accept both as "looks like a ptr".
        HeapValid = HeapPtr >= 0x10000000000 or 0x140000000 <= HeapPtr < 0x180000000
        ModValid = ModCache >= 0x10000000000 or 0x140000000 <= ModCache < 0x180000000
        if HeapValid and ModValid and Maxn in (0x7FF, 0x7FE, 0x800, 0x1000):
            Result["valid_chunks"] += 1
            # Read 64 bytes from chunk[0]'s heap ptr to confirm FNameEntry shape
            if I == 0:
                try:
                    Sample = Mr.read(HeapPtr, 64)
                    Entry["heap_first_64_hex"] = Sample.hex()
                except Exception as Exc:
                    Entry["heap_read_error"] = f"{Exc!r}"
                try:
                    SampleMc = Mr.read(ModCache, 64)
                    Entry["modcache_first_64_hex"] = SampleMc.hex()
                except Exception as Exc:
                    Entry["modcache_read_error"] = f"{Exc!r}"
        Result["chunks"].append(Entry)
        if not HeapValid and not ModValid and I > 2:
            break

    Result["is_fnamepool"] = Result["valid_chunks"] >= 2
    return Result


def ProbeKeyTable(Mr: MemReader, Va: int) -> dict:
    Result = {"va": f"0x{Va:X}"}
    try:
        Buf = Mr.read(Va, 256)
    except Exception as Exc:
        Result["error"] = f"read: {Exc!r}"
        return Result
    Ok, Stats = LooksLikeKeyTable(Buf)
    Result.update(Stats)
    Result["valid"] = Ok
    Words = struct.unpack("<128H", Buf)
    Result["first_4_u16"] = [f"0x{W:04X}" for W in Words[:4]]
    Result["first_8_u16"] = [f"0x{W:04X}" for W in Words[:8]]
    return Result


def Main() -> int:
    Pid = 0
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        P = int(entry)
        try:
            with open(f"/proc/{P}/comm") as F:
                if "GameThread" not in F.read():
                    continue
            with open(f"/proc/{P}/cmdline", "rb") as F:
                Cmd = F.read()
            if b"CrashReportClient" in Cmd:
                continue
            if b"PioneerGame" in Cmd or b"ArcRaiders" in Cmd:
                Pid = P
                break
            if Pid == 0:
                Pid = P
        except OSError:
            continue
    if Pid == 0:
        Pid = find_pid()
    if Pid == 0:
        print("ERROR: no GameThread PID found", file=sys.stderr)
        return 2
    print(f"# PID = {Pid}", file=sys.stderr)

    Out = {
        "pid": Pid,
        "module_base": f"0x{ModuleBase:X}",
        "fnamepool_candidates": [],
        "key_table_candidates": [],
    }

    with MemReader(Pid) as Mr:
        for Label, Rva in FNamePoolCandidates:
            Probe = ProbeFNamePool(Mr, ModuleBase + Rva)
            Probe["label"] = Label
            Probe["rva"] = f"0x{Rva:X}"
            Out["fnamepool_candidates"].append(Probe)
        for Label, Rva in KeyTableCandidates:
            Probe = ProbeKeyTable(Mr, ModuleBase + Rva)
            Probe["label"] = Label
            Probe["rva"] = f"0x{Rva:X}"
            Out["key_table_candidates"].append(Probe)

    # Pick verified
    Verified = {"fnamepool_rva": None, "key_table_rva": None,
                "first_chunks": [], "key_table_first": []}
    BestPool = None
    for C in Out["fnamepool_candidates"]:
        if C.get("is_fnamepool"):
            if BestPool is None or C["valid_chunks"] > BestPool["valid_chunks"]:
                BestPool = C
    if BestPool:
        Verified["fnamepool_rva"] = BestPool["rva"]
        Verified["first_chunks"] = [
            Ch["heap_ptr"] for Ch in BestPool["chunks"][:5]
        ]

    BestKey = None
    for C in Out["key_table_candidates"]:
        if C.get("valid"):
            if BestKey is None:
                BestKey = C
            elif C["label"] == "config":
                # Prefer config when both valid
                BestKey = C
    if BestKey:
        Verified["key_table_rva"] = BestKey["rva"]
        Verified["key_table_first"] = BestKey["first_4_u16"]

    Out["verified"] = Verified
    print(json.dumps(Out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(Main())
