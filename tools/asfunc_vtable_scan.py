"""AngelScript vtable heap scan (fast).

Scans rw- regions of the live PioneerGame process for known AngelScript
metaclass vtables (ASClass / ASFunction_*_JIT / ASFunction_* / ASStruct)
and counts how many object instances point to each vtable.

Uses numpy for vectorized 8-byte aligned compare — covers ~100 GB of
heap in minutes.
"""
import os
import re
import sys
import struct
from collections import defaultdict, Counter

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from memreader import MemReader, find_pid

MODULE_BASE = 0x140000000

AS_VTABLES = {
    0x14B8A9180: "ASClass",
    0x14B8A9A60: "ASFunction_NotThreadSafe",
    0x14B8A9E80: "ASFunction_NoParams",
    0x14B8AAF20: "ASFunction_FloatExtendedToDoubleArg",
    0x14B8ABBA0: "ASFunction_ByteArg",
    0x14B8ABFD0: "ASFunction_ReferenceArg",
    0x14B8AC400: "ASFunction_ObjectReturn",
    0x14B8AD490: "ASFunction_ByteReturn",
    0x14B8AD8A0: "ASFunction_JIT",
    0x14B8ADCD0: "ASFunction_NotThreadSafe_JIT",
    0x14B8AE100: "ASFunction_NoParams_JIT",
    0x14B8AE530: "ASFunction_DWordArg_JIT",
    0x14B8AE960: "ASFunction_QWordArg_JIT",
    0x14B8AED90: "ASFunction_FloatArg_JIT",
    0x14B8AF1E0: "ASFunction_FloatExtendedToDoubleArg_JIT",
    0x14B8AF630: "ASFunction_FloatExtendedToDoubleReturn_JIT",
    0x14B8AFA60: "ASFunction_DoubleArg_JIT",
    0x14B8AFE80: "ASFunction_ByteArg_JIT",
    0x14B8B02B0: "ASFunction_ReferenceArg_JIT",
    0x14B8B06E0: "ASFunction_ObjectReturn_JIT",
    0x14B8B0B10: "ASFunction_DoubleReturn_JIT",
    0x14B8B0F40: "ASFunction_FloatReturn_JIT",
    0x14B8B1370: "ASFunction_DWordReturn_JIT",
    0x14B8B17A0: "ASFunction_ByteReturn_JIT",
    0x14B8B2420: "ASStruct",
}

# Compute lo/hi bounds — all targets fall in 0x14B8A9180..0x14B8B2420
TGT_LO = min(AS_VTABLES.keys())
TGT_HI = max(AS_VTABLES.keys())


def parse_maps(pid: int):
    rgs = []
    with open(f"/proc/{pid}/maps") as f:
        for line in f:
            m = re.match(r"([0-9a-f]+)-([0-9a-f]+) (\S+)", line)
            if not m:
                continue
            s, e, p = int(m.group(1), 16), int(m.group(2), 16), m.group(3)
            if not (p[0] == 'r' and p[1] == 'w'):
                continue
            sz = e - s
            if sz < 0x10000 or sz > 0xC800000:
                continue
            if s >= MODULE_BASE and s < MODULE_BASE + 0x10000000:
                continue
            rgs.append((s, e, sz))
    return rgs


def scan(pid: int):
    rgs = parse_maps(pid)
    total_bytes = sum(r[2] for r in rgs)
    print(f"[scan] {len(rgs)} regions, {total_bytes/1024/1024:.0f} MB", flush=True)

    counts = Counter()
    addr_min = defaultdict(lambda: 1 << 64)
    addr_max = defaultdict(int)

    CHUNK = 0x400000  # 4 MB
    target_set = np.array(sorted(AS_VTABLES.keys()), dtype=np.uint64)
    target_to_name = {v: AS_VTABLES[int(v)] for v in target_set}

    with MemReader(pid) as mr:
        scanned = 0
        last_pct = -1
        regions_done = 0
        skipped_regions = 0
        for (lo, hi, sz) in rgs:
            base = lo
            while base < hi:
                want = min(CHUNK, hi - base)
                # Align want to 8 bytes
                want_aligned = want & ~7
                if want_aligned == 0:
                    base += want
                    scanned += want
                    continue
                try:
                    buf = mr.read(base, want_aligned)
                except OSError:
                    base += want
                    scanned += want
                    skipped_regions += 1
                    continue
                # View as uint64
                arr = np.frombuffer(buf, dtype=np.uint64)
                # Coarse filter: TGT_LO <= x <= TGT_HI
                mask = (arr >= TGT_LO) & (arr <= TGT_HI)
                if mask.any():
                    cands = arr[mask]
                    cand_offs = np.nonzero(mask)[0] * 8
                    # Match exact
                    in_set = np.isin(cands, target_set)
                    for i, ok in enumerate(in_set):
                        if not ok:
                            continue
                        v = int(cands[i])
                        addr = base + int(cand_offs[i])
                        name = target_to_name[np.uint64(v)]
                        counts[name] += 1
                        if addr < addr_min[name]:
                            addr_min[name] = addr
                        if addr > addr_max[name]:
                            addr_max[name] = addr
                base += want_aligned
                scanned += want_aligned
                pct = int(scanned * 100 / total_bytes)
                if pct != last_pct and pct % 5 == 0:
                    print(f"  {pct:3d}% scanned ({scanned/1024/1024:.0f} MB) "
                          f"hits so far: {sum(counts.values())}",
                          flush=True)
                    last_pct = pct
            regions_done += 1

    print(f"[scan] regions done={regions_done} skipped={skipped_regions}", flush=True)
    print()
    print(f"{'Class':<46} {'Count':>7} {'Lo':>10} {'Hi':>10}")
    print("-" * 78)
    func_total = 0
    class_total = 0
    struct_total = 0
    for vt in sorted(AS_VTABLES.keys()):
        name = AS_VTABLES[vt]
        c = counts[name]
        lo = addr_min[name] if c else 0
        hi = addr_max[name] if c else 0
        print(f"{name:<46} {c:>7} {lo:>10x} {hi:>10x}")
        if name.startswith("ASFunction"):
            func_total += c
        elif name == "ASClass":
            class_total += c
        elif name == "ASStruct":
            struct_total += c
    print("-" * 78)
    print(f"Total ASFunction*: {func_total}")
    print(f"Total ASClass:     {class_total}")
    print(f"Total ASStruct:    {struct_total}")


if __name__ == "__main__":
    pid = int(sys.argv[1]) if len(sys.argv) > 1 else find_pid()
    print(f"[scan] pid={pid}")
    scan(pid)
