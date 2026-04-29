"""Discover live UPackages in the chunk pool and tabulate them.

Strategy
--------
1. Stride-scan a candidate region (default 0x85E30000-0x86200000) at stride 0x10
   for u64 == UPACKAGE_VTABLE.
2. For each hit, try all 4 UObject FName slots — slot 0..3 at obj+0x20+i*0x20.
   Decrypt each via the patch-20260428 slot pipeline (`fname_pipeline.slot_decrypt`)
   and resolve any plausible comp_index against the live FNamePool.
3. Keep candidates whose decoded name starts with '/' (i.e. UPackage path).

Counting children
-----------------
Run alongside `dump_objects.txt`: every UObject in there has its outer-chain
walked to a UPackage via `fname_pipeline.LiveResolver` + the existing dumper
chain. We DON'T do that here — we just emit the raw UPackage list. The SDK_Output
currently knows the outer pointer for each object indirectly: orphan-owner
addresses at heap ranges are themselves UPackages produced by chain-walking.

For child counts we use a different strategy: parse SDK_Output.txt for "// Class
.../Script/Foo." or "// Enum .../Foo." or "// Struct .../Foo." headers, and
match against package short names from the live scan. (Anything not in
SDK_Output but with a live UPackage = a missed package.)
"""

import argparse
import os
import re
import sys
import time

# Make sibling modules importable.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from memreader import MemReader, find_pid  # noqa: E402
from fname_pipeline import (  # noqa: E402
    MASK32, MODULE_BASE, slot_decrypt, LiveResolver,
)


UPACKAGE_VTABLE = 0x14AD8AE70  # observed at 0x85E30000/100/200/300, etc.


def is_module_ptr(p: int) -> bool:
    return MODULE_BASE <= p < MODULE_BASE + 0x10000000


def scan_upackages(mr, lo: int, hi: int, vtable: int = UPACKAGE_VTABLE,
                   stride: int = 0x10, batch: int = 0x10000) -> list[int]:
    """Stride-scan [lo, hi) for u64 == vtable. Returns list of addresses."""
    hits: list[int] = []
    a = lo
    while a < hi:
        chunk = min(batch, hi - a)
        try:
            buf = mr.read(a, chunk)
        except OSError:
            a += chunk
            continue
        # Walk u64 at stride.
        # Note: stride must be 8-aligned.
        for off in range(0, len(buf) - 7, stride):
            v = int.from_bytes(buf[off:off+8], "little")
            if v == vtable:
                hits.append(a + off)
        a += chunk
    return hits


def resolve_obj_name(mr, rv: LiveResolver, obj: int) -> str:
    """Try all 4 FName slots, return first plausible name string."""
    for slot in range(4):
        addr = obj + 0x20 + slot * 0x20
        try:
            enc = mr.read(addr, 16)
        except OSError:
            continue
        if not any(enc):
            continue
        dec = slot_decrypt(enc)
        ci = dec & MASK32
        hi = (dec >> 32) & MASK32
        # Try BOTH halves: comp_index can be in either lo or hi half.
        for v in (ci, hi):
            if 0 < v < 0x2000000:
                ptr = rv.resolve_name_ptr(v)
                if ptr:
                    name = rv.decrypt_name_string(ptr)
                    if name and 1 <= len(name) <= 256:
                        # Reject obvious garbage (unprintable etc.)
                        good = sum(1 for c in name if 32 <= ord(c) < 127)
                        if good >= 0.8 * len(name):
                            return name
    return ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, default=0)
    ap.add_argument("--lo", default="0x85E00000")
    ap.add_argument("--hi", default="0x86400000")
    ap.add_argument("--vtable", default=hex(UPACKAGE_VTABLE))
    ap.add_argument("--stride", type=lambda x: int(x, 0), default=0x10)
    ap.add_argument("--out", default="/tmp/upackages.txt")
    args = ap.parse_args()

    pid = args.pid or find_pid()
    if not pid:
        print("could not find game PID", file=sys.stderr)
        return 1

    lo = int(args.lo, 0)
    hi = int(args.hi, 0)
    vtable = int(args.vtable, 0)

    print(f"[+] PID={pid}  scan [0x{lo:X}, 0x{hi:X})  vtable=0x{vtable:X}  stride=0x{args.stride:X}")
    t0 = time.time()
    with MemReader(pid) as mr:
        rv = LiveResolver(mr)
        hits = scan_upackages(mr, lo, hi, vtable=vtable, stride=args.stride)
        print(f"[+] vtable hits: {len(hits)} (scan took {time.time()-t0:.1f}s)")

        results = []
        for i, obj in enumerate(hits):
            name = resolve_obj_name(mr, rv, obj)
            results.append((obj, name))
            if i < 20 or i % 200 == 0:
                print(f"  [{i:5d}] 0x{obj:016X}  {name!r}")

    pkgs = [(a, n) for a, n in results if n and n.startswith("/")]
    print(f"[+] valid UPackage names: {len(pkgs)} / {len(results)}")
    pkgs.sort(key=lambda x: x[1])
    with open(args.out, "w") as f:
        f.write(f"# UPackage scan @ {time.strftime('%Y-%m-%d %H:%M:%S')}  PID={pid}\n")
        f.write(f"# Region: 0x{lo:X}..0x{hi:X}  stride=0x{args.stride:X}  vtable=0x{vtable:X}\n")
        f.write(f"# count={len(pkgs)}\n")
        for a, n in pkgs:
            f.write(f"0x{a:016X}\t{n}\n")
    print(f"[+] wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
