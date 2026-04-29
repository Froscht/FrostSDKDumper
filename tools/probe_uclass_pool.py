"""Probe the UClass chunk-pool region to discover UClass-shaped objects.

Scans 0x77000000..0x90000000 at stride 8 looking for vtable-prefixed objects
that the GUObjectArray scan doesn't reach.

A UClass-shaped object has:
  - First u64 (vtable) in the module range [0x140000000, 0x160000000)
  - The vtable itself is one of a small number of recurring values

Usage:
    sudo python3 probe_uclass_pool.py [--start HEX] [--end HEX] [--stride N]
"""
import argparse
import os
import sys
import struct
from collections import defaultdict, Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from memreader import MemReader, find_pid
from fname_pipeline import (
    LiveResolver, MODULE_BASE, slot_decrypt, slot_picker, MASK32,
    RVA_GUOBJECT_ARRAY,
)

MOD_LO = 0x140000000
MOD_HI = 0x160000000


def is_module_ptr(p):
    return MOD_LO <= p < MOD_HI


def is_heap_ptr(p):
    return 0x10000000 <= p < 0x800000000000


def scan_vtables(mr, start, end, stride=0x10, bulk=0x10000):
    """Sweep [start, end) at given stride. Return Counter of vtable values."""
    vt_counts = Counter()
    # Bulk-read with up to 'bulk' bytes per ioctl, then iterate at stride.
    addr = start
    while addr < end:
        chunk = min(bulk, end - addr)
        try:
            data = mr.read(addr, chunk)
        except Exception:
            addr += chunk
            continue
        # We want u64 reads at stride
        for off in range(0, chunk - 7, stride):
            v = struct.unpack_from("<Q", data, off)[0]
            if is_module_ptr(v):
                vt_counts[v] += 1
        addr += chunk
    return vt_counts


def walk_outer(mr, addr, max_depth=8, slot_offsets=(0x20, 0x40, 0x60, 0x80)):
    """Walk an object's pointer-shaped slots looking for an Outer chain."""
    visited = set()
    cur = addr
    chain = [cur]
    for _ in range(max_depth):
        if cur in visited:
            break
        visited.add(cur)
        # Try all 4 slot offsets in case it's not a UObject layout we recognise
        outer = 0
        for off in slot_offsets:
            try:
                enc = mr.read(cur + off, 16)
            except Exception:
                continue
            if not any(enc):
                continue
            dec = slot_decrypt(enc)
            hi = (dec >> 32) & MASK32
            # Reinterpret hi32 plus first u64 from vtable region as candidate ptr...
            # Easier: read the raw qwords at slot offsets — heap pointers
            # often live in raw form too.
        # Actually slot decode is for FName CIs, not Outer pointers.
        break
    return chain


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--start", default="0x77000000")
    ap.add_argument("--end",   default="0x90000000")
    ap.add_argument("--stride", default="0x10")
    ap.add_argument("--top", type=int, default=30)
    ap.add_argument("--pid", type=int, default=0)
    args = ap.parse_args()

    start  = int(args.start, 0)
    end    = int(args.end, 0)
    stride = int(args.stride, 0)

    pid = args.pid or find_pid("GameThread")
    if not pid:
        print("[-] no PID")
        return 1
    print(f"[+] pid={pid}  scan 0x{start:X}..0x{end:X}  stride=0x{stride:X}")

    with MemReader(pid) as mr:
        vt = scan_vtables(mr, start, end, stride=stride)

    print(f"[+] hits: {sum(vt.values())}  unique vtables: {len(vt)}")
    print(f"\n=== top {args.top} vtables ===")
    for v, c in vt.most_common(args.top):
        rva = v - MOD_LO
        print(f"  vtable=0x{v:016X}  rva=0x{rva:08X}  count={c}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
