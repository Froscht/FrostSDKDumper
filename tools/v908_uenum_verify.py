#!/usr/bin/env python3
"""Verify the struct-of-arrays UEnum::Names layout on v908.

Hypothesis found by probing:
  +0xB0 -> pointer (odd, strip bit 0) to array of u64 name entries — each
          is an FName {CI(u32), Number(u32)} stored inline.
  +0xB8 -> pointer (odd, strip bit 0) to array of i64 values.
  +0xC0 -> Num (u32 or u64).

Resolve the first few CIs via the v908 FName pipeline and check they yield
plausible enum entry names.
"""
from __future__ import annotations
import os, sys, struct
sys.path.insert(0, os.path.dirname(__file__))
from memreader import MemReader

# reuse v908 resolver from the sibling probe module
from v908_uenum_probe import (
    resolve_name, load_keystream, MODULE_BASE
)

def probe(mr, addr, name, keytable):
    print(f"\n=== {name} @ 0x{addr:X} ===")
    buf = mr.read(addr, 0x100)
    key_ptr = struct.unpack_from('<Q', buf, 0xB0)[0] & ~1
    val_ptr = struct.unpack_from('<Q', buf, 0xB8)[0] & ~1
    num32   = struct.unpack_from('<I', buf, 0xC0)[0]
    num64   = struct.unpack_from('<Q', buf, 0xC0)[0]
    print(f"  KeysPtr = 0x{key_ptr:X}")
    print(f"  ValsPtr = 0x{val_ptr:X}")
    print(f"  Num32   = {num32}    Num64 = {num64}")

    if num32 <= 0 or num32 > 512:
        print(f"  bad num, skipping")
        return

    keys = mr.read(key_ptr, num32 * 8)
    vals = mr.read(val_ptr, num32 * 8)
    print(f"  Entries:")
    for i in range(num32):
        ci = struct.unpack_from('<i', keys, i * 8)[0]
        num = struct.unpack_from('<I', keys, i * 8 + 4)[0]
        val = struct.unpack_from('<q', vals, i * 8)[0]
        nm = resolve_name(mr, ci, keytable)
        if nm is None:
            nm = f"<CI={ci} unresolved>"
        # Include _Number-1 suffix if Number != 0
        if num and num < 0x100000:
            nm = f"{nm}_{num-1}"
        print(f"    [{i:>3}] {nm:40s} = {val}")

def main():
    pid = int(sys.argv[1]) if len(sys.argv) > 1 else 97340
    enums = [
        ("EPhysicalSurface",  0x7FFFDE7AAE30),
        ("ETickingGroup",     0x7FFFDE713970),
        ("ETraceTypeQuery",   0x7FFFDE71A8E0),
        ("ECollisionChannel", 0x7FFFDE7BF890),
        ("EViewModeIndex",    0x7FFFDE7FB6F0),
    ]
    with MemReader(pid) as mr:
        keytable = load_keystream(mr)
        print(f"[+] CI=0 -> {resolve_name(mr, 0, keytable)!r}")
        for name, addr in enums:
            probe(mr, addr, name, keytable)

if __name__ == '__main__':
    main()
