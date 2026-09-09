#!/usr/bin/env python3
"""Dereference the suspect pointers at +0xB0/+0xB8 of a UEnum on v908 and
try to interpret them as UEnum::Names candidates (raw, decrypted-tag,
xor-stripped, etc.)."""
from __future__ import annotations
import os, sys, struct
sys.path.insert(0, os.path.dirname(__file__))
from memreader import MemReader

MODULE_BASE = 0x140000000

def try_read(mr, addr, size):
    try:
        return mr.read(addr, size)
    except OSError as e:
        return None

def dump_ptr(mr, tag, ptr):
    print(f"\n  {tag} = 0x{ptr:X}")
    for xor in (0, 1):  # strip low bit
        p = ptr & ~1
        if p != ptr:
            print(f"    (bit0-stripped -> 0x{p:X})")
        break
    d = try_read(mr, ptr & ~1, 64)
    if d is None:
        print(f"    unreadable")
        return
    print(f"    +0x00..3F: {d.hex()}")
    # Interpret as FName pair layout {CI(u32), Number(u32), Value(i64)}
    for stride in (0x10, 0x18):
        print(f"    as TPair<FName,int64> stride={stride}:")
        for j in range(min(4, 64 // stride)):
            ci = struct.unpack_from('<i', d, j * stride)[0]
            num = struct.unpack_from('<I', d, j * stride + 4)[0]
            val = struct.unpack_from('<q', d, j * stride + 8)[0]
            print(f"      [{j}] ci={ci} num={num} val={val}")

def probe(mr, addr, name):
    print(f"\n=== {name} @ 0x{addr:X} ===")
    buf = try_read(mr, addr, 0x200)
    if buf is None:
        print(f"  read fail")
        return
    # Interpret +0xB0..+0xC0 as different structures
    ptr1 = struct.unpack_from('<Q', buf, 0xB0)[0]
    ptr2 = struct.unpack_from('<Q', buf, 0xB8)[0]
    small = struct.unpack_from('<Q', buf, 0xC0)[0]
    tail = struct.unpack_from('<I', buf, 0xCC)[0]
    print(f"  +0xB0 raw = 0x{ptr1:X}")
    print(f"  +0xB8 raw = 0x{ptr2:X}")
    print(f"  +0xC0 (potential Num?) = {small}")
    print(f"  +0xCC = 0x{tail:X}")
    dump_ptr(mr, "+0xB0 deref", ptr1)
    dump_ptr(mr, "+0xB8 deref", ptr2)

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
        for name, addr in enums:
            probe(mr, addr, name)

if __name__ == '__main__':
    main()
