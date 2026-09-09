#!/usr/bin/env python3
"""Dump the raw bytes of a known UEnum object and show every plausible
{Data(u64), Num(u32), Max(u32)} triple at 4-byte-aligned offsets.

Root required (uses /dev/memreader).
"""
from __future__ import annotations
import os, sys, struct
sys.path.insert(0, os.path.dirname(__file__))
from memreader import MemReader

MODULE_BASE = 0x140000000

def probe(mr, addr, name):
    print(f"\n=== {name} @ 0x{addr:X} ===")
    try:
        buf = mr.read(addr, 0x200)
    except OSError as e:
        print(f"  read fail: {e}")
        return
    # Print raw bytes 0x00..0x180 in 16-byte rows
    print("  Raw bytes:")
    for row in range(0, 0x180, 16):
        hex_part = ' '.join(f'{b:02X}' for b in buf[row:row+16])
        print(f"    +{row:03X}: {hex_part}")

    print("\n  Pointer-shaped u64 slots (0x60..0x180):")
    for off in range(0x60, 0x180, 8):
        (v,) = struct.unpack_from('<Q', buf, off)
        if 0x10000 < v < 0x800000000000:
            in_mod = MODULE_BASE <= v < MODULE_BASE + 0x15000000
            tag = ' (in-module)' if in_mod else ''
            print(f"    +0x{off:03X}: 0x{v:016X}{tag}")

    print("\n  {u64,u32,u32} triples with any plausible {Data,Num,Max}:")
    for off in range(0x60, 0x160, 4):
        if off + 16 > len(buf):
            break
        data, num, max_ = struct.unpack_from('<QII', buf, off)
        # Loose gate: any heap ptr + small counts
        if not (0x10000 < data < 0x800000000000):
            continue
        if MODULE_BASE <= data < MODULE_BASE + 0x15000000:
            continue
        if not (0 < num < 4096):
            continue
        if not (num <= max_ < 8192):
            continue
        print(f"    +0x{off:03X}: Data=0x{data:X} Num={num} Max={max_}")
        # peek first 32 bytes at Data
        try:
            head = mr.read(data, 32)
            print(f"        first32: {head.hex()}")
        except OSError:
            print("        (unreadable)")


def main():
    pid = int(sys.argv[1]) if len(sys.argv) > 1 else 97340
    print(f"[+] PID = {pid}")
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
