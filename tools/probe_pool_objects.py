"""Sample N UClass-shaped objects from the unscanned pool, decode their
NamePrivate FName slot, and walk OuterPrivate to learn the package.

UClass vtable rva: 0x0AD6D440 (verified via dump_classes).
ScriptStruct vtable rva: 0x0AD6CB80
Enum vtable rva: 0x0AD6FF30
Function vtable rva: 0x0AD6D980
Package vtable rva: 0x0AD8AE70
BPGenClass vtable rva: 0x0B527FC0
"""
import argparse
import os
import sys
import struct
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from memreader import MemReader, find_pid
from fname_pipeline import (
    LiveResolver, MODULE_BASE, slot_decrypt, slot_picker, MASK32,
)

MOD_LO = 0x140000000
MOD_HI = 0x160000000

VT_KIND = {
    0x140000000 + 0xAD6D440: "Class",
    0x140000000 + 0xAD6CB80: "ScriptStruct",
    0x140000000 + 0xAD6FF30: "Enum",
    0x140000000 + 0xAD6D980: "Function",
    0x140000000 + 0xAD8AE70: "Package",
    0x140000000 + 0xB527FC0: "BlueprintGeneratedClass",
}


def decode_pointer_slots(mr, obj_addr):
    """Return list of (slot, decrypted_ptr, ptr_vtable_kind) for all 4 slots
    where the slot decodes to a heap pointer (hi32 ≥ 0x10000)."""
    out = []
    for slot in range(4):
        try:
            enc = mr.read(obj_addr + 0x20 + slot * 0x20, 16)
        except Exception:
            continue
        if not any(enc):
            continue
        dec = slot_decrypt(enc)
        lo = dec & MASK32
        hi = (dec >> 32) & MASK32
        if hi < 0x10000:
            continue  # FName-shaped
        ptr = (lo << 32) | hi
        if ptr < 0x100000 or ptr >= 0x800000000000:
            continue
        try:
            vt = mr.read_u64(ptr)
        except Exception:
            continue
        out.append((slot, ptr, vt, VT_KIND.get(vt, "?")))
    return out


def decode_fname_slot_ci(mr, obj_addr):
    """Return list of (slot, ci) for FName-shaped slots."""
    out = []
    for slot in range(4):
        try:
            enc = mr.read(obj_addr + 0x20 + slot * 0x20, 16)
        except Exception:
            continue
        if not any(enc):
            continue
        dec = slot_decrypt(enc)
        lo = dec & MASK32
        hi = (dec >> 32) & MASK32
        if hi >= 0x10000:
            continue  # pointer-shaped
        if 0 < lo < 0x2000000:
            out.append((slot, lo))
    return out


def get_object_name(mr, rv, obj_addr):
    cands = decode_fname_slot_ci(mr, obj_addr)
    for slot, ci in cands:
        ptr = rv.resolve_name_ptr(ci)
        if not ptr:
            continue
        name = rv.decrypt_name_string(ptr)
        if name and all(0x20 <= ord(c) <= 0x7E for c in name):
            return name
    return ""


def walk_outer_to_package(mr, rv, obj_addr, max_depth=12):
    """Walk pointer slots until we reach a Package (or terminate)."""
    seen = {obj_addr}
    cur = obj_addr
    chain = []
    for _ in range(max_depth):
        slot_decodes = decode_pointer_slots(mr, cur)
        # Pick a Package preferentially, otherwise a Class/SS/Enum/Function/...
        # Skip pointers that are vtable-of-meta itself (those would mean current
        # IS the metaclass; we already past it).
        # The OuterPrivate is a slot whose decoded ptr's vtable is in our metaclass
        # set BUT distinct from the ClassPrivate slot.
        # Heuristic: if there's a Package among decodes -> take it.
        pkgs = [(s, p, vt, k) for s, p, vt, k in slot_decodes if k == "Package"]
        if pkgs:
            cur = pkgs[0][1]
            chain.append(("Package", cur))
            return cur, chain
        # Otherwise pick the first not-yet-seen heap-pointer that has a vtable
        # in VT_KIND set.
        progressed = False
        for s, p, vt, k in slot_decodes:
            if p in seen:
                continue
            if k == "?":
                continue
            seen.add(p)
            cur = p
            chain.append((k, p))
            progressed = True
            break
        if not progressed:
            return cur, chain
    return cur, chain


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--start", default="0x77000000")
    ap.add_argument("--end",   default="0x80000000")
    ap.add_argument("--stride", default="0x10")
    ap.add_argument("--max-samples", type=int, default=50)
    args = ap.parse_args()

    pid = find_pid("GameThread")
    print(f"[+] pid={pid}")

    start = int(args.start, 0)
    end   = int(args.end, 0)
    stride = int(args.stride, 0)

    UCLASS_VT = 0x140000000 + 0xAD6D440

    found_uclasses = []

    with MemReader(pid) as mr:
        rv = LiveResolver(mr)
        addr = start
        BULK = 0x100000
        while addr < end:
            try:
                data = mr.read(addr, min(BULK, end - addr))
            except Exception:
                addr += BULK
                continue
            for off in range(0, len(data) - 8, stride):
                v = struct.unpack_from("<Q", data, off)[0]
                if v == UCLASS_VT:
                    found_uclasses.append(addr + off)
            addr += BULK

        print(f"[+] Found {len(found_uclasses)} UClass-vtable objects in 0x{start:X}..0x{end:X}")

        per_pkg = Counter()
        sample_lines = []
        for ua in found_uclasses[:args.max_samples]:
            name = get_object_name(mr, rv, ua)
            pkg_addr, chain = walk_outer_to_package(mr, rv, ua)
            pkg_name = get_object_name(mr, rv, pkg_addr) if pkg_addr != ua else ""
            per_pkg[pkg_name] += 1
            chain_repr = " -> ".join(f"{k}@0x{p:X}" for k, p in chain[:4])
            sample_lines.append(
                f"  0x{ua:012X}  name={name!r:36s}  pkg=0x{pkg_addr:X}  pkg_name={pkg_name!r:30s}  chain={chain_repr}"
            )

        print(f"\n=== {len(sample_lines)} sample UClass instances ===")
        for line in sample_lines[:60]:
            print(line)

        print(f"\n=== package tally ===")
        for p, c in per_pkg.most_common():
            print(f"  {c:5d}  {p!r}")


if __name__ == "__main__":
    main()
