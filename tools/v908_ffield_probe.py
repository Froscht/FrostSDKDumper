#!/usr/bin/env python3
"""FField NamePrivate offset + decoder probe.

Walks a UStruct's ChildProperties chain and tries multiple candidate
NamePrivate offsets. For each offset, decodes with the compile-time
Windows-verified PSHUFB+XOR+ROL16(13)+ROL64(32) pipeline and looks up
the CI in the FName pool. Picks the offset that yields the most
recognizable engine names ("bRegister", "bAllowTickOnDedicatedServer",
etc. — real Actor tick-function fields).
"""
from __future__ import annotations
import os, sys, random
sys.path.insert(0, os.path.dirname(__file__))
from memreader import MemReader, find_pid
from v908_fname_probe import (
    MODULE_BASE, POOL_RVA, BLOCK_BASE_OFF, BLOCK_STRIDE,
    shard_hash_orig, slot_c1315578, dec_block1_padd, dec_block2_padd,
    fnv_chain, MASK64, KEYSTREAM_RVA,
)
from v908_slot_probe import (
    decode_slot16, name_slot, class_slot, get_obj_name, decrypt_string,
    resolve_fname, SLOT_KEY_LO64, SLOT_PSHUF_MASK, pshuflw, pshufb8, rol64,
    STRIDE, OBJ_OFF, ITEMS_PER_CHUNK,
)

# Chunks-manager via handoff constants — decrypt shape is odd; we skip it and
# instead reuse the fact that the running dumper produced live objects. The
# simplest reliable path to a chunk-array pointer here is to read live-dumped
# object addresses from the dumper's own debug log — but we can also brute-scan
# the wine module for objects with known class names. Simpler: pass an object
# address on the command line, or read one from a probe log.

FFIELD_KEY = 0x0D58B9970DD2BBAF
FFIELD_MASK = [0x05, 0x06, 0x01, 0x04, 0x03, 0x07, 0x02, 0x00]
UOBJ_SLOT_STRIDE = 0x20
UOBJ_SLOT_BASE   = 0x20

# Candidate NamePrivate offsets to probe on the FField.
NAMEPRIVATE_CANDIDATES = [0x50, 0x60, 0x68, 0x70, 0x78, 0x80, 0x88, 0x90, 0x98,
                          0xA0, 0xA8, 0xB0, 0xB8, 0xC0]
# Candidate NEXT offsets to walk the chain.
NEXT_CANDIDATES = [0x60, 0x68, 0x78, 0x80, 0x100, 0x108, 0x110, 0x118, 0x120]


def rol16_perword(x, n):
    n &= 15
    if not n: return x
    out = 0
    for i in range(4):
        w = (x >> (i*16)) & 0xFFFF
        w = ((w << n) | (w >> (16-n))) & 0xFFFF
        out |= w << (i*16)
    return out


def decode_ffield_name(lo):
    x = pshufb8(lo, FFIELD_MASK) ^ FFIELD_KEY
    x = rol16_perword(x, 13)
    return rol64(x, 32)


def try_offset_pair(mr, ustruct_addr, name_off, next_off, ks, verbose=False):
    """Walk chain and score how many valid names come out."""
    head = 0
    # Try both +0x108 and +0x120 as UStruct::ChildProperties
    for chp_off in (0x108, 0x120, 0xE8, 0xF0, 0xF8):
        try:
            head = int.from_bytes(mr.read(ustruct_addr + chp_off, 8), 'little')
        except OSError:
            continue
        if 0x10000 < head < 0x800000000000:
            break
    if not head or head < 0x10000:
        return 0, []

    names = []
    cur = head
    visited = set()
    for i in range(64):
        if cur < 0x10000 or cur >= 0x800000000000:
            break
        if cur in visited:
            break
        visited.add(cur)
        try:
            enc = int.from_bytes(mr.read(cur + name_off, 8), 'little')
        except OSError:
            break
        dec = decode_ffield_name(enc)
        ci = dec & 0xFFFFFFFF
        if 0 < ci < 5_000_000:
            entry = resolve_fname(mr, ci)
            name = decrypt_string(mr, entry, ks)
            if name:
                try:
                    name_str = name.decode('utf-8')
                except:
                    name_str = str(name)
                if all(32 <= b < 127 for b in name):
                    names.append((ci, name_str))
                    if verbose:
                        print(f'  ff@0x{cur:X} name_off=0x{name_off:02X} ci={ci} name={name_str!r}')
        # advance
        try:
            nxt = int.from_bytes(mr.read(cur + next_off, 8), 'little')
        except OSError:
            break
        if nxt == cur: break
        cur = nxt
    return len(names), names


def main():
    pid = int(sys.argv[1]) if len(sys.argv) > 1 else find_pid()
    if not pid:
        sys.exit("no PID")
    print(f"[+] PID = {pid}")
    with MemReader(pid) as mr:
        ks = mr.read(MODULE_BASE + KEYSTREAM_RVA, 512)

        # Get UObject seed addresses. For now, brute-scan a heap range from a
        # known heap address (obtained from prior dumper log or /proc/pid/maps).
        # As a fallback, use an obvious wine heap start.
        # Read maps to find a big heap region.
        heap_regions = []
        with open(f'/proc/{pid}/maps') as f:
            for ln in f:
                parts = ln.split()
                if len(parts) < 2: continue
                rng, perms = parts[0], parts[1]
                if 'rw' not in perms: continue
                lo, hi = rng.split('-')
                lo = int(lo, 16); hi = int(hi, 16)
                sz = hi - lo
                if sz < 0x100000 or lo >= 0x800000000000: continue
                heap_regions.append((lo, hi))
        print(f'[+] {len(heap_regions)} rw regions')

        # Find candidate UStructs: objects whose class name is "Class",
        # "ScriptStruct", "Function". Sample offsets aligned to 0x10 in
        # heap regions and check if it looks like a UObject with a real name.
        candidates = []
        vt_lo = MODULE_BASE + 0x1000
        vt_hi = MODULE_BASE + 0x14000000
        random.seed(1)
        max_scan = 500000  # limit
        for base, hi in heap_regions[:20]:
            for off in range(0, min(hi - base, 0x20000000), 0x110):
                addr = base + off
                try:
                    vt = int.from_bytes(mr.read(addr, 8), 'little')
                except OSError:
                    break
                if not (vt_lo <= vt < vt_hi):
                    continue
                # Skip if InternalIndex+0x90 not sensible
                try:
                    idx = int.from_bytes(mr.read(addr + 0x90, 4), 'little')
                except OSError:
                    continue
                if idx == 0 or idx > 2_000_000:
                    continue
                name = get_obj_name(mr, addr, ks)
                if name is None or len(name) < 3:
                    continue
                try:
                    ns = name.decode()
                except:
                    continue
                # Interested in classes/structs whose OWN name would suggest a
                # UStruct instance (any class or struct).
                if ns and all(32 <= b < 127 for b in name):
                    candidates.append((addr, ns))
                    if len(candidates) >= 200:
                        break
            if len(candidates) >= 200:
                break
        print(f'[+] found {len(candidates)} UObject-shaped addresses')
        # print(f'    examples:', [c[1] for c in candidates[:10]])

        # For each NamePrivate offset candidate, try walking chains and count
        # non-garbage decoded property names.
        best_hits = 0
        best_off = None
        for name_off in NAMEPRIVATE_CANDIDATES:
            for next_off in NEXT_CANDIDATES:
                total = 0
                sampled = 0
                for addr, cname in candidates[:100]:
                    n, _names = try_offset_pair(mr, addr, name_off, next_off, ks)
                    sampled += 1
                    total += n
                if total > best_hits:
                    best_hits = total
                    best_off = (name_off, next_off)
                    print(f'  name_off=0x{name_off:02X} next_off=0x{next_off:02X}: {total} named fields across {sampled} structs')
        print(f'\n[+] Best: NamePrivate offset = 0x{best_off[0]:02X}, Next offset = 0x{best_off[1]:02X} ({best_hits} named fields)')

        # Verbose dump for winning pair on 3 candidate structs
        if best_off:
            print(f'\n=== Verbose dump for winning offsets ===')
            for addr, cname in candidates[:3]:
                print(f'\n[obj 0x{addr:X} class="{cname}"]')
                try_offset_pair(mr, addr, best_off[0], best_off[1], ks, verbose=True)


if __name__ == '__main__':
    main()
