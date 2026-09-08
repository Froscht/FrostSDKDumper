#!/usr/bin/env python3
"""Sweep many CIs against the v908 resolver and report which land in the
pool. If NONE land in pool, the shard/block/FNV shape is wrong. If SOME
land, the geometry (pool_rva or seed_off) may be right but the decode has
a defect on certain slots.
"""
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
from memreader import MemReader, find_pid
from v908_fname_probe import (
    MODULE_BASE, POOL_RVA, BLOCK_BASE_OFF, BLOCK_STRIDE,
    shard_hash_orig, slot_c1315578,
    dec_block1_padd, dec_block2_padd, fnv_chain,
    MASK64, header_looks_like,
)

def probe(mr, ci):
    chunk_off = ((ci >> 8) & 0xFFFF00)
    name_off = ci & 0xFFFF
    chunk_addr = MODULE_BASE + POOL_RVA + chunk_off
    seed = chunk_addr + 0x2490
    T = shard_hash_orig(seed)
    b1 = slot_c1315578(T)
    b2 = (b1 + 1) & 7
    try:
        raw1 = int.from_bytes(mr.read(chunk_addr + BLOCK_BASE_OFF + BLOCK_STRIDE * b1, 8), 'little')
        raw2 = int.from_bytes(mr.read(chunk_addr + BLOCK_BASE_OFF + BLOCK_STRIDE * b2, 8), 'little')
    except OSError:
        return None
    V13 = dec_block1_padd(raw1)
    V15 = dec_block2_padd(raw2)
    Fv2 = fnv_chain(V13)
    Entry = (V13 + (V15 ^ Fv2) + 2 * name_off) & MASK64
    return Entry, V13, V15, Fv2, b1, b2


def main():
    pid = int(sys.argv[1]) if len(sys.argv) > 1 else find_pid()
    with MemReader(pid) as mr:
        pool_lo = MODULE_BASE + POOL_RVA
        pool_hi = pool_lo + 0x100000000  # 4 GiB window
        module_hi = MODULE_BASE + 0x20000000
        in_pool = in_module = readable = 0
        first_in_pool = []
        for ci in range(0, 1024):
            r = probe(mr, ci)
            if r is None:
                continue
            Entry, V13, V15, Fv2, b1, b2 = r
            v15_eq_fv2 = (V15 == Fv2)
            if pool_lo <= Entry < pool_hi:
                in_pool += 1
                if len(first_in_pool) < 8:
                    first_in_pool.append((ci, Entry, V13, V15, Fv2, v15_eq_fv2))
            elif MODULE_BASE <= Entry < module_hi:
                in_module += 1
            elif 0x10000 <= Entry < 0x800000000000:
                readable += 1
        print(f"[stats] CI 0..1024: in_pool={in_pool} in_module={in_module} other={readable}")
        for ci, E, V13, V15, Fv2, eq in first_in_pool:
            print(f"  CI={ci:5d} Entry=0x{E:016X}  V13=0x{V13:X}  V15==FV2:{eq}")

        # Also test: is V15 always == FV2? That would explain everything.
        eq_count = 0
        for ci in range(0, 512):
            r = probe(mr, ci)
            if r and r[2] == r[3]:  # V15 == FV2
                eq_count += 1
        print(f"[degeneracy] V15==FV2 held for {eq_count}/512 CIs")


if __name__ == '__main__':
    main()
