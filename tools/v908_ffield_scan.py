#!/usr/bin/env python3
"""Sweep candidate FField NamePrivate offsets + Next offsets against a
handful of known-good UStructs and score by decoded name plausibility."""
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
from memreader import MemReader
from v908_fname_probe import (
    MODULE_BASE, POOL_RVA, BLOCK_BASE_OFF, BLOCK_STRIDE,
    shard_hash_orig, slot_c1315578, dec_block1_padd, dec_block2_padd,
    fnv_chain, MASK64, KEYSTREAM_RVA,
)
from v908_slot_probe import pshufb8, rol64, resolve_fname, decrypt_string

# Known-good UStructs from live dump
CANDIDATE_STRUCTS = [
    0x7FFFDDFF0FA0,  # MaterialExpressionCustomOutput
    0x7FFFDDFF1E50,  # MaterialExpressionFirstPersonOutput
    0x7FFFDDFF3F60,  # MaterialProvider
    0x7FFFDDFF7870,  # Int16Property
    0x7FFFDDFF8720,  # UInt64Property
]

FFIELD_KEY = 0x0D58B9970DD2BBAF
FFIELD_MASK = [0x05, 0x06, 0x01, 0x04, 0x03, 0x07, 0x02, 0x00]

NP_CANDS = [0x50, 0x60, 0x68, 0x70, 0x78, 0x80, 0x88, 0x90, 0x98, 0xA0, 0xA8, 0xB0]
NEXT_CANDS = [0x40, 0x50, 0x60, 0x68, 0x78, 0x80, 0x100, 0x108, 0x110, 0x118, 0x120]
CHP_CANDS = [0xE0, 0xE8, 0xF0, 0xF8, 0x100, 0x108, 0x110, 0x118, 0x120, 0x128]


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


def is_engine_name(s):
    if not s or len(s) < 2 or len(s) > 80:
        return False
    if not all(32 <= b < 127 for b in s):
        return False
    # Real engine names are ASCII identifier-shaped
    try:
        return all(c.isalnum() or c in '_' for c in s.decode('ascii'))
    except:
        return False


def try_config(mr, ks, ustruct, chp_off, np_off, next_off, verbose=False):
    try:
        head = int.from_bytes(mr.read(ustruct + chp_off, 8), 'little')
    except OSError:
        return 0, []
    if head < 0x10000 or head >= 0x800000000000:
        return 0, []
    names = []
    cur = head
    visited = set()
    for i in range(64):
        if cur in visited: break
        visited.add(cur)
        try:
            enc = int.from_bytes(mr.read(cur + np_off, 8), 'little')
        except OSError:
            break
        dec = decode_ffield_name(enc)
        ci = dec & 0xFFFFFFFF
        num = dec >> 32
        if 0 <= ci < 5_000_000:
            entry = resolve_fname(mr, ci)
            name = decrypt_string(mr, entry, ks) if entry else None
            if name and is_engine_name(name):
                names.append((ci, num, name.decode('ascii')))
                if verbose:
                    print(f'    ff@0x{cur:X}+0x{np_off:02X}: ci={ci} num={num} name={name.decode("ascii")!r}')
        try:
            nxt = int.from_bytes(mr.read(cur + next_off, 8), 'little')
        except OSError:
            break
        if nxt < 0x10000 or nxt >= 0x800000000000:
            break
        cur = nxt
    # Score = DISTINCT names, not raw hits — filters out chain loops
    distinct = len({(ci, n) for ci, _, n in names})
    return distinct, names


def main():
    pid = int(sys.argv[1]) if len(sys.argv) > 1 else 297727
    with MemReader(pid) as mr:
        ks = mr.read(MODULE_BASE + KEYSTREAM_RVA, 512)
        results = []
        for chp_off in CHP_CANDS:
            for np_off in NP_CANDS:
                for next_off in NEXT_CANDS:
                    total = 0
                    for u in CANDIDATE_STRUCTS:
                        n, _ = try_config(mr, ks, u, chp_off, np_off, next_off)
                        total += n
                    if total > 0:
                        results.append((total, chp_off, np_off, next_off))
        results.sort(reverse=True)
        print('Top 15 (chp, name_off, next_off):')
        for t, chp, np, nx in results[:15]:
            print(f'  {t:4d} chp=0x{chp:03X} np=0x{np:02X} next=0x{nx:03X}')
        if results:
            _, chp, np, nx = results[0]
            print(f'\n=== Verbose dump: chp=0x{chp:X} np=0x{np:X} next=0x{nx:X} ===')
            for u in CANDIDATE_STRUCTS:
                print(f'\n[UStruct 0x{u:X}]')
                try_config(mr, ks, u, chp, np, nx, verbose=True)


if __name__ == '__main__':
    main()
