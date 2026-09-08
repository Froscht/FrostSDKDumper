#!/usr/bin/env python3
"""Live probe for the v908 FName pipeline.

Reads live game memory (via /dev/memreader) and tries every plausible variation
of the shard hash + block decode + FNV chain until CI=0 decodes to something
that looks like the "None" entry (short header, printable ASCII 'N','o','n','e'
after string decrypt, or at least a header whose length matches len("None")).

Run as root:
    sudo ./v908_fname_probe.py [PID]
"""

from __future__ import annotations
import os, sys, ctypes, fcntl, itertools, struct
sys.path.insert(0, os.path.dirname(__file__))
from memreader import MemReader, find_pid

# ── Constants extracted from IDA (v20260908, CL-1372005) ──────────────────
MODULE_BASE     = 0x140000000
POOL_RVA        = 0x10AB5DC0        # verified via .rdata header pattern
KEYSTREAM_RVA   = 0x1095926C
KEYSTREAM_WIN   = 0xA0              # bytes above KEYSTREAM_RVA (u16 index 80)
SEED_OFF        = 0x2490
BLOCK_BASE_OFF  = 0x24A0
BLOCK_STRIDE    = 32

P32 = 0x01000193
A32 = 0x902D0766                    # -1876097178 as u32
P64 = 0x100000001B3
A64 = 0x6292C37EFA7F5FA6

K_A   = 0x2B4667862B466786          # xmmword_14D4D3C90 (blend K_A)
K_B   = 0xD4B99879D4B99879          # xmmword_14D4D3C80 (blend K_B, ~K_A)
K_B1  = 0x9B9D24BF5D56B7D8          # xmmword_14D4D3CA0 (block1 xor)
K_B2  = 0x4F24BCC689EF2FA1          # xmmword_14D4D3BB0 (block2 xor)
K_ADD = 0xB0DB433A7610D05F          # qword_14D4D3BC0   (per-dword add)

FNV_ROL1 = 37
FNV_ROL2 = 48

MASK32 = 0xFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF


def rol32(x, n):
    n &= 31
    x &= MASK32
    return ((x << n) | (x >> (32 - n))) & MASK32 if n else x


def rol64(x, n):
    n &= 63
    x &= MASK64
    return ((x << n) | (x >> (64 - n))) & MASK64 if n else x


# ── The candidate shard-hash formulas ─────────────────────────────────────
def shard_hash_orig(seed):
    """The formula extracted from sub_1402D5F40 as decompiled."""
    lo = seed & MASK32
    hi = (seed >> 32) & MASK32
    c = ((P32 * rol32(lo, 19)) + A32) & MASK32
    e = ((P32 * rol32(c, 13)) + A32) & MASK32
    f = (e + hi) & MASK32
    h = ((P32 * rol32(f, 19)) + A32) & MASK32
    return rol32(h, 13)


def shard_hash_alt_hi_pos(seed):
    """Hi added AFTER the first imul instead of after the second."""
    lo = seed & MASK32
    hi = (seed >> 32) & MASK32
    c = ((P32 * rol32(lo, 19)) + A32) & MASK32
    f = (c + hi) & MASK32
    e = ((P32 * rol32(f, 13)) + A32) & MASK32
    h = ((P32 * rol32(e, 19)) + A32) & MASK32
    return rol32(h, 13)


def shard_hash_no_final_rol(seed):
    """Skip the final ROL(13) — use h ^ (h >> 16) directly."""
    lo = seed & MASK32
    hi = (seed >> 32) & MASK32
    c = ((P32 * rol32(lo, 19)) + A32) & MASK32
    e = ((P32 * rol32(c, 13)) + A32) & MASK32
    f = (e + hi) & MASK32
    h = ((P32 * rol32(f, 19)) + A32) & MASK32
    return h ^ (h >> 16)


def shard_hash_four_imul(seed):
    """Four imul rounds like v818 (add hi after imul#1)."""
    lo = seed & MASK32
    hi = (seed >> 32) & MASK32
    H = ((P32 * rol32(lo, 19)) + A32) & MASK32
    H = ((P32 * rol32(H, 13)) + hi + A32) & MASK32
    H = ((P32 * rol32(H, 19)) + A32) & MASK32
    H = ((P32 * rol32(H, 13)) + A32) & MASK32
    return H ^ (H >> 16)


# ── Slot selectors ────────────────────────────────────────────────────────
def slot_c1315578(T):
    """(-109*T + 102) ^ ((P*T + A) >> 16) & 7 — the shape in IDA."""
    Pa = ((((-109) & MASK32) * T + 102) & MASK32) & 0xFF
    Pb = (((P32 * T + A32) & MASK32) >> 16) & 0xFF
    return (Pa ^ Pb) & 7


def slot_simple(T):
    """T & 7 — v818 shape."""
    return T & 7


def slot_xor_and_shift(T):
    """(T ^ (T >> 16)) & 7 — v708-ish."""
    return (T ^ (T >> 16)) & 7


# ── Block decoders ────────────────────────────────────────────────────────
def dec_block1_padd(raw):
    x = (((raw & K_A) | ((~raw) & K_B)) & MASK64) ^ K_B1
    d0 = (rol32(x & MASK32, 3) + (K_ADD & MASK32)) & MASK32
    d1 = (rol32((x >> 32) & MASK32, 3) + ((K_ADD >> 32) & MASK32)) & MASK32
    return d0 | (d1 << 32)


def dec_block2_padd(raw):
    x = raw ^ K_B2
    d0 = (rol32(x & MASK32, 3) + (K_ADD & MASK32)) & MASK32
    d1 = (rol32((x >> 32) & MASK32, 3) + ((K_ADD >> 32) & MASK32)) & MASK32
    return d0 | (d1 << 32)


# Alternate decodes: maybe blend takes different K assignments
def dec_block1_swap_ab(raw):
    x = (((raw & K_B) | ((~raw) & K_A)) & MASK64) ^ K_B1
    d0 = (rol32(x & MASK32, 3) + (K_ADD & MASK32)) & MASK32
    d1 = (rol32((x >> 32) & MASK32, 3) + ((K_ADD >> 32) & MASK32)) & MASK32
    return d0 | (d1 << 32)


def dec_block1_no_padd(raw):
    x = (((raw & K_A) | ((~raw) & K_B)) & MASK64) ^ K_B1
    d0 = rol32(x & MASK32, 3)
    d1 = rol32((x >> 32) & MASK32, 3)
    return d0 | (d1 << 32)


# ── FNV chain variants ────────────────────────────────────────────────────
def fnv_chain(V13, rol1=FNV_ROL1, rol2=FNV_ROL2):
    Fv = (P64 * rol64(V13, rol1) + A64) & MASK64
    Fv = (P64 * rol64(Fv, rol2) + A64) & MASK64
    return Fv


# ── The probe ─────────────────────────────────────────────────────────────
def probe_ci(mr, ci, shard_fn, slot_fn, dec1_fn, dec2_fn):
    """Return (Entry, header_bytes) for a candidate pipeline configuration."""
    chunk_off = ((ci >> 8) & 0xFFFF00)
    name_off = ci & 0xFFFF
    chunk_addr = MODULE_BASE + POOL_RVA + chunk_off
    seed = chunk_addr + SEED_OFF
    T = shard_fn(seed)
    b1 = slot_fn(T)
    b2 = (b1 + 1) & 7
    try:
        raw1_bytes = mr.read(chunk_addr + BLOCK_BASE_OFF + BLOCK_STRIDE * b1, 8)
        raw2_bytes = mr.read(chunk_addr + BLOCK_BASE_OFF + BLOCK_STRIDE * b2, 8)
    except OSError as e:
        return None, None, (b1, b2)
    raw1 = int.from_bytes(raw1_bytes, 'little')
    raw2 = int.from_bytes(raw2_bytes, 'little')
    V13 = dec1_fn(raw1)
    V15 = dec2_fn(raw2)
    Fv2 = fnv_chain(V13)
    Entry = (V13 + (V15 ^ Fv2) + 2 * name_off) & MASK64
    if Entry < 0x10000 or Entry >= 0x800000000000:
        return Entry, None, (b1, b2)
    try:
        hdr = mr.read(Entry, 16)
    except OSError:
        return Entry, None, (b1, b2)
    return Entry, hdr, (b1, b2)


def header_looks_like(hdr, expected_len):
    """None entry: header u16 encodes length=4, wide=0. On v908 the length
    layout is (h & 7) | ((h >> 5) & 0x3F8); wide bit is 0x8000. len=4 wide=0
    means h & 7 == 4 and (h >> 5) & 0x3F8 == 0, so h in {4, 36, 37, 38, 39,
    100, ...}. Simpler check: (h & 0x8000) == 0 and low bits encode 4."""
    if not hdr or len(hdr) < 2:
        return False
    h = int.from_bytes(hdr[:2], 'little')
    wide = (h & 0x8000) != 0
    length = (h & 7) | ((h >> 5) & 0x3F8)
    return not wide and length == expected_len


def main():
    pid = int(sys.argv[1]) if len(sys.argv) > 1 else find_pid()
    if not pid:
        sys.exit("no PID")
    print(f"[+] PID = {pid}")

    with MemReader(pid) as mr:
        # Confirm the pool address is readable and shows the expected header.
        rd = mr.read(MODULE_BASE + POOL_RVA, 32)
        print(f"[+] pool @ 0x{MODULE_BASE + POOL_RVA:X}: {rd.hex()}")

        # Read the 8 blocks at chunk[0] once and print
        base = MODULE_BASE + POOL_RVA + BLOCK_BASE_OFF
        print(f"[+] chunk[0] blocks @ 0x{base:X}:")
        blocks = []
        for i in range(8):
            b = mr.read(base + BLOCK_STRIDE * i, 16)
            blocks.append(int.from_bytes(b[:8], 'little'))
            print(f"    block[{i}] lo64 = 0x{blocks[-1]:016X}")

        shard_fns = [
            ('orig_3imul_rol_final',  shard_hash_orig),
            ('alt_hi_pos',            shard_hash_alt_hi_pos),
            ('no_final_rol',          shard_hash_no_final_rol),
            ('four_imul',             shard_hash_four_imul),
        ]
        slot_fns = [
            ('c1315578', slot_c1315578),
            ('simple',   slot_simple),
            ('xor_hi',   slot_xor_and_shift),
        ]
        dec1_fns = [
            ('padd',    dec_block1_padd),
            ('swap_ab', dec_block1_swap_ab),
            ('no_padd', dec_block1_no_padd),
        ]
        dec2_fns = [
            ('padd', dec_block2_padd),
        ]

        # Sweep all combinations for CI=0 and report ones whose Entry is
        # inside the pool region and whose header decodes to length 4.
        pool_lo = MODULE_BASE + POOL_RVA
        pool_hi = pool_lo + 0x1000000  # allow up to 16 MiB pool
        best = []
        for (sn, sf), (ln, lf), (d1n, d1f), (d2n, d2f) in itertools.product(
                shard_fns, slot_fns, dec1_fns, dec2_fns):
            Entry, hdr, (b1, b2) = probe_ci(mr, 0, sf, lf, d1f, d2f)
            if Entry is None:
                continue
            in_pool = pool_lo <= Entry < pool_hi
            looks_none = header_looks_like(hdr, 4)
            tag = ''
            if looks_none: tag = '★ NONE-shape header'
            elif in_pool:  tag = '  in pool'
            elif hdr is not None: tag = '  readable'
            print(f"  shard={sn:24s} slot={ln:10s} b1={b1} b2={b2} "
                  f"dec1={d1n:8s} Entry=0x{Entry:016X} "
                  f"hdr={hdr.hex() if hdr else '--':32s} {tag}")
            if looks_none or in_pool:
                best.append((sn, ln, d1n, d2n, Entry, hdr))

        print()
        if best:
            print(f"[+] {len(best)} candidate(s) landed in pool or matched None header")
        else:
            print("[-] no candidate landed in pool")


if __name__ == '__main__':
    main()
