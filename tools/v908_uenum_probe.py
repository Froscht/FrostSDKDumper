#!/usr/bin/env python3
"""Live probe: locate UEnum::Names on v20260908 (CL-1372005).

The dump is currently emitting empty enum bodies because the compiled
UENUM_NAMES_OFF (0xB0) may be wrong for this patch. This script:

  1. Reads memory for well-known enum objects picked from dump_objects.txt.
  2. Sweeps every 8-byte-aligned offset in [0x60, 0x160] for a valid
     TArray<TPair<FName,int64>> header {Data (u64 heap ptr), Num (u32),
     Max (u32)}.
  3. For each candidate, reads the first few TPair<FName,int64> elements
     at both stride 16 (TPair<FName,int64> == {ComparisonIndex(u32),
     Number(u32), Value(i64)}) and asserts:
        - CI in [1, 0x1FFFFFFF]
        - Number in [0, 0xFF]
        - Value in [-0x10000, 0x10000]
        - CI resolves via the v908 FName resolver to a plausible name
  4. Reports offset / TPair stride / entry count / first-few names per enum.

Root required (uses /dev/memreader). Run:
    sudo python3 tools/v908_uenum_probe.py [PID]
"""

from __future__ import annotations
import os, sys, struct
sys.path.insert(0, os.path.dirname(__file__))
from memreader import MemReader, find_pid

MODULE_BASE   = 0x140000000

# ── v20260908 pipeline constants (from arc_decrypt.h) ─────────────────────
POOL_RVA        = 0x10AB5DC0
KEYSTREAM_RVA   = 0x1095926C
KEYSTREAM_BASE  = 0x78
SEED_OFF        = 0x2490
BLOCK_BASE_OFF  = 0x24A0
BLOCK_STRIDE    = 0x20

P32  = 0x01000193
A32  = 0x902D0766
P64  = 0x100000001B3
A64  = 0x6292C37EFA7F5FA6

BLOCK2_XOR = 0x4F24BCC689EF2FA1
BLOCK_ADD  = 0xB0DB433A7610D05F
BLOCK_ROL32 = 3

FNV_ROL1 = 37
FNV_ROL2 = 48

PTR_XOR1 = 0x5D4B82B8
PTR_XOR2 = 0x0000516500000000
PTR_XOR3 = 0xB8821A3800000000

HDR_WIDE_BIT      = 0x8000
KEY_INIT_ADD      = 0x2E0
KEY_STEP_PAIR     = 0x67E
KEY_INDEX_MASK    = 0x3F
NARROW_KEY_SHIFT  = 3

SHARD_ROL_A = 19
SHARD_ROL_B = 13

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


def shard_hash_v9(seed):
    lo = seed & MASK32
    hi = (seed >> 32) & MASK32
    s1 = (P32 * rol32(lo, SHARD_ROL_A) + A32) & MASK32
    s2 = (P32 * rol32(s1, SHARD_ROL_B) + hi + A32) & MASK32
    s3 = (P32 * rol32(s2, SHARD_ROL_A) + A32) & MASK32
    return rol32(s3, SHARD_ROL_B)


def block_index(v9):
    pa = ((-109 & MASK32) * v9 + 102) & 0xFF
    pb = ((P32 * v9 + A32) & MASK32) >> 16 & 0xFF
    return (pa ^ pb) & 7


def decode_block(raw):
    x = raw ^ BLOCK2_XOR
    d0 = (rol32(x & MASK32, BLOCK_ROL32) + (BLOCK_ADD & MASK32)) & MASK32
    d1 = (rol32((x >> 32) & MASK32, BLOCK_ROL32) + ((BLOCK_ADD >> 32) & MASK32)) & MASK32
    return d0 | (d1 << 32)


def fnv_chain(v13):
    fv = (P64 * rol64(v13, FNV_ROL1) + A64) & MASK64
    fv = (P64 * rol64(fv, FNV_ROL2) + A64) & MASK64
    return fv


def apply_ptr_chain(raw):
    s1 = int.from_bytes(((raw ^ PTR_XOR1) & MASK64).to_bytes(8, 'little'), 'big')
    s2 = PTR_XOR2 ^ s1
    return int.from_bytes(((PTR_XOR3 ^ s2) & MASK64).to_bytes(8, 'little'), 'big')


def resolve_entry(mr, ci):
    if ci < 0:
        return 0
    ci &= MASK32
    name_off = ci & 0xFFFF
    chunk_off = (ci >> 8) & 0xFFFF00
    chunk_addr = MODULE_BASE + POOL_RVA + chunk_off
    try:
        raw_b1 = mr.read(chunk_addr + BLOCK_BASE_OFF + BLOCK_STRIDE * block_index(shard_hash_v9(chunk_addr + SEED_OFF)), 8)
        v9 = shard_hash_v9(chunk_addr + SEED_OFF)
        b1 = block_index(v9)
        b2 = (b1 + 1) & 7
        raw1 = int.from_bytes(mr.read(chunk_addr + BLOCK_BASE_OFF + BLOCK_STRIDE * b1, 8), 'little')
        raw2 = int.from_bytes(mr.read(chunk_addr + BLOCK_BASE_OFF + BLOCK_STRIDE * b2, 8), 'little')
    except OSError:
        return 0
    if not raw1 and not raw2:
        return 0
    v14 = decode_block(raw1)
    v15 = decode_block(raw2)
    fv = fnv_chain(v14)
    raw = (v14 + (v15 ^ fv) + 2 * name_off) & MASK64
    entry = apply_ptr_chain(raw)
    if entry < 0x10000 or entry >= 0x800000000000:
        return 0
    return entry


def read_header(mr, entry):
    try:
        hdr = int.from_bytes(mr.read(entry, 2), 'little')
    except OSError:
        return None
    if not hdr:
        return None
    raw_bytes = ((hdr >> 5) & 0x3F8) | (hdr & 7)
    is_wide = (hdr & HDR_WIDE_BIT) != 0
    length = raw_bytes // 2 if is_wide else raw_bytes
    return raw_bytes, length, is_wide


def decrypt_narrow(cipher, length, keytable, base_idx):
    out = []
    key = length + KEY_INIT_ADD
    i = 0
    while i + 1 < length and i + 1 < len(cipher):
        idx1 = key & KEY_INDEX_MASK
        idx2 = (key - 1) & KEY_INDEX_MASK
        k1 = keytable[idx1 + base_idx] >> NARROW_KEY_SHIFT & 0xFF
        k2 = keytable[idx2 + base_idx] >> NARROW_KEY_SHIFT & 0xFF
        out.append(cipher[i] ^ k1)
        out.append(cipher[i + 1] ^ k2)
        key += KEY_STEP_PAIR
        i += 2
    if i < length and i < len(cipher):
        idx = key & KEY_INDEX_MASK
        k = keytable[idx + base_idx] >> NARROW_KEY_SHIFT & 0xFF
        out.append(cipher[i] ^ k)
    return bytes(out).decode('latin-1', errors='replace')


def load_keystream(mr):
    keystream_base = MODULE_BASE + KEYSTREAM_RVA + KEYSTREAM_BASE * 2
    raw = mr.read(keystream_base, 0x80 * 2)
    return list(struct.unpack('<128H', raw))


def resolve_name(mr, ci, keytable):
    entry = resolve_entry(mr, ci)
    if not entry:
        return None
    hdr = read_header(mr, entry)
    if not hdr:
        return None
    raw_bytes, length, is_wide = hdr
    if length <= 0 or length > 128:
        return None
    if is_wide:
        return None  # skip wide for probe simplicity
    try:
        cipher = mr.read(entry + 2, raw_bytes)
    except OSError:
        return None
    return decrypt_narrow(cipher, length, keytable, 0)


def is_plausible_name(s):
    if not s:
        return False
    if len(s) < 1 or len(s) > 128:
        return False
    for c in s:
        if not (c.isalnum() or c in '_:-'):
            return False
    return True


# ── UEnum layout probe ────────────────────────────────────────────────────
def probe_enum(mr, addr, name, keytable):
    print(f"\n=== {name} @ 0x{addr:X} ===")
    try:
        buf = mr.read(addr, 0x200)
    except OSError as e:
        print(f"  read fail: {e}")
        return None

    # Sweep 8-byte-aligned offsets in [0x60, 0x160]
    candidates = []
    for off in range(0x60, 0x160, 4):
        if off + 16 > len(buf):
            break
        data_ptr, num, max_ = struct.unpack_from('<QII', buf, off)
        if not (0x10000 < data_ptr < 0x800000000000):
            continue
        if not (2 <= num <= 500):
            continue
        if not (num <= max_ <= 512):
            continue
        # Reject if data_ptr is inside module
        if MODULE_BASE <= data_ptr < MODULE_BASE + 0x15000000:
            continue
        candidates.append((off, data_ptr, num, max_))

    if not candidates:
        print("  no {Data, Num, Max} triple found")
        return None

    # For each candidate, try both TPair strides and validate first entries
    best = None
    for (off, data_ptr, num, max_) in candidates:
        for stride in (0x10, 0x18, 0x20):
            probe_n = min(num, 8)
            try:
                arr = mr.read(data_ptr, stride * probe_n)
            except OSError:
                continue
            # Try FName layouts:
            # Layout A: TPair<{CI(u32), Number(u32)}, int64> stride=0x10, val@+8
            # Layout B: same but stride=0x18 (aligned padding)
            # Layout C: value first? — unusual, try later
            ok = 0
            names = []
            for j in range(probe_n):
                # Layout A: CI @+0, Number @+4, value @+8
                ci = struct.unpack_from('<i', arr, j * stride)[0]
                num_field = struct.unpack_from('<I', arr, j * stride + 4)[0]
                val = struct.unpack_from('<q', arr, j * stride + 8)[0]
                if not (0 < ci < 0x1FFFFFFF):
                    break
                if num_field >= 0x100:
                    break
                if not (-0x10000 < val < 0x10000):
                    break
                nm = resolve_name(mr, ci, keytable)
                if not is_plausible_name(nm):
                    break
                ok += 1
                names.append((nm, val))
            marker = ' <-- WINS' if ok == probe_n else ''
            if ok >= 2:
                print(f"  offset +0x{off:03X} data=0x{data_ptr:X} num={num} max={max_} "
                      f"stride={stride} decoded {ok}/{probe_n} names{marker}")
                for n, v in names:
                    print(f"      [{v:>3}] {n}")
                if best is None or ok > best[1]:
                    best = ((off, data_ptr, num, max_, stride), ok, names)
            elif ok == 1 and stride == 0x10:
                # Show at least one match for diag
                print(f"  offset +0x{off:03X} data=0x{data_ptr:X} num={num} max={max_} "
                      f"stride={stride} decoded {ok}/{probe_n} (partial)")

    return best


def main():
    pid = int(sys.argv[1]) if len(sys.argv) > 1 else 97340
    print(f"[+] PID = {pid}")

    # Enum addresses from dump_objects.txt
    enums = [
        ("EPhysicalSurface",  0x7FFFDE7AAE30),
        ("ETickingGroup",     0x7FFFDE713970),
        ("ETraceTypeQuery",   0x7FFFDE71A8E0),
        ("ECollisionChannel", 0x7FFFDE7BF890),
        ("EViewModeIndex",    0x7FFFDE7FB6F0),
    ]

    with MemReader(pid) as mr:
        # Sanity: CI=0 -> "None"
        print("[+] loading keystream...")
        keytable = load_keystream(mr)
        none_str = resolve_name(mr, 0, keytable)
        print(f"[+] CI=0 -> {none_str!r} (expect 'None')")
        if none_str != "None":
            print("[!!!] FName pipeline sanity check failed; results below unreliable")

        # Sanity: also try a mid CI to confirm
        for ci in (100, 500, 1000, 5000):
            nm = resolve_name(mr, ci, keytable)
            print(f"    CI={ci} -> {nm!r}")

        results = []
        for name, addr in enums:
            r = probe_enum(mr, addr, name, keytable)
            if r:
                results.append((name, r))

        print("\n" + "=" * 70)
        print("SUMMARY")
        print("=" * 70)
        offsets = {}
        for name, ((off, data_ptr, num, max_, stride), ok, names) in results:
            print(f"{name:20s}: UEnum::Names @ +0x{off:X} (stride 0x{stride:X}, {ok} names ok)")
            offsets.setdefault((off, stride), []).append(name)

        if offsets:
            print("\nConsensus:")
            for (off, stride), enum_names in sorted(offsets.items(),
                                                    key=lambda kv: -len(kv[1])):
                print(f"  offset +0x{off:X} stride 0x{stride:X}: {len(enum_names)} enums "
                      f"({', '.join(enum_names)})")


if __name__ == '__main__':
    main()
