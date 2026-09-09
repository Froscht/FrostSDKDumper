#!/usr/bin/env python3
"""Live probe for the v908 outer-chain break.

Reproduces exactly what fname_decrypt.h::GetPackagePtr does on this build:
walks the 4 UObject slot candidates via DecodeSlot16_V908, resolves each
candidate's name via GetNameV908 (including the fallback slot sweep), and
follows the "first slot whose name starts with '/'" rule until a UPackage
is reached OR the chain terminates.

Usage:
    sudo ./v908_outer_chain_probe.py                        # scan 2000 random objects
    sudo ./v908_outer_chain_probe.py <pid>                  # explicit pid
    sudo ./v908_outer_chain_probe.py <pid> <hex-obj-addr>   # one specific object
    FROST_SCAN=5000 ./v908_outer_chain_probe.py             # bigger sample
    FROST_PATTERN=AnimBlueprintExtension ./v908_outer_chain_probe.py

Prints, per target object, the full walk step by step: current object,
its four decoded slot pointers, each pointer's decoded name, and the
"Best" the walker would follow.  Terminal state is one of:
    found_package  -- OK, a name starting with '/' was reached
    no_progress    -- all 4 slots decoded to null / no name
    cycle_or_max   -- chain looped or hit depth 24
"""
from __future__ import annotations
import os, sys, random
sys.path.insert(0, os.path.dirname(__file__))
from memreader import MemReader

# ── v20260908 constants (mirror arc_decrypt.h::v20260908) ─────────────────
MODULE_BASE       = 0x140000000
POOL_RVA          = 0x10AB5DC0
KEYSTREAM_RVA     = 0x1095926C
KEYSTREAM_BASE    = 120           # u16 index above RVA_KEYSTREAM (+0xF0 bytes)
SEED_OFF          = 0x2490
BLOCK_BASE_OFF    = 0x24A0
BLOCK_STRIDE      = 32

SHARD_P32         = 0x01000193
SHARD_A32         = 0x902D0766
SHARD_ROL_A       = 19
SHARD_ROL_B       = 13

FNV_P64           = 0x100000001B3
FNV_A64           = 0x6292C37EFA7F5FA6
FNV_ROL1          = 37
FNV_ROL2          = 48

BLOCK2_XOR        = 0x4F24BCC689EF2FA1
BLOCK_ADD         = 0xB0DB433A7610D05F

PTR_XOR1          = 0x5D4B82B8
PTR_XOR2          = 0x0000516500000000
PTR_XOR3          = 0xB8821A3800000000

KEY_INIT_ADD      = 0x2E0
KEY_STEP_PAIR     = 0x67E
KEY_INDEX_MASK    = 0x3F

# UObject slot decoder (post-fix d0356c0: ADDITIVE hash const 0x993B3384)
UOBJ_SEED_OFF     = 0x10
UOBJ_SLOT_BASE    = 0x20
UOBJ_SLOT_STRIDE  = 0x20
UOBJ_HASH_PRIME   = 0x01000193
UOBJ_HASH_ADD     = 0x993B3384
UOBJ_IDX_ADD      = 0x33384
UOBJ_ROL_A        = 13
UOBJ_ROL_B        = 22
UOBJ_ROL_C        = 13
UOBJ_SHR          = 10
UOBJ_NAME_XOR     = 2
UOBJ_CLASS_ADJ    = 1
UOBJ_OUTER_ADJ    = 0

SLOT_KEY_LO64     = 0x06CC58E720047BF7
SLOT_PSHUF_MASK   = [2, 5, 4, 6, 0, 7, 1, 3]
UOBJ_PSHUFLW_IMM  = 30
UOBJ_ROL64        = 17
UOBJ_NAME_ROL64   = 32

# ChunkMgr
CHUNK_ARRAY_RVA   = 0x10D853F0
CHUNKMGR_KEY_RVA  = 0xD4B22B0
CHUNKMGR_ROL16    = 13
CHUNKMGR_PSHUFLW  = 27
MGR_NUM_OFF       = 0x04
MGR_NUM_XOR       = 0xBD497AA1
MGR_ARR_OFF       = 0x30
MGR_ARR_XOR       = 0x6BC7FB8600000000

STRIDE            = 24
OBJ_OFF           = 8
ITEMS_PER_CHUNK   = 65536

M32 = 0xFFFFFFFF
M64 = 0xFFFFFFFFFFFFFFFF

# ── SIMD helpers ─────────────────────────────────────────────────────────
def rol32(x, n):
    n &= 31; x &= M32
    return ((x << n) | (x >> (32 - n))) & M32 if n else x

def rol64(x, n):
    n &= 63; x &= M64
    return ((x << n) | (x >> (64 - n))) & M64 if n else x

def pshuflw(lo, imm):
    w = [(lo >> (i*16)) & 0xFFFF for i in range(4)]
    out = 0
    for i in range(4):
        out |= w[(imm >> (i*2)) & 3] << (i*16)
    return out & M64

def pshufb8(lo, mask):
    src = [(lo >> (i*8)) & 0xFF for i in range(8)]
    out = 0
    for i in range(8):
        out |= src[mask[i] & 7] << (i*8)
    return out & M64

def rol32x2(v, n):
    d0 = rol32(v & M32, n)
    d1 = rol32((v >> 32) & M32, n)
    return d0 | (d1 << 32)

def padd32x2(v, broadcast):
    lo = broadcast & M32
    hi = (broadcast >> 32) & M32
    a0 = ((v & M32) + lo) & M32
    a1 = (((v >> 32) & M32) + hi) & M32
    return a0 | (a1 << 32)

def rol16x4(v, n):
    n &= 15
    out = 0
    for i in range(4):
        w = (v >> (i*16)) & 0xFFFF
        out |= (((w << n) | (w >> (16 - n))) & 0xFFFF) << (i*16)
    return out

def bswap64(x):
    return int.from_bytes((x & M64).to_bytes(8, 'big'), 'little')

def bswap32(x):
    return int.from_bytes((x & M32).to_bytes(4, 'big'), 'little')

# ── UObject slot decode (v908) ────────────────────────────────────────────
def decode_slot16(lo):
    x = pshuflw(lo, UOBJ_PSHUFLW_IMM) ^ SLOT_KEY_LO64
    x = rol64(x, UOBJ_ROL64)
    x = pshufb8(x, SLOT_PSHUF_MASK)
    return rol64(x, UOBJ_NAME_ROL64)

def slot_hash(obj):
    seed = (obj + UOBJ_SEED_OFF) & M64
    lo = seed & M32; hi = (seed >> 32) & M32
    P, A = UOBJ_HASH_PRIME, UOBJ_HASH_ADD
    h = (P * rol32(lo, UOBJ_ROL_A) + A) & M32
    h = (P * rol32(h, UOBJ_ROL_B) + hi + A) & M32
    h = (P * rol32(h, UOBJ_ROL_C) + A) & M32
    return (P * (h >> UOBJ_SHR)) & M32

def slot_idx_base(obj):
    v3 = slot_hash(obj)
    return ((v3 & 0xFF) ^ (((v3 + UOBJ_IDX_ADD) >> 16) & 0xFF)) & 3

def name_slot(obj):  return slot_idx_base(obj) ^ UOBJ_NAME_XOR
def class_slot(obj): return (slot_idx_base(obj) + UOBJ_CLASS_ADJ) & 3
def outer_slot(obj): return (slot_idx_base(obj) + UOBJ_OUTER_ADJ) & 3

# ── FName resolve (v908) ──────────────────────────────────────────────────
def shard_hash_v9(seed_addr):
    lo = seed_addr & M32; hi = (seed_addr >> 32) & M32
    P, A = SHARD_P32, SHARD_A32
    s1 = (P * rol32(lo, SHARD_ROL_A) + A) & M32
    s2 = (P * rol32(s1, SHARD_ROL_B) + hi + A) & M32
    s3 = (P * rol32(s2, SHARD_ROL_A) + A) & M32
    return rol32(s3, SHARD_ROL_B)

def block_index(v9):
    P, A = SHARD_P32, SHARD_A32
    pa = ((((-109) & M32) * v9 + 102) & M32) & 0xFF
    pb = (((P * v9 + A) & M32) >> 16) & 0xFF
    return (pa ^ pb) & 7

def decode_block(raw):
    x = raw ^ BLOCK2_XOR
    x = rol32x2(x, 3)
    return padd32x2(x, BLOCK_ADD)

def apply_ptr_chain(raw):
    s1 = bswap64(raw ^ PTR_XOR1)
    s2 = PTR_XOR2 ^ s1
    return bswap64(PTR_XOR3 ^ s2)

def resolve_entry(mr, ci):
    if ci is None or ci < 0: return 0
    name_off  = ci & 0xFFFF
    chunk_off = (ci >> 8) & 0xFFFF00
    chunk_addr = MODULE_BASE + POOL_RVA + chunk_off
    v9 = shard_hash_v9(chunk_addr + SEED_OFF)
    b1 = block_index(v9); b2 = (b1 + 1) & 7
    try:
        raw1 = int.from_bytes(mr.read(chunk_addr + BLOCK_BASE_OFF + BLOCK_STRIDE * b1, 8), 'little')
        raw2 = int.from_bytes(mr.read(chunk_addr + BLOCK_BASE_OFF + BLOCK_STRIDE * b2, 8), 'little')
    except OSError:
        return 0
    if raw1 == 0 and raw2 == 0: return 0
    v14 = decode_block(raw1); v15 = decode_block(raw2)
    fv = (FNV_P64 * rol64(v14, FNV_ROL1) + FNV_A64) & M64
    fv = (FNV_P64 * rol64(fv, FNV_ROL2) + FNV_A64) & M64
    raw = (v14 + (v15 ^ fv) + 2 * name_off) & M64
    entry = apply_ptr_chain(raw)
    if entry < 0x10000 or entry >= 0x800000000000: return 0
    return entry

def decrypt_narrow(cipher, length, ks_u16):
    out = bytearray()
    key = (length + KEY_INIT_ADD) & M32
    i = 0
    while i + 1 < length and i + 1 < len(cipher):
        idx1 = key & KEY_INDEX_MASK
        idx2 = (key - 1) & KEY_INDEX_MASK
        k1 = (ks_u16[idx1 + KEYSTREAM_BASE] >> 3) & 0xFF
        k2 = (ks_u16[idx2 + KEYSTREAM_BASE] >> 3) & 0xFF
        out.append(cipher[i]     ^ k1)
        out.append(cipher[i + 1] ^ k2)
        key = (key + KEY_STEP_PAIR) & M32
        i += 2
    if i < length and i < len(cipher):
        idx = key & KEY_INDEX_MASK
        k = (ks_u16[idx + KEYSTREAM_BASE] >> 3) & 0xFF
        out.append(cipher[i] ^ k)
    return bytes(out)

def decrypt_wide(cipher16, length, ks_u16):
    if length <= 0 or length > 128: return b''
    out = bytearray()
    non_ascii = 0
    key = (length + KEY_INIT_ADD) & M32
    i = 0
    while i + 1 < length and i + 1 < len(cipher16):
        idx1 = key & KEY_INDEX_MASK
        idx2 = (key - 1) & KEY_INDEX_MASK
        w1 = cipher16[i]     ^ ks_u16[idx1 + KEYSTREAM_BASE]
        w2 = cipher16[i + 1] ^ ks_u16[idx2 + KEYSTREAM_BASE]
        for w in (w1, w2):
            c = w & 0xFF
            if (w & 0xFF00) or c >= 0x80: non_ascii += 1
            out.append(c)
        key = (key + KEY_STEP_PAIR) & M32
        i += 2
    if i < length and i < len(cipher16):
        idx = key & KEY_INDEX_MASK
        w = cipher16[i] ^ ks_u16[idx + KEYSTREAM_BASE]
        c = w & 0xFF
        if (w & 0xFF00) or c >= 0x80: non_ascii += 1
        out.append(c)
    if out and non_ascii * 5 > len(out): return b''
    return bytes(out)

def read_keystream(mr):
    raw = mr.read(MODULE_BASE + KEYSTREAM_RVA, 512)
    return [int.from_bytes(raw[i*2:i*2+2], 'little') for i in range(256)]

def name_from_ci(mr, ci, ks):
    entry = resolve_entry(mr, ci)
    if not entry: return ''
    try:
        hdr = int.from_bytes(mr.read(entry, 2), 'little')
    except OSError:
        return ''
    if hdr == 0: return ''
    is_wide  = bool(hdr & 0x8000)
    raw_bytes = ((hdr >> 5) & 0x3F8) | (hdr & 7)
    if is_wide:
        if raw_bytes < 2: return ''
        length = raw_bytes // 2
        try:
            cipher = mr.read(entry + 2, raw_bytes)
        except OSError:
            return ''
        cipher16 = [int.from_bytes(cipher[i*2:i*2+2], 'little') for i in range(length)]
        return decrypt_wide(cipher16, length, ks).decode('latin-1', errors='replace')
    else:
        length = raw_bytes
        if length == 0 or length > 1023: return ''
        try:
            cipher = mr.read(entry + 2, length)
        except OSError:
            return ''
        return decrypt_narrow(cipher, length, ks).decode('latin-1', errors='replace')

# ── UObject helpers ───────────────────────────────────────────────────────
def read_slot_raw(mr, obj, idx):
    """Return the decoded Raw for slot idx (or None on read failure / all-zero)."""
    try:
        b = mr.read(obj + UOBJ_SLOT_BASE + UOBJ_SLOT_STRIDE * idx, 16)
    except OSError:
        return None
    lo = int.from_bytes(b[:8], 'little')
    if lo == 0: return None
    return decode_slot16(lo)

def slot_as_ptr(raw):
    if raw is None: return None
    p = ((raw << 32) | (raw >> 32)) & M64
    if p < 0x10000 or p >= 0x800000000000: return None
    return p

def slot_as_fname(raw):
    """Return (CI, Number)."""
    if raw is None: return (None, None)
    return (raw & M32, (raw >> 32) & M32)

def is_ident_or_path(s):
    for c in s:
        if not (c.isalnum() or c in '_/.'):
            return False
    return True

def get_obj_name(mr, obj, ks):
    """Mirror of fname_decrypt.h::GetNameV908 including the fallback sweep."""
    if obj is None or obj < 0x10000 or obj >= 0x800000000000:
        return ''
    raw = read_slot_raw(mr, obj, name_slot(obj))
    ci, num = slot_as_fname(raw)
    primary = ''
    if raw is not None:
        primary = name_from_ci(mr, ci, ks) if ci is not None else ''
    looks_ptr        = (ci == 0x7FFF and num is not None and num > 0x10000)
    looks_bogus      = looks_ptr or (ci == 0 and num is not None and num > 0x1000)
    primary_is_none  = (ci == 0 and num == 0)
    if primary == '' or looks_bogus or primary_is_none:
        best_ci = 0xFFFFFFFF
        best_s  = None
        for i in range(4):
            r = read_slot_raw(mr, obj, i)
            if r is None: continue
            ci_i, num_i = slot_as_fname(r)
            if ci_i == 0 or ci_i is None or ci_i >= 0x100000 or num_i != 0:
                continue
            s = name_from_ci(mr, ci_i, ks)
            if not s or len(s) > 128 or not is_ident_or_path(s):
                continue
            if ci_i < best_ci:
                best_ci = ci_i; best_s = s
        if best_s is not None:
            return best_s
    if primary and num and 0 < num < 0x100000:
        return f"{primary}_{num - 1}"
    return primary

def all_slot_ptrs(mr, obj):
    """Return list of (idx, ptr or None) for the four slots after halves-swap."""
    out = []
    for i in range(4):
        r = read_slot_raw(mr, obj, i)
        out.append((i, slot_as_ptr(r)))
    return out

# ── Package-walk (mirror of GetPackagePtr v908 branch) ────────────────────
def walk_outer_chain(mr, obj, ks, max_depth=24):
    """Return list of steps.  Each step is a dict for a walk-node; a str for terminal state."""
    steps = []
    cur = obj
    visited = set()
    for depth in range(max_depth):
        if cur in visited:
            steps.append(('cycle', cur, None)); return steps
        visited.add(cur)
        slots = all_slot_ptrs(mr, cur)
        step = {'depth': depth, 'cur': cur, 'slots': []}
        best = 0
        found = 0
        for (i, p) in slots:
            if p is None or p == cur:
                step['slots'].append((i, p, ''))
                continue
            n = get_obj_name(mr, p, ks)
            step['slots'].append((i, p, n))
            if n and n[0] == '/' and found == 0:
                found = p
            if best == 0 and n:
                best = p
        steps.append(step)
        if found:
            steps.append(('found_package', found, get_obj_name(mr, found, ks)))
            return steps
        if best == 0:
            steps.append(('no_progress', None, None))
            return steps
        cur = best
    steps.append(('max_depth', cur, None))
    return steps

# ── ChunkMgr / object enumeration ────────────────────────────────────────
def decrypt_chunkmgr(blob_lo, key_lo):
    x = blob_lo ^ key_lo
    x = rol16x4(x, CHUNKMGR_ROL16)
    return pshuflw(x, CHUNKMGR_PSHUFLW)

def read_chunkmgr(mr):
    """Mirror of arc_decrypt.h::v20260908 (bswap-then-xor is the C++ pattern)."""
    enc = mr.read(MODULE_BASE + CHUNK_ARRAY_RVA, 16)
    key = mr.read(MODULE_BASE + CHUNKMGR_KEY_RVA, 16)
    blob  = int.from_bytes(enc[:8], 'little')
    keylo = int.from_bytes(key[:8], 'little')
    mgr = decrypt_chunkmgr(blob, keylo)
    num_raw = int.from_bytes(mr.read(mgr + MGR_NUM_OFF, 4), 'little')
    arr_raw = int.from_bytes(mr.read(mgr + MGR_ARR_OFF, 8), 'little')
    num = bswap32(num_raw ^ MGR_NUM_XOR)
    arr = bswap64(arr_raw ^ MGR_ARR_XOR)
    return mgr, num, arr

def read_obj_by_index(mr, arr, idx):
    ci = idx >> 16
    slot = idx & 0xFFFF
    try:
        chunk_ptr = int.from_bytes(mr.read(arr + 8*ci, 8), 'little')
    except OSError:
        return 0
    if chunk_ptr < 0x10000: return 0
    item = chunk_ptr + STRIDE * slot
    try:
        return int.from_bytes(mr.read(item + OBJ_OFF, 8), 'little')
    except OSError:
        return 0

def load_object_addrs_from_dump(path):
    """Return list of (idx, addr, name) parsed from dump_objects.txt."""
    out = []
    with open(path) as f:
        for line in f:
            if not line.startswith('['): continue
            try:
                lb = line.index(']')
                idx = int(line[1:lb])
                rest = line[lb+1:].strip()
                pipe = rest.index('|')
                addr = int(rest[:pipe].strip(), 16)
                name = rest[pipe+1:].strip()
                out.append((idx, addr, name))
            except (ValueError, IndexError):
                continue
    return out

# ── Pretty printer ────────────────────────────────────────────────────────
def print_chain(chain):
    for step in chain:
        if isinstance(step, tuple):
            kind, obj, extra = step
            objs = f"0x{obj:X}" if isinstance(obj, int) and obj else "<none>"
            print(f"    << {kind:15s}  {objs}  extra={extra!r}")
            continue
        print(f"    depth={step['depth']:<2d} cur=0x{step['cur']:X}")
        for (i, p, n) in step['slots']:
            ps = f"0x{p:X}" if p else "<none>"
            print(f"        slot{i}: ptr={ps:<16s} name={n!r}")

def main():
    argv = sys.argv[1:]
    pid_arg = None
    obj_arg = None
    for a in argv:
        if pid_arg is None:
            pid_arg = int(a)
        elif obj_arg is None:
            obj_arg = int(a, 16)
    if pid_arg is None: pid_arg = 97340
    print(f"[+] PID = {pid_arg}")

    pattern = os.environ.get('FROST_PATTERN', '')
    n_scan  = int(os.environ.get('FROST_SCAN', '2000'))
    max_report = int(os.environ.get('FROST_REPORT', '5'))

    dump_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              'dump_objects.txt')
    if not os.path.exists(dump_path):
        sys.exit(f"dump_objects.txt not found at {dump_path}")

    with MemReader(pid_arg) as mr:
        ks = read_keystream(mr)

        # Sanity: CI=0 must decode to "None"
        none_str = name_from_ci(mr, 0, ks)
        print(f"[+] CI=0 name: {none_str!r}  (expect 'None')")

        entries = load_object_addrs_from_dump(dump_path)
        print(f"[+] loaded {len(entries)} objects from dump_objects.txt")

        targets = []
        if obj_arg is not None:
            targets = [(0, obj_arg, get_obj_name(mr, obj_arg, ks))]
        else:
            print(f"[+] scanning {n_scan} random objects" +
                  (f" for pattern {pattern!r}" if pattern else " for outer-chain failures"))
            random.seed(0)
            checked = 0
            good = 0
            bad = 0
            found_hits = []
            pool = random.sample(entries, min(n_scan, len(entries)))
            for (idx, obj, name_hint) in pool:
                if obj < 0x10000: continue
                checked += 1
                name = get_obj_name(mr, obj, ks)
                if not name: continue
                if pattern and pattern not in name: continue
                chain = walk_outer_chain(mr, obj, ks, max_depth=12)
                terminal = chain[-1]
                is_found = isinstance(terminal, tuple) and terminal[0] == 'found_package'
                if is_found:
                    good += 1
                else:
                    bad += 1
                    found_hits.append((idx, obj, name, terminal))
                    if len(found_hits) >= max_report: break
            print(f"[+] scan: checked={checked}  chain-reaches-package={good}  chain-fails={bad}")
            print(f"[+] first {len(found_hits)} failing candidates:")
            for (idx, obj, name, term) in found_hits:
                termkind = term[0] if isinstance(term, tuple) else str(term)
                print(f"    idx={idx:8d} obj=0x{obj:X} name={name!r}  end={termkind}")
            targets = [(h[0], h[1], h[2]) for h in found_hits]

        for (idx, tgt, tname) in targets:
            print("\n" + "=" * 72)
            print(f"[chain] obj 0x{tgt:X} idx={idx} name={tname!r}")
            print(f"        name_slot={name_slot(tgt)} class_slot={class_slot(tgt)} outer_slot={outer_slot(tgt)}")
            # print vtable too
            try:
                vt = int.from_bytes(mr.read(tgt, 8), 'little')
                vt_rva = vt - MODULE_BASE if MODULE_BASE <= vt < MODULE_BASE + 0x20000000 else 0
                print(f"        vtable=0x{vt:X}  rva=0x{vt_rva:X}")
            except OSError:
                print(f"        vtable: <unreadable>")
            chain = walk_outer_chain(mr, tgt, ks)
            print_chain(chain)


if __name__ == '__main__':
    main()
