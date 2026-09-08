#!/usr/bin/env python3
"""Live probe for the v908 UObject slot decoder and class/outer resolution.

Verifies GetFName, GetClassPtr, GetOuterPtr against live UObjects and reports
what fraction of a random sample decode to plausible names. This is the same
math the C++ dispatcher runs, so a discrepancy between this probe and the
dumper's [+] Classes count points at the dispatcher, not the crypto.
"""
from __future__ import annotations
import os, sys, struct, random
sys.path.insert(0, os.path.dirname(__file__))
from memreader import MemReader, find_pid
from v908_fname_probe import (
    MODULE_BASE, POOL_RVA, BLOCK_BASE_OFF, BLOCK_STRIDE,
    shard_hash_orig, slot_c1315578, dec_block1_padd, dec_block2_padd, fnv_chain,
    MASK64, KEYSTREAM_RVA,
)

# UObject GetFName constants (from Windows arc_decrypt v20260908)
UOBJ_SEED_OFF     = 0x10
UOBJ_SLOT_BASE    = 0x20
UOBJ_SLOT_STRIDE  = 0x20
UOBJ_HASH_PRIME   = 0x01000193
UOBJ_HASH_ADD     = 0x99C193C4  # SUBTRACTIVE
UOBJ_IDX_ADD      = 209796      # 0x33384
UOBJ_ROL_A        = 13
UOBJ_ROL_B        = 22
UOBJ_ROL_C        = 13
UOBJ_SHR          = 10
UOBJ_NAME_XOR     = 2   # Name  = Idx ^ 2
UOBJ_CLASS_ADJ    = 1   # Class = (Idx + 1) & 3
UOBJ_OUTER_ADJ    = 0   # Outer = Idx

SLOT_KEY_LO64     = 0x06CC58E720047BF7
SLOT_PSHUF_MASK   = [0x02, 0x05, 0x04, 0x06, 0x00, 0x07, 0x01, 0x03]
UOBJ_PSHUFLW_IMM  = 30
UOBJ_ROL64        = 17
UOBJ_NAME_ROL64   = 32

# FUObjectItem layout (UE 5.7)
CHUNK_ARRAY_RVA   = 0x10D853F0
CHUNKMGR_KEY_RVA  = 0xD4B22B0
STRIDE            = 24
OBJ_OFF           = 8
ITEMS_PER_CHUNK   = 65536

MASK32 = 0xFFFFFFFF


def rol32(x, n):
    n &= 31; x &= MASK32
    return ((x << n) | (x >> (32 - n))) & MASK32 if n else x


def rol64(x, n):
    n &= 63; x &= MASK64
    return ((x << n) | (x >> (64 - n))) & MASK64 if n else x


def pshuflw(lo, imm):
    words = [(lo >> (i*16)) & 0xFFFF for i in range(4)]
    out = 0
    for i in range(4):
        src = (imm >> (i*2)) & 3
        out |= words[src] << (i*16)
    return out & MASK64


def pshufb8(lo, mask):
    src = [(lo >> (i*8)) & 0xFF for i in range(8)]
    out = 0
    for i in range(8):
        out |= src[mask[i] & 7] << (i*8)
    return out & MASK64


def slot_hash(obj):
    seed = (obj + UOBJ_SEED_OFF) & MASK64
    lo = seed & MASK32
    hi = (seed >> 32) & MASK32
    P = UOBJ_HASH_PRIME
    A = UOBJ_HASH_ADD
    s1 = (P * rol32(lo, UOBJ_ROL_A) - A) & MASK32
    s2 = (P * rol32(s1, UOBJ_ROL_B)) & MASK32
    s3 = rol32((hi + s2 - A) & MASK32, UOBJ_ROL_C)
    T  = (P * s3 - A) & MASK32
    v3 = (P * (T >> UOBJ_SHR)) & MASK32
    return v3


def slot_index_base(obj):
    v3 = slot_hash(obj)
    idx = (((v3 & 0xFF) ^ (((v3 + UOBJ_IDX_ADD) >> 16) & 0xFF)) & 3)
    return idx


def name_slot(obj):  return slot_index_base(obj) ^ UOBJ_NAME_XOR
def class_slot(obj): return (slot_index_base(obj) + UOBJ_CLASS_ADJ) & 3
def outer_slot(obj): return (slot_index_base(obj) + UOBJ_OUTER_ADJ) & 3


def decode_slot16(lo):
    x = pshuflw(lo, UOBJ_PSHUFLW_IMM) ^ SLOT_KEY_LO64
    x = rol64(x, UOBJ_ROL64)
    x = pshufb8(x, SLOT_PSHUF_MASK)
    return rol64(x, UOBJ_NAME_ROL64)


def resolve_fname(mr, ci):
    """CI -> FNameEntry* via v908 pool pipeline."""
    chunk_off = ((ci >> 8) & 0xFFFF00)
    name_off = ci & 0xFFFF
    chunk_addr = MODULE_BASE + POOL_RVA + chunk_off
    seed = chunk_addr + 0x2490
    T = shard_hash_orig(seed)
    b1 = slot_c1315578(T)
    b2 = (b1 + 1) & 7
    try:
        r1 = int.from_bytes(mr.read(chunk_addr + BLOCK_BASE_OFF + BLOCK_STRIDE * b1, 8), 'little')
        r2 = int.from_bytes(mr.read(chunk_addr + BLOCK_BASE_OFF + BLOCK_STRIDE * b2, 8), 'little')
    except OSError:
        return 0
    V13 = dec_block1_padd(r1)
    V15 = dec_block2_padd(r2)
    Fv2 = fnv_chain(V13)
    return (V13 + (V15 ^ Fv2) + 2*name_off) & MASK64


def decrypt_string(mr, entry, ks):
    """Decrypt narrow FNameEntry string. Wide not implemented."""
    if not entry or entry < 0x10000:
        return None
    try:
        hdr = int.from_bytes(mr.read(entry, 2), 'little')
    except OSError:
        return None
    wide = bool(hdr & 0x8000)
    if wide:
        return None  # skip wide for now
    length = (hdr & 7) | ((hdr >> 5) & 0x3F8)
    if length == 0 or length > 200:
        return None
    try:
        cipher = mr.read(entry + 2, length)
    except OSError:
        return None
    # Paired key schedule matching Windows DecryptNarrow.
    key = (length + 0x2E0) & MASK32
    step_pair = 0x67E
    out = bytearray()
    i = 0
    while i + 1 < length:
        idx1 = key & 0x3F
        idx2 = (key - 1) & 0x3F
        # KS index 120 = byte offset +0xF0 above KEYSTREAM_RVA. Read word.
        if (idx1+120)*2+1 >= len(ks) or (idx2+120)*2+1 >= len(ks):
            return None
        w1 = ks[(idx1+120)*2] | (ks[(idx1+120)*2+1] << 8)
        w2 = ks[(idx2+120)*2] | (ks[(idx2+120)*2+1] << 8)
        k1 = (w1 >> 3) & 0xFF
        k2 = (w2 >> 3) & 0xFF
        out.append(cipher[i] ^ k1)
        out.append(cipher[i+1] ^ k2)
        key = (key + step_pair) & MASK32
        i += 2
    if i < length:  # odd tail
        idx = key & 0x3F
        w = ks[(idx+120)*2] | (ks[(idx+120)*2+1] << 8)
        out.append(cipher[i] ^ ((w >> 3) & 0xFF))
    return bytes(out)


def get_obj_name(mr, obj, ks):
    """Full pipeline: obj -> slot -> decode -> FName lo32 -> pool -> string."""
    idx = name_slot(obj)
    slot_addr = obj + UOBJ_SLOT_BASE + UOBJ_SLOT_STRIDE * idx
    try:
        raw16 = mr.read(slot_addr, 16)
    except OSError:
        return None
    lo = int.from_bytes(raw16[:8], 'little')
    if lo == 0:
        return None
    fname = decode_slot16(lo)
    ci = fname & MASK32
    entry = resolve_fname(mr, ci)
    return decrypt_string(mr, entry, ks)


def get_class_ptr(mr, obj):
    idx = class_slot(obj)
    slot_addr = obj + UOBJ_SLOT_BASE + UOBJ_SLOT_STRIDE * idx
    try:
        raw16 = mr.read(slot_addr, 16)
    except OSError:
        return 0
    lo = int.from_bytes(raw16[:8], 'little')
    if lo == 0:
        return 0
    ptr = decode_slot16(lo)
    if ptr < 0x10000 or ptr >= 0x800000000000:
        return 0
    return ptr


def get_outer_ptr(mr, obj):
    idx = outer_slot(obj)
    slot_addr = obj + UOBJ_SLOT_BASE + UOBJ_SLOT_STRIDE * idx
    try:
        raw16 = mr.read(slot_addr, 16)
    except OSError:
        return 0
    lo = int.from_bytes(raw16[:8], 'little')
    if lo == 0:
        return 0
    ptr = decode_slot16(lo)
    if ptr < 0x10000 or ptr >= 0x800000000000:
        return 0
    return ptr


# ── Chunk-manager decrypt ─────────────────────────────────────────────────
def decrypt_chunkmgr(blob_lo, key_lo):
    x = blob_lo ^ key_lo
    # ROL16(13) per word on low 64
    words = [(x >> (i*16)) & 0xFFFF for i in range(4)]
    words = [((w << 13) | (w >> 3)) & 0xFFFF for w in words]
    x = 0
    for i, w in enumerate(words):
        x |= w << (i*16)
    # PSHUFLW(imm=27)
    return pshuflw(x, 27)


def main():
    pid = int(sys.argv[1]) if len(sys.argv) > 1 else find_pid()
    if not pid:
        sys.exit("no PID")
    print(f"[+] PID = {pid}")
    with MemReader(pid) as mr:
        ks = mr.read(MODULE_BASE + KEYSTREAM_RVA, 512)

        # Decrypt chunk manager
        enc = mr.read(MODULE_BASE + CHUNK_ARRAY_RVA, 16)
        key = mr.read(MODULE_BASE + CHUNKMGR_KEY_RVA, 16)
        blob = int.from_bytes(enc[:8], 'little')
        keylo = int.from_bytes(key[:8], 'little')
        mgr = decrypt_chunkmgr(blob, keylo)
        print(f"[+] chunkmgr enc lo64=0x{blob:X}  key lo64=0x{keylo:X}")
        print(f"[+] chunkmgr decoded = 0x{mgr:X}")

        # Try reading NumElements + ChunkArray via published offsets
        try:
            num_raw = int.from_bytes(mr.read(mgr + 4, 4), 'little')
            arr_raw = int.from_bytes(mr.read(mgr + 0x30, 8), 'little')
            num = int.from_bytes(num_raw.to_bytes(4, 'little')[::-1], 'little') ^ 0xBD497AA1
            arr = int.from_bytes(arr_raw.to_bytes(8, 'little')[::-1], 'little') ^ 0x6BC7FB8600000000
            print(f"[+] NumElements = {num}")
            print(f"[+] ChunkArray  = 0x{arr:X}")
        except OSError as e:
            print(f"[-] mgr read failed: {e}")
            return

        if num <= 0 or num > 2_000_000 or arr < 0x10000:
            print("[-] bogus manager decode")
            return

        # Sample UObjects across all chunks
        num_chunks = (num + ITEMS_PER_CHUNK - 1) // ITEMS_PER_CHUNK
        print(f"[+] {num_chunks} chunks, sampling 200 objects")
        random.seed(42)
        indices = [random.randrange(num) for _ in range(200)]
        named = 0
        classed = 0
        printable = 0
        seen_class_names = {}
        for i, idx in enumerate(indices):
            ci = idx >> 16
            slot = idx & 0xFFFF
            try:
                chunk_ptr = int.from_bytes(mr.read(arr + 8*ci, 8), 'little')
            except OSError:
                continue
            if chunk_ptr < 0x10000:
                continue
            item = chunk_ptr + STRIDE * slot
            try:
                obj = int.from_bytes(mr.read(item + OBJ_OFF, 8), 'little')
            except OSError:
                continue
            if obj < 0x10000:
                continue
            name = get_obj_name(mr, obj, ks)
            if name is None:
                continue
            named += 1
            is_printable = all(32 <= b < 127 for b in name)
            if is_printable:
                printable += 1
                if i < 5:
                    print(f"  idx={idx:6d} obj=0x{obj:X} name={name!r}")
                # class ptr
                cls = get_class_ptr(mr, obj)
                if cls:
                    cname = get_obj_name(mr, cls, ks)
                    if cname:
                        classed += 1
                        seen_class_names[cname] = seen_class_names.get(cname, 0) + 1
        print(f"\n[stats] named={named}/200 printable={printable}/200 with-class={classed}/200")
        top = sorted(seen_class_names.items(), key=lambda x: -x[1])[:20]
        for cn, cnt in top:
            print(f"  {cnt:3d}× {cn!r}")


if __name__ == '__main__':
    main()
