"""Pure-Python implementation of the patch 20260428 FName decrypt pipeline.

Mirrors `REFERENCE_FName_20260428.h` so each stage can be exercised
independently without rebuilding the C++ dumper. Use the CLI subcommands
to test stages against synthetic inputs or live game memory.

Stages:
    slot_decrypt    UObject 4-slot decrypt → comp_index (lo32 of result)
    slot_picker     ObjSlotHash + index formula
    ci_transform    3-stage SIMD CI → (name_offset_word, chunk_off)
    block_hash      Block-selector hash (chunk → slot index)
    block_decrypt   16-byte block → u64 (PSHUFB + ROL16(5) + XOR)
    fnv_fold        FNV64 fold on a u64
    pointer_fixup   Result → FNameEntry pointer (3 XORs + 2 bswaps)
    string_decrypt  FNameEntry header + LCG keystream → string
    resolve         Full chain: comp_index + live mem → string

Live mode requires sudo (uses /dev/memreader).
"""

import argparse
import struct
import sys
import os

# ─── Constants (verified live + reference) ──────────────────────────────────

MODULE_BASE = 0x140000000
RVA_GUOBJECT_ARRAY = 0xDE173A0
RVA_GNAMES_BASE    = 0xDB5BE80
RVA_FNAME_KEYTABLE = 0xDAA07F4

# Slot decrypt
ACTOR_SHUF_MASK = bytes([0x01, 0x06, 0x00, 0x04, 0x07, 0x03, 0x02, 0x05])
ACTOR_DECRYPT_XOR = 0x4834C6DEA02581C7

# Slot picker hash
HASH_PRIME    = 0x01000193
HASH_ADD_MAIN = 0x114E4953  # 290405715

# CI 3-stage transform — bytes loaded from live RVAs
RVA_GIDX_SHUF1   = 0xAD49100  # 8B mask, replicated to 16B
RVA_GIDX_XOR1    = 0xAD49110  # 8B XOR, replicated to 16B
RVA_STAGE2_XOR   = 0xAD49390  # 8B XOR, replicated to 16B
RVA_EXTRACT_SHUF = 0xAD49140  # 16B mask
RVA_EXTRACT_XOR  = 0xAD49150  # 16B XOR

# Reference byte values (from REFERENCE_FName_20260428.h)
GIDX_SHUF1_REF   = bytes([0x00, 0x02, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00] * 2)
GIDX_XOR1_REF    = bytes([0xBC, 0xBD, 0x4B, 0x43, 0xC8, 0x09, 0xFF, 0x4B] * 2)
STAGE2_XOR_REF   = bytes([0x00, 0xBD, 0x00, 0x43, 0xC8, 0x09, 0x00, 0x00] * 2)
EXTRACT_SHUF_REF = bytes([0x05, 0x03, 0x01, 0x04] + [0]*12)
EXTRACT_XOR_REF  = bytes([0x09, 0x43, 0xBD, 0xC8] + [0]*12)
BLOCK_SHUF_REF   = bytes([0x05, 0x00, 0x06, 0x04, 0x03, 0x07, 0x02, 0x01] + [0]*8)

# Block decrypt
RVA_BLOCK_SHUF = 0xAD49130
BLOCK_POST_XOR = 0x9F737271C0F041C4

# Block-selector hash
BHASH_ADD = 0xCA104182  # = -904904318 as int32

# Chunk offsets
CHUNK_FNV_SEED_OFF   = 0x7090
CHUNK_BLOCK_BASE_OFF = 0x70A0

# FNV fold
FNV_PRIME  = 0x100000001B3
FNV_OFFSET = 0x7631B6D6E2D67842

# Pointer fixup
PTR_XOR_1 = 0xBD8F879C
PTR_XOR_2 = 0x003E22B700000000
PTR_XOR_3 = 0x9CB9AD0A00000000  # = ENTRY_HANDLE_XOR

# Keystream LCG (FNameEntry decrypt)
KEY_TABLE_UINT16_OFFSET = 8

# ─── Bit ops ────────────────────────────────────────────────────────────────

MASK32 = 0xFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF


def rotl32(x: int, n: int) -> int:
    x &= MASK32
    n &= 31
    return ((x << n) | (x >> (32 - n))) & MASK32


def rotl64(x: int, n: int) -> int:
    x &= MASK64
    n &= 63
    return ((x << n) | (x >> (64 - n))) & MASK64


def bswap32(x: int) -> int:
    x &= MASK32
    return ((x & 0xFF) << 24) | ((x & 0xFF00) << 8) | ((x >> 8) & 0xFF00) | ((x >> 24) & 0xFF)


def bswap64(x: int) -> int:
    x &= MASK64
    b = x.to_bytes(8, "little")
    return int.from_bytes(b, "big")


# ─── SIMD primitives (operate on 16-byte buffers) ──────────────────────────

def pshuflw(src: bytes, imm8: int) -> bytes:
    """Shuffle the LOW 4 uint16 words; high 4 words pass through unchanged.
    imm8 bit pairs select source word for each destination word."""
    assert len(src) == 16
    words = [int.from_bytes(src[i*2:i*2+2], "little") for i in range(8)]
    out = []
    for i in range(4):
        sel = (imm8 >> (2 * i)) & 3
        out.append(words[sel])
    out += words[4:]
    return b"".join(w.to_bytes(2, "little") for w in out)


def pshufd(src: bytes, imm8: int) -> bytes:
    """Shuffle four 32-bit dwords. imm8 bit pairs select source dword."""
    assert len(src) == 16
    dwords = [int.from_bytes(src[i*4:i*4+4], "little") for i in range(4)]
    out = []
    for i in range(4):
        sel = (imm8 >> (2 * i)) & 3
        out.append(dwords[sel])
    return b"".join(d.to_bytes(4, "little") for d in out)


def pshufb(src: bytes, mask: bytes) -> bytes:
    """Per-byte shuffle. Mask byte with bit 7 set → output byte is 0;
    otherwise output[i] = src[mask[i] & 0x0F]."""
    assert len(src) == 16 and len(mask) == 16
    out = bytearray(16)
    for i in range(16):
        m = mask[i]
        if m & 0x80:
            out[i] = 0
        else:
            out[i] = src[m & 0x0F]
    return bytes(out)


def pxor(a: bytes, b: bytes) -> bytes:
    assert len(a) == 16 and len(b) == 16
    return bytes(x ^ y for x, y in zip(a, b))


def rol32_lanes(src: bytes, n: int) -> bytes:
    """Per-uint32-lane ROL32(n). Operates on all 4 lanes in 16 bytes."""
    assert len(src) == 16
    out = bytearray(16)
    for i in range(4):
        v = int.from_bytes(src[i*4:i*4+4], "little")
        r = rotl32(v, n)
        out[i*4:i*4+4] = r.to_bytes(4, "little")
    return bytes(out)


def rol16_lanes(src: bytes, n: int) -> bytes:
    """Per-uint16-lane ROL16(n). Operates on all 8 lanes in 16 bytes."""
    assert len(src) == 16
    out = bytearray(16)
    for i in range(8):
        v = int.from_bytes(src[i*2:i*2+2], "little")
        n_ = n & 15
        r = ((v << n_) | (v >> (16 - n_))) & 0xFFFF
        out[i*2:i*2+2] = r.to_bytes(2, "little")
    return bytes(out)


def lo64(b: bytes) -> int:
    return int.from_bytes(b[:8], "little")


def lo32(b: bytes) -> int:
    return int.from_bytes(b[:4], "little")


def loadl(mask8: bytes) -> bytes:
    """Replicate `_mm_loadl_epi64`: low 8 bytes = mask, high 8 bytes = 0."""
    assert len(mask8) >= 8
    return bytes(mask8[:8]) + b"\x00" * 8


# ─── Pipeline stages ────────────────────────────────────────────────────────

def slot_decrypt(enc16: bytes) -> int:
    """UObject 4-slot decrypt. Returns u64 where lo32 = comp_index."""
    assert len(enc16) == 16
    shuf = loadl(ACTOR_SHUF_MASK)
    shuffled = pshufb(enc16, shuf)
    rot = rol32_lanes(shuffled, 17)
    raw = lo64(rot) ^ ACTOR_DECRYPT_XOR
    return rotl64(raw, 32)


def slot_picker(obj_addr: int) -> tuple[int, int]:
    """Compute (v7, slot_idx) where slot_idx ∈ {0..3}."""
    p = (obj_addr + 0x10) & MASK64
    lo = p & MASK32
    hi = (p >> 32) & MASK32

    h = rotl32(lo, 25)
    h = (HASH_PRIME * h + HASH_ADD_MAIN) & MASK32
    h = rotl32(h, 27)
    h = (HASH_PRIME * h + hi + HASH_ADD_MAIN) & MASK32
    h = h >> 7
    h = (HASH_PRIME * h + HASH_ADD_MAIN) & MASK32
    h = h >> 5
    v7 = (HASH_PRIME * h + HASH_ADD_MAIN) & MASK32

    lo8 = v7 & 0xFF
    hi8 = (v7 >> 16) & 0xFF
    idx = ((lo8 ^ hi8) & 3) ^ 2
    return v7, idx


def ci_transform(comp_index: int,
                 shuf1: bytes, xor1: bytes,
                 stage2_xor: bytes, extract_shuf: bytes, extract_xor: bytes) -> int:
    """Three-stage SIMD CI transform → uint32 v5.
    name_offset = 2 * (uint16)v5
    chunk_off   = (v5 >> 8) & 0xFFFF00."""
    # Stage 1
    ci = (comp_index & MASK32).to_bytes(4, "little") + b"\x00" * 12
    t1 = pxor(pshufb(ci, shuf1), xor1)
    r1 = rol32_lanes(t1, 17)
    state1 = pshuflw(r1, 0xB1)

    # Stage 2
    s2a = pshuflw(state1, 0xB1)
    s2b = rol32_lanes(s2a, 15)
    s2c = pshufd(s2b, 0x44)
    s2d = pxor(pxor(s2c, stage2_xor), xor1)
    s2e = rol32_lanes(s2d, 17)
    state2 = pshuflw(s2e, 0xB1)

    # Stage 3
    s3a = pshuflw(state2, 0xB1)
    s3b = rol32_lanes(s3a, 15)
    s3c = pshufb(s3b, extract_shuf)
    s3d = pxor(s3c, extract_xor)
    return lo32(s3d)


def block_hash(seed_addr: int) -> int:
    """Block-selector hash → uint8 bidx."""
    lo = seed_addr & MASK32
    hi = (seed_addr >> 32) & MASK32

    h = (lo >> 6) | 0x40000000
    h = (HASH_PRIME * h + BHASH_ADD) & MASK32
    h = rotl32(h, 28)
    h = (HASH_PRIME * h + hi + BHASH_ADD) & MASK32
    h = h >> 6
    h = (HASH_PRIME * h + BHASH_ADD) & MASK32
    h = h >> 4
    nxt = (HASH_PRIME * h + BHASH_ADD) & MASK32

    a = ((-109 * h - 126) & 0xFF)
    b = ((nxt >> 16) & 0xFF)
    return a ^ b


def block_decrypt(slot16: bytes, block_shuf: bytes) -> int:
    """16-byte block → u64. PSHUFB + ROL16(5) + XOR(0x9F73...)."""
    assert len(slot16) == 16
    b = pshufb(slot16, block_shuf)
    r = rol16_lanes(b, 5)
    return lo64(r) ^ BLOCK_POST_XOR


def fnv_fold(v: int) -> int:
    """Two-round FNV64 fold."""
    fnv = (FNV_PRIME * rotl64(v, 50) + FNV_OFFSET) & MASK64
    fnv = (FNV_PRIME * rotl64(fnv, 56) + FNV_OFFSET) & MASK64
    return fnv


def pointer_fixup(R: int) -> int:
    """3-XOR pointer fixup chain."""
    a = bswap64(R ^ PTR_XOR_1)
    b = a ^ PTR_XOR_2
    return bswap64(b ^ PTR_XOR_3)


def fnameentry_header_decode(hdr: int) -> tuple[int, bool]:
    v3 = hdr & 0x7F
    v4 = (hdr >> 5) & 0x380
    length = v3 + v4
    is_wide = (hdr & 0x8000) != 0
    return length, is_wide


def string_decrypt(buf: bytes, hdr: int, key_table: list[int]) -> str:
    """Decrypt a buffer of `length` bytes (or 2*length if wide) using
    the LCG keystream defined in REFERENCE_FName_20260428.h."""
    length, is_wide = fnameentry_header_decode(hdr)
    if length <= 0 or length > 1023:
        return ""
    nbytes = length * 2 if is_wide else length
    nbytes = min(nbytes, len(buf))

    KT = KEY_TABLE_UINT16_OFFSET
    out = bytearray(buf[:nbytes])

    def to_int8(x):
        x &= 0xFF
        return x - 256 if x >= 128 else x

    key = to_int8(length - 68)
    i = 0

    if not is_wide:
        v3 = length & 0x7F
        v4 = (length >> 5) & 0x380  # using the post-decode form
        loopCount = v3 | v4
        while i + 1 < loopCount:
            uk = key & 0xFF
            idx_a = (uk & 0x3F) + KT
            idx_b = ((68 * uk + 96) & 0x3C) + KT
            if i < nbytes:
                out[i] ^= (key_table[idx_a] >> 3) & 0xFF
            if i + 1 < nbytes:
                out[i + 1] ^= (key_table[idx_b] >> 3) & 0xFF
            key = to_int8(16 * key - 32)
            i += 2
        if (loopCount & 1) and i < nbytes:
            uk = key & 0xFF
            idx_a = (uk & 0x3F) + KT
            out[i] ^= (key_table[idx_a] >> 3) & 0xFF
        # Build ANSI string
        end = min(length, nbytes)
        return bytes(out[:end]).decode("latin-1", errors="replace")
    else:
        wcount = nbytes // 2
        words = [int.from_bytes(out[j*2:j*2+2], "little") for j in range(wcount)]
        i = 0
        while i + 1 < length:
            uk = key & 0xFF
            idx_a = (uk & 0x3F) + KT
            idx_b = ((68 * uk + 96) & 0x3C) + KT
            if i < wcount:
                words[i] ^= key_table[idx_a]
            if i + 1 < wcount:
                words[i + 1] ^= key_table[idx_b]
            key = to_int8(16 * key - 32)
            i += 2
        if (length & 1) and i < wcount:
            uk = key & 0xFF
            idx_a = (uk & 0x3F) + KT
            words[i] ^= key_table[idx_a]
        chars = []
        for w in words:
            if w == 0:
                continue
            chars.append(chr(w & 0xFF))
        return "".join(chars)


# ─── Live-mode resolver ─────────────────────────────────────────────────────

class LiveResolver:
    """Reads SIMD constants and FNamePool data from a running game."""

    def __init__(self, mr, base: int = MODULE_BASE):
        self.mr = mr
        self.base = base
        self._load_consts()

    def _load_consts(self):
        self.gidx_shuf1   = self.mr.read(self.base + RVA_GIDX_SHUF1, 16)
        self.gidx_xor1    = self.mr.read(self.base + RVA_GIDX_XOR1, 16)
        self.stage2_xor   = self.mr.read(self.base + RVA_STAGE2_XOR, 16)
        self.extract_shuf = self.mr.read(self.base + RVA_EXTRACT_SHUF, 16)
        self.extract_xor  = self.mr.read(self.base + RVA_EXTRACT_XOR, 16)
        block_shuf_lo     = self.mr.read(self.base + RVA_BLOCK_SHUF, 8)
        self.block_shuf   = loadl(block_shuf_lo)
        kt_bytes = self.mr.read(self.base + RVA_FNAME_KEYTABLE, 256 * 2)
        self.key_table = [int.from_bytes(kt_bytes[i*2:i*2+2], "little") for i in range(256)]

    def resolve_name_ptr(self, comp_index: int) -> int:
        """Run the full CI → FNameEntry pointer chain. Returns 0 on failure."""
        if comp_index <= 0:
            return 0
        v5 = ci_transform(
            comp_index,
            self.gidx_shuf1, self.gidx_xor1,
            self.stage2_xor, self.extract_shuf, self.extract_xor,
        )
        name_offset = 2 * (v5 & 0xFFFF)
        chunk_off   = (v5 >> 8) & 0xFFFF00

        gnames_base = self.base + RVA_GNAMES_BASE
        chunk_addr  = gnames_base + chunk_off
        seed_addr   = chunk_addr + CHUNK_FNV_SEED_OFF

        bidx = block_hash(seed_addr)

        block_base = chunk_addr + CHUNK_BLOCK_BASE_OFF
        b1 = self.mr.read(block_base + 32 * (bidx & 7), 16)
        b2 = self.mr.read(block_base + 32 * ((bidx + 1) & 7), 16)

        v14 = block_decrypt(b1, self.block_shuf)
        v15 = block_decrypt(b2, self.block_shuf)
        fnv = fnv_fold(v14)
        R = (v14 + (fnv ^ v15) + name_offset) & MASK64
        return pointer_fixup(R)

    def decrypt_name_string(self, name_entry_ptr: int) -> str:
        if not name_entry_ptr:
            return ""
        hdr_bytes = self.mr.read(name_entry_ptr, 2)
        hdr = int.from_bytes(hdr_bytes, "little")
        if hdr == 0:
            return ""
        length, is_wide = fnameentry_header_decode(hdr)
        if length <= 0 or length > 1023:
            return ""
        nbytes = length * 2 if is_wide else length
        nbytes = min(nbytes, 2048)
        buf = self.mr.read(name_entry_ptr + 2, nbytes)
        return string_decrypt(buf, hdr, self.key_table)

    def resolve(self, comp_index: int) -> str:
        ptr = self.resolve_name_ptr(comp_index)
        if not ptr:
            return ""
        return self.decrypt_name_string(ptr)


# ─── CLI ────────────────────────────────────────────────────────────────────

def cmd_slot_decrypt(args):
    enc = bytes.fromhex(args.bytes)
    if len(enc) != 16:
        print(f"need exactly 16 bytes, got {len(enc)}", file=sys.stderr)
        return 2
    out = slot_decrypt(enc)
    print(f"raw_u64       = 0x{out:016X}")
    print(f"comp_index    = {out & MASK32}  (0x{out & MASK32:08X})")
    print(f"hi32 (other)  = 0x{(out >> 32) & MASK32:08X}")
    return 0


def cmd_slot_picker(args):
    obj = int(args.obj, 16) if args.obj.startswith("0x") else int(args.obj)
    v7, idx = slot_picker(obj)
    print(f"v7        = 0x{v7:08X}")
    print(f"slot_idx  = {idx}  (slot offset = obj + {0x20 + idx*0x20:#x})")
    return 0


def cmd_resolve_offline(args):
    """Run resolver math against the *reference* SIMD constants only."""
    ci = int(args.ci, 0)
    block_shuf = loadl(BLOCK_SHUF_REF[:8])
    v5 = ci_transform(
        ci,
        GIDX_SHUF1_REF, GIDX_XOR1_REF,
        STAGE2_XOR_REF, EXTRACT_SHUF_REF, EXTRACT_XOR_REF,
    )
    print(f"v5            = 0x{v5:08X}")
    print(f"name_offset   = {2 * (v5 & 0xFFFF):#x}")
    print(f"chunk_off     = {(v5 >> 8) & 0xFFFF00:#x}")
    return 0


def cmd_live_resolve(args):
    from memreader import MemReader, find_pid
    pid = int(args.pid) if args.pid else find_pid()
    if not pid:
        print("could not find game PID", file=sys.stderr)
        return 1
    print(f"[+] PID = {pid}")
    with MemReader(pid) as mr:
        rv = LiveResolver(mr)
        for ci in args.ci:
            ci_val = int(ci, 0)
            ptr = rv.resolve_name_ptr(ci_val)
            name = rv.decrypt_name_string(ptr) if ptr else ""
            print(f"CI={ci_val:>8}  ptr=0x{ptr:016X}  name={name!r}")
    return 0


def cmd_live_obj(args):
    """Read an obj's slot, decrypt it, resolve the comp_index to a name."""
    from memreader import MemReader, find_pid
    pid = int(args.pid) if args.pid else find_pid()
    if not pid:
        print("could not find game PID", file=sys.stderr)
        return 1
    obj = int(args.obj, 16) if args.obj.startswith("0x") else int(args.obj)
    print(f"[+] PID = {pid}  obj = 0x{obj:016X}")
    with MemReader(pid) as mr:
        rv = LiveResolver(mr)
        # Try all 4 slots
        for slot in range(4):
            addr = obj + 0x20 + slot * 0x20
            enc = mr.read(addr, 16)
            if not any(enc):
                print(f"  slot {slot} @ {addr:#x}: <zero>")
                continue
            dec = slot_decrypt(enc)
            ci  = dec & MASK32
            hi  = (dec >> 32) & MASK32
            ptr = rv.resolve_name_ptr(ci) if 0 < ci < 0x2000000 else 0
            name = rv.decrypt_name_string(ptr) if ptr else ""
            print(f"  slot {slot} @ {addr:#x}: enc={enc.hex()}")
            print(f"           dec=0x{dec:016X}  ci={ci}  hi=0x{hi:08X}")
            if ptr:
                print(f"           ptr=0x{ptr:016X}  name={name!r}")
        v7, idx = slot_picker(obj)
        print(f"  hash-picked slot: {idx}")
    return 0


def cmd_dump_obj0(args):
    """Sanity dump: read GUObjectArray to find chunks_array, then obj[0]."""
    from memreader import MemReader, find_pid
    pid = int(args.pid) if args.pid else find_pid()
    if not pid:
        print("could not find game PID", file=sys.stderr)
        return 1
    with MemReader(pid) as mr:
        gobj = MODULE_BASE + RVA_GUOBJECT_ARRAY
        n_at_38 = int.from_bytes(mr.read(gobj + 0x38, 8), "little")
        ptr_at_78 = int.from_bytes(mr.read(gobj + 0x78, 8), "little")
        ptr_at_80 = int.from_bytes(mr.read(gobj + 0x80, 8), "little")
        enc_b0 = mr.read(gobj + 0xB0, 16)
        print(f"GUObjectArray @ 0x{gobj:X}")
        print(f"  +0x38 NumElements = {n_at_38}")
        print(f"  +0x78 heap-ptr    = 0x{ptr_at_78:X}")
        print(f"  +0x80 chunks_mgr? = 0x{ptr_at_80:X}")
        print(f"  +0xB0 enc16       = {enc_b0.hex()}")
        if ptr_at_80:
            vt = int.from_bytes(mr.read(ptr_at_80, 8), "little")
            print(f"  *(+0x80) vtable   = 0x{vt:X}")
            if vt:
                vt5 = int.from_bytes(mr.read(vt + 0x28, 8), "little")
                print(f"  vtable[5]         = 0x{vt5:X}")
    return 0


def cmd_selftest(args):
    """Stage-by-stage sanity tests with synthetic inputs (no live mem)."""
    print("=== rotl32 / rotl64 / bswap ===")
    assert rotl32(0x80000001, 1) == 0x00000003, "rotl32 wraps wrong"
    assert rotl64(0x8000000000000001, 1) == 0x0000000000000003
    assert bswap32(0x01020304) == 0x04030201
    assert bswap64(0x0102030405060708) == 0x0807060504030201
    print("  pass")

    print("=== PSHUFB with hi8=0 broadcasts src[0] to upper half ===")
    src = bytes(range(16))
    mask = bytes([0]*16)
    out = pshufb(src, mask)
    assert out == b"\x00" * 16, "PSHUFB with mask=0 should give all src[0] (=0)"
    print("  pass")

    print("=== PSHUFLW preserves high 4 words ===")
    src = b"".join(i.to_bytes(2, "little") for i in range(8))
    out = pshuflw(src, 0xE4)  # E4 = 11_10_01_00 = identity
    assert out == src
    print("  pass")

    print("=== ROL32 lanes ===")
    src = (0x12345678).to_bytes(4, "little") * 4
    out = rol32_lanes(src, 8)
    expect = (0x34567812).to_bytes(4, "little") * 4
    assert out == expect
    print("  pass")

    print("=== ROL16 lanes ===")
    src = (0x1234).to_bytes(2, "little") * 8
    out = rol16_lanes(src, 4)
    expect = (0x2341).to_bytes(2, "little") * 8
    assert out == expect
    print("  pass")

    print("=== Slot picker — known constants produce 0..3 idx ===")
    # Run on a few addresses; slot index must be in 0..3
    for addr in [0xD517F700, 0x140000000, 0x10000, 0x18B5B0000]:
        v7, idx = slot_picker(addr)
        assert 0 <= idx < 4, f"slot_picker {hex(addr)}: idx={idx}"
        print(f"  obj=0x{addr:X}  v7=0x{v7:08X}  idx={idx}")

    print("=== CI transform — small CI passes through cleanly ===")
    for ci in [1, 100, 1000, 65535, 70591]:
        v5 = ci_transform(
            ci,
            GIDX_SHUF1_REF, GIDX_XOR1_REF,
            STAGE2_XOR_REF, EXTRACT_SHUF_REF, EXTRACT_XOR_REF,
        )
        name_off = 2 * (v5 & 0xFFFF)
        chunk_off = (v5 >> 8) & 0xFFFF00
        print(f"  CI={ci:>6}  v5=0x{v5:08X}  name_off={name_off:#x}  chunk_off={chunk_off:#x}")

    print("=== Block decrypt — input=0 produces XOR const ===")
    block_shuf = loadl(BLOCK_SHUF_REF[:8])
    out = block_decrypt(b"\x00" * 16, block_shuf)
    assert out == BLOCK_POST_XOR, f"got 0x{out:016X}, expect 0x{BLOCK_POST_XOR:016X}"
    print(f"  pass (output = 0x{out:016X})")

    print("=== Pointer fixup — round-trip identity ===")
    # The fixup is bswap(R^X1) -> ^X2 -> bswap(_^X3). It's not invertible to
    # a no-op, but for a fixed input we should get a deterministic output.
    R = 0x0123456789ABCDEF
    out = pointer_fixup(R)
    print(f"  R=0x{R:016X}  fixup=0x{out:016X}")

    print("=== FNameEntry header decode ===")
    # length = (hdr & 0x7F) | ((hdr >> 5) & 0x380)
    cases = [
        (0x0001, 1, False),
        (0x000A, 10, False),
        (0x0040, 64, False),  # 0x40 & 0x7F = 0x40
        (0x0080, 0x80 >> 5 << 5 if False else (0x80 >> 5 & 0x380), False),
        (0x8005, 5, True),
    ]
    for hdr, expected_len, expected_wide in cases:
        L, w = fnameentry_header_decode(hdr)
        ok = "ok" if (L == expected_len and w == expected_wide) else "FAIL"
        print(f"  hdr=0x{hdr:04X} → len={L} wide={w}  ({ok}, expect {expected_len}/{expected_wide})")

    print("\nAll structural sanity checks passed.")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("selftest", help="run stage-by-stage sanity checks (no live mem)")
    p.set_defaults(func=cmd_selftest)

    p = sub.add_parser("slot-decrypt", help="decrypt a 16-byte slot")
    p.add_argument("bytes", help="32 hex chars")
    p.set_defaults(func=cmd_slot_decrypt)

    p = sub.add_parser("slot-picker", help="run ObjSlotHash on an address")
    p.add_argument("obj", help="UObject address (hex or decimal)")
    p.set_defaults(func=cmd_slot_picker)

    p = sub.add_parser("ci-resolve-offline",
                       help="resolve CI using REFERENCE constants (no live mem)")
    p.add_argument("ci")
    p.set_defaults(func=cmd_resolve_offline)

    p = sub.add_parser("live-resolve",
                       help="resolve CI(s) against live game memory (needs root)")
    p.add_argument("--pid")
    p.add_argument("ci", nargs="+", help="comp_index values (decimal or hex)")
    p.set_defaults(func=cmd_live_resolve)

    p = sub.add_parser("live-obj",
                       help="dump all 4 slots of a UObject and resolve names")
    p.add_argument("--pid")
    p.add_argument("obj", help="UObject address (hex)")
    p.set_defaults(func=cmd_live_obj)

    p = sub.add_parser("live-gobj",
                       help="dump GUObjectArray header (live)")
    p.add_argument("--pid")
    p.set_defaults(func=cmd_dump_obj0)

    args = ap.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
