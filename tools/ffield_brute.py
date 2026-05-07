#!/usr/bin/env python3
"""
Brute-force the FField NamePrivate decoder algorithm on CL-1177678.

Strategy:
  1. Walk the FField chain of a known UScriptStruct (ARFilter) via /proc/<pid>/mem
  2. Collect 8-16 NamePrivate slots (16 bytes each at FField+0x30)
  3. Brute-force all combinations of:
     - shufflelo immediate (256 values)
     - per-uint32-lane ROL32 amount (1..31)
     - PXOR with one of N candidate xor consts (or none)
     - PSHUFB with one of M candidate masks (or none)
     - ROL64 amount (0,7,11,16,32,41,53)
  4. Score: how many slots produce VALID, UNIQUE, SMALL (< 0x80000) CIs
  5. Best params (highest score) likely == real algorithm

Requires sudo for /proc/<pid>/mem read access.
"""
import os
import struct
import sys
from itertools import product

# Game PID — find from /proc/*/comm == "GameThread"
def find_game_pid():
    for entry in os.listdir('/proc'):
        if not entry.isdigit():
            continue
        try:
            with open(f'/proc/{entry}/comm') as f:
                if 'GameThread' in f.read():
                    return int(entry)
        except (OSError, IOError):
            continue
    return None

class ProcMem:
    def __init__(self, pid):
        self.pid = pid
        self.fd = os.open(f'/proc/{pid}/mem', os.O_RDONLY)

    def read(self, addr, size):
        try:
            return os.pread(self.fd, size, addr)
        except OSError as e:
            return None

    def read_u64(self, addr):
        data = self.read(addr, 8)
        return struct.unpack('<Q', data)[0] if data else 0

    def close(self):
        os.close(self.fd)

# ── SIMD primitives ────────────────────────────────────────────────────────────
def rotl32(x, n): return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
def rotl64(x, n): return ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF
def rotl16(x, n): return ((x << n) | (x >> (16 - n))) & 0xFFFF

def shufflelo(buf, mask):
    """SSE PSHUFLW: shuffle 4 u16s in low qword by 2-bit selectors in mask."""
    u16s = list(struct.unpack('<8H', buf))
    sel = [(mask >> (i*2)) & 3 for i in range(4)]
    new_lo = [u16s[s] for s in sel]
    return struct.pack('<4H', *new_lo) + buf[8:16]

def rol32_lanes(buf, n):
    out = bytearray()
    for i in range(4):
        u = struct.unpack_from('<I', buf, i*4)[0]
        out += struct.pack('<I', rotl32(u, n))
    return bytes(out)

def rol16_lanes(buf, n):
    out = bytearray()
    for i in range(8):
        u = struct.unpack_from('<H', buf, i*2)[0]
        out += struct.pack('<H', rotl16(u, n))
    return bytes(out)

def pshufb(buf, mask):
    out = bytearray(16)
    for i in range(16):
        m = mask[i]
        out[i] = 0 if (m & 0x80) else buf[m & 0x0F]
    return bytes(out)

def pxor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

# ── Walk FField chain to collect slots ───────────────────────────────────────
def collect_slots(mem, ustruct_addr, max_count=16):
    """Walk FField chain at ustruct+0x100 → +0x118 → +0xC0 (try several heads),
    follow Next pointer at +0x48, read NamePrivate at +0x30."""
    slots = []
    chain_offsets = [0x100, 0x118, 0xC0, 0xE0, 0xB8]
    for chain_off in chain_offsets:
        ff = mem.read_u64(ustruct_addr + chain_off)
        if ff < 0x100000 or ff >= 0x800000000000:
            continue
        seen = set()
        for _ in range(max_count):
            if ff in seen or ff < 0x100000 or ff >= 0x800000000000:
                break
            seen.add(ff)
            slot = mem.read(ff + 0x30, 16)
            if not slot or all(b == 0 for b in slot):
                break
            slots.append((ff, slot))
            ff = mem.read_u64(ff + 0x48)  # Next
            if len(slots) >= max_count:
                break
        if slots:
            break  # found a working chain head
    return slots

# ── Brute-force ────────────────────────────────────────────────────────────────
def score_params(slots, xform_func):
    """Apply xform to each slot, count how many produce valid unique small CIs."""
    cis = []
    for _, slot in slots:
        try:
            result = xform_func(slot)
        except Exception:
            return 0, []
        ci = result & 0xFFFFFFFF
        num = result >> 32
        # Must be in plausible CI range AND Number must be small
        if not (1 < ci < 0x80000):
            return 0, []
        if num > 0x100:
            return 0, []
        cis.append(ci)
    if len(set(cis)) != len(cis):
        return 0, cis  # duplicates suggest wrong params
    return len(cis), cis

def main():
    pid = find_game_pid()
    if not pid:
        print('[!] No GameThread PID found')
        return 1
    print(f'[+] Game PID: {pid}')

    mem = ProcMem(pid)

    # Try known UScriptStructs: ARFilter (lots of fields), TopLevelAssetPath, etc.
    candidates = [
        ('ARFilter', 0x8B9F4DE0),
        ('TopLevelAssetPath', 0x8B9F5200),
        # Add more if needed
    ]
    all_slots = []
    for name, addr in candidates:
        slots = collect_slots(mem, addr, max_count=16)
        print(f'  {name} @ {addr:#x}: collected {len(slots)} FField slots')
        for ff_addr, slot in slots:
            print(f'    FField {ff_addr:#x}: {slot.hex()}')
        all_slots.extend(slots)

    if len(all_slots) < 2:
        print('[!] Need at least 2 slots to validate; aborting')
        mem.close()
        return 1

    print(f'\n[+] Total {len(all_slots)} slots collected. Brute-forcing decoder…')

    # Known .rdata constants
    XOR_CONSTS = {
        'ADD1110': 0x15DE19C2226E19C2,
        'ADD0CA0': 0x82344B319BA94B71,
        'ADB8B10': 0xDD91E63DEC24EA21,
        'AD9F790': 0x226E19C213DB15DE,
        'CL1177146_FField': 0x9A492C85DDF6F193,
        'zero': 0,
    }
    # PSHUFB masks (low 8 bytes; rest=0 for low-only or replicated for full)
    PSHUFB_MASKS = {
        'ADEAC80': bytes.fromhex('06000104070302050000000000000000'),
        'AD97CC0': bytes.fromhex('02050007010403060000000000000000'),
        'none': None,
    }
    # The output goes through up to: shufflelo, ROL32_lanes, [PXOR], [PSHUFB], lo64, [XOR const], ROL64
    # Brute-force most flexible variant. Total combos: 256 × 31 × 7 × 6 × 8 = ~2.6M

    best = []
    SHUFFLES = [0x39, 0x1B, 0x2E, 0x4B, 0x72, 0xED, 0x57, 0x9C, 0xB1, 0xC6]
    ROL32_AMTS = [3, 7, 13, 17, 19, 22, 25, 26]
    ROL64_AMTS = [0, 7, 11, 16, 32, 41, 53]
    XOR_NAMES = list(XOR_CONSTS.keys())
    MASK_NAMES = list(PSHUFB_MASKS.keys())

    total_combos = 0
    for shuf, r32, mask_name, pre_xor_name, post_xor_name, r64 in product(
        SHUFFLES, ROL32_AMTS, MASK_NAMES, XOR_NAMES, XOR_NAMES, ROL64_AMTS
    ):
        total_combos += 1
        mask = PSHUFB_MASKS[mask_name]
        pre_xor_const = XOR_CONSTS[pre_xor_name]
        post_xor_const = XOR_CONSTS[post_xor_name]
        # Build pre_xor as 16-byte buffer for SIMD
        pre_xor_bytes = struct.pack('<Q', pre_xor_const) * 2

        def xform(slot):
            s = shufflelo(slot, shuf)
            s = rol32_lanes(s, r32)
            if pre_xor_const != 0:
                s = pxor(s, pre_xor_bytes)
            if mask is not None:
                s = pshufb(s, mask)
            lo64 = struct.unpack_from('<Q', s, 0)[0]
            lo64 ^= post_xor_const
            return rotl64(lo64, r64)

        score, cis = score_params(all_slots, xform)
        if score >= 2:
            best.append((score, shuf, r32, mask_name, pre_xor_name, post_xor_name, r64, cis))

    print(f'[+] Tried {total_combos} combinations')
    if not best:
        print('[!] No valid parameter set found at score >= 2')
    else:
        best.sort(key=lambda x: -x[0])
        print(f'[+] Top {min(20, len(best))} parameter sets:')
        for entry in best[:20]:
            score, shuf, r32, mn, prx, pox, r64, cis = entry
            print(f'  score={score}/{len(all_slots)}: shuffle=0x{shuf:02x} ROL32({r32}) pre_xor={prx} mask={mn} post_xor={pox} ROL64({r64})  CIs: {cis[:5]}…')

    mem.close()
    return 0

if __name__ == '__main__':
    sys.exit(main())
