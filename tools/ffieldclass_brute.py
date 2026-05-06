#!/usr/bin/env python3
"""
Ground-truth-validated FFieldClass NamePrivate decoder hunt.

Use the WELL-KNOWN type names (BoolProperty=CI 10, ArrayProperty=CI 56, etc.)
verified live at GNamePool+0x64C8+.

For each ARFilter FField, its ClassPrivate (FField+0x50) → FFieldClass instance.
That FFieldClass+0x30 has the encrypted type-name slot. We know what type each
FField is (from refSDK ARFilter struct).

ARFilter mapping (refSDK):
  offset 0x00..0x40: 5x TArray<...>   → FArrayProperty     → expected CI = 56
  offset 0xA0, 0xF0: 2x TMap<..., ...> → FMapProperty       → expected CI = ? (let's brute it)
  offset 0x140..0x142: 3x bool        → FBoolProperty      → expected CI = 10

Procedure:
  1. Walk live ARFilter FField chain.
  2. For each FField, read ClassPrivate (the FFieldClass).
  3. Read FFieldClass+0x30 (16-byte NamePrivate slot).
  4. Brute-force algorithms; score = matches expected-CI count.
  5. Top algorithm wins.
"""
import os, struct, sys
from itertools import product

ARFILTER_ADDR = 0x8B9F4DE0

# Expected FFieldClass type → CI (from live game, GNamePool registration table)
KNOWN_TYPE_CIS = {
    'BoolProperty':   10,
    'FloatProperty':  17,
    'ObjectProperty': 24,
    'NameProperty':   32,
    'DelegateProperty':40,
    'DoubleProperty': 47,
    'ArrayProperty':  56,
    'StructProperty': 64,
    'StrProperty':    72,
    'TextProperty':   80,
}

# ARFilter offset → expected FFieldClass type name (from refSDK)
ARFILTER_TYPES = {
    0x00: 'ArrayProperty',
    0x10: 'ArrayProperty',
    0x20: 'ArrayProperty',
    0x30: 'ArrayProperty',
    0x40: 'ArrayProperty',
    0xA0: 'MapProperty',  # CI unknown — brute-force candidate
    0xF0: 'MapProperty',  # same
    0x140: 'BoolProperty',
    0x141: 'BoolProperty',
    0x142: 'BoolProperty',
}

def find_game_pid():
    for entry in os.listdir('/proc'):
        if not entry.isdigit(): continue
        try:
            with open(f'/proc/{entry}/comm') as f:
                if 'GameThread' in f.read(): return int(entry)
        except (OSError, IOError): continue
    return None

class ProcMem:
    def __init__(self, pid):
        self.fd = os.open(f'/proc/{pid}/mem', os.O_RDONLY)
    def read(self, addr, size):
        try: return os.pread(self.fd, size, addr)
        except OSError: return None
    def read_u64(self, addr):
        d = self.read(addr, 8); return struct.unpack('<Q', d)[0] if d else 0
    def read_u32(self, addr):
        d = self.read(addr, 4); return struct.unpack('<I', d)[0] if d else 0
    def close(self): os.close(self.fd)

def rotl32(x, n): return ((x << n) | (x >> (32-n))) & 0xFFFFFFFF
def rotl64(x, n): return ((x << n) | (x >> (64-n))) & 0xFFFFFFFFFFFFFFFF

def shufflelo(buf, mask):
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

def pshufb(buf, mask):
    out = bytearray(16)
    for i in range(16):
        m = mask[i]
        out[i] = 0 if (m & 0x80) else buf[m & 0x0F]
    return bytes(out)

def pxor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def main():
    pid = find_game_pid()
    if not pid: return 1
    mem = ProcMem(pid)
    print(f'[+] Game PID: {pid}')

    # Walk ARFilter FField chain → for each, read its FFieldClass+0x30 slot
    samples = []
    ff = 0
    for chain_off in [0x100, 0xC0, 0xE0, 0xB8, 0x118]:
        cand = mem.read_u64(ARFILTER_ADDR + chain_off)
        if 0x100000 <= cand < 0x800000000000:
            ff = cand
            print(f'[+] ARFilter chain head found at +0x{chain_off:x} = {ff:#x}')
            break
    if not ff:
        print('[!] No valid ARFilter chain head found')
        return 1

    seen = set()
    while ff and ff not in seen and len(samples) < 12:
        seen.add(ff)
        # Decode offset_internal (try +0x88 and +0x8C)
        real_off = None
        for try_pos in (0x88, 0x8C):
            stored = mem.read_u32(ff + try_pos)
            x = stored ^ 0xCCCCACBB
            cand = ((x >> 24) | ((x >> 8) & 0xFF00) |
                    ((x << 8) & 0xFF0000) | ((x << 24) & 0xFFFFFFFF)) & 0xFFFFFFFF
            if cand < 0x10000:
                real_off = cand
                break
        # Read ClassPrivate (FFieldClass instance pointer)
        fc_addr = mem.read_u64(ff + 0x50)
        # Read FFieldClass+0x30 slot
        fc_slot = mem.read(fc_addr + 0x30, 16) if (0x100000 <= fc_addr < 0x800000000000) else None
        samples.append((ff, real_off, fc_addr, fc_slot))
        ff = mem.read_u64(ff + 0x48)

    print(f'[+] Walked {len(samples)} ARFilter FFields:')
    for ff, off, fc, slot in samples:
        slot_hex = slot.hex() if slot else 'NULL'
        expected = ARFILTER_TYPES.get(off, '???')
        print(f'  +{off:#x} FField={ff:#x} FFieldClass={fc:#x} slot={slot_hex} expected_type={expected}')
    mem.close()

    # Group: distinct FFieldClass addresses + their expected CIs
    fc_groups = {}  # fc_addr → (slot, expected_type, expected_ci)
    for ff, off, fc, slot in samples:
        if fc and slot and off in ARFILTER_TYPES:
            etype = ARFILTER_TYPES[off]
            eci = KNOWN_TYPE_CIS.get(etype)
            fc_groups.setdefault(fc, (slot, etype, eci))

    print(f'\n[+] Distinct FFieldClass instances: {len(fc_groups)}')
    for fc, (slot, etype, eci) in fc_groups.items():
        print(f'  {fc:#x}: type={etype} expected_CI={eci}  slot={slot.hex()}')

    # Filter to those with KNOWN expected CI
    known = [(fc, slot, eci) for fc, (slot, etype, eci) in fc_groups.items() if eci]
    print(f'[+] {len(known)} FFieldClass instances with KNOWN expected CIs')

    if len(known) < 2:
        print('[!] Need at least 2 different FFieldClass instances with known CIs')
        return 1

    # Now brute-force algorithms — must produce expected_ci for ALL known samples
    PSHUFB_MASKS = {
        'ADEAC80': bytes.fromhex('06000104070302050000000000000000'),
        'AD97CC0': bytes.fromhex('02050007010403060000000000000000'),
        'none': None,
    }
    XOR_CONSTS = {
        'ADD1110': 0x15DE19C2226E19C2,
        'ADD0CA0': 0x82344B319BA94B71,
        'AD9F790': 0x226E19C213DB15DE,
        'CL1177146_FField': 0x9A492C85DDF6F193,
        'zero': 0,
    }
    SHUFFLES = [None, 0x39, 0x1B, 0x2E, 0x4B, 0x72, 0xED, 0x57, 0x4C, 0xC9]
    ROL32_AMTS = [None, 3, 7, 11, 13, 16, 17, 19, 22, 25, 26]
    ROL64_AMTS = [None, 0, 7, 11, 13, 16, 32, 41, 47, 53]

    print(f'\n[+] Brute-forcing FFieldClass NamePrivate decoder…')
    matches = []
    total = 0
    for shuf, r32, mask_name, pre_xor_name, post_xor_name, r64 in product(
        SHUFFLES, ROL32_AMTS, PSHUFB_MASKS.keys(), XOR_CONSTS.keys(), XOR_CONSTS.keys(), ROL64_AMTS
    ):
        total += 1
        mask = PSHUFB_MASKS[mask_name]
        pre = XOR_CONSTS[pre_xor_name]
        post = XOR_CONSTS[post_xor_name]
        pre_bytes = struct.pack('<Q', pre) * 2 if pre else None

        score = 0
        produced = []
        for fc, slot, expected_ci in known:
            try:
                s = slot
                if shuf is not None: s = shufflelo(s, shuf)
                if r32 is not None: s = rol32_lanes(s, r32)
                if pre_bytes: s = pxor(s, pre_bytes)
                if mask is not None: s = pshufb(s, mask)
                lo64 = struct.unpack_from('<Q', s, 0)[0]
                lo64 ^= post
                if r64 is not None: lo64 = rotl64(lo64, r64)
                ci = lo64 & 0xFFFFFFFF
            except Exception:
                ci = -1
            produced.append(ci)
            if ci == expected_ci:
                score += 1
        if score >= len(known):  # ALL must match
            matches.append((score, shuf, r32, mask_name, pre_xor_name, post_xor_name, r64, produced))

    print(f'[+] Tried {total} algorithm combinations')
    if not matches:
        print('[!] No algorithm matches ALL known CIs')
        # Show partial-match top scorers
        return 1

    print(f'[+] {len(matches)} algorithms match ALL {len(known)} expected CIs:')
    for m in matches[:10]:
        score, shuf, r32, mn, prx, pox, r64, produced = m
        print(f'  score={score}/{len(known)}: shuffle={shuf} ROL32({r32}) pre_xor={prx} mask={mn} post_xor={pox} ROL64({r64})')

    return 0

if __name__ == '__main__':
    sys.exit(main())
