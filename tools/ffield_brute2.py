#!/usr/bin/env python3
"""
Smarter FField NamePrivate decoder hunt.

Insight from collected slots:
  All have form `XX F3 9X XX 4X 91 7E 76 XX F3 9X XX 4X 91 7E 76` (replicated lo==hi)
  Bytes 4..7 are NEAR-CONSTANT (`4X 91 7E 76`) across slots — this is the
  session-wide constant. Bytes 0..3 vary per slot (= encoded CI).

Strategy: directly DERIVE the XOR const from the constant high pattern.
After ROL32(N), the constant lane should equal the FIXED XOR const used
for cancellation. Try every ROL32 amount and check if rotating the
constant high-lane gives a stable value across ALL slots.

Also try: PSHUFB-only-on-lo8 algorithms, no-shuffle algorithms,
and direct lo32 extraction without any cancellation.
"""
import os, struct, sys
from itertools import product

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
        data = self.read(addr, 8); return struct.unpack('<Q', data)[0] if data else 0
    def close(self): os.close(self.fd)

def rotl32(x, n): return ((x << n) | (x >> (32-n))) & 0xFFFFFFFF
def rotl64(x, n): return ((x << n) | (x >> (64-n))) & 0xFFFFFFFFFFFFFFFF
def rotl16(x, n): return ((x << n) | (x >> (16-n))) & 0xFFFF

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

def rol16_lanes(buf, n):
    out = bytearray()
    for i in range(8):
        u = struct.unpack_from('<H', buf, i*2)[0]
        out += struct.pack('<H', rotl16(u, n))
    return bytes(out)

def collect_slots(mem, addr, max_count=20):
    slots = []
    for chain_off in [0x100, 0x118, 0xC0, 0xE0, 0xB8]:
        ff = mem.read_u64(addr + chain_off)
        if ff < 0x100000 or ff >= 0x800000000000: continue
        seen = set()
        for _ in range(max_count):
            if ff in seen or ff < 0x100000 or ff >= 0x800000000000: break
            seen.add(ff)
            slot = mem.read(ff + 0x30, 16)
            if not slot or all(b == 0 for b in slot): break
            slots.append((ff, slot))
            ff = mem.read_u64(ff + 0x48)
            if len(slots) >= max_count: break
        if slots: break
    return slots

def main():
    pid = find_game_pid()
    if not pid: return 1
    mem = ProcMem(pid)

    # Collect from multiple structs for diversity
    candidates = [
        ('ARFilter', 0x8B9F4DE0),
        ('TopLevelAssetPath', 0x8B9F5200),
    ]
    all_slots = []
    for name, addr in candidates:
        slots = collect_slots(mem, addr, max_count=20)
        all_slots.extend(slots)
    print(f'[+] Collected {len(all_slots)} slots')

    if len(all_slots) < 4: mem.close(); return 1

    # Print slot byte breakdown
    print('\n[+] Slot bytes (lo qword only — hi qword is replicated):')
    for ff_addr, slot in all_slots:
        print(f'  {ff_addr:#x}: {slot[:8].hex()} == {slot[8:16].hex()}? {slot[:8] == slot[8:16]}')

    # Extract just lo64 from each slot
    los = [struct.unpack('<Q', s[:8])[0] for _, s in all_slots]

    # Approach 1: maybe decoder is just ROL32-per-lane-then-XOR-with-self-rotated
    # → result depends on diff between lanes after rotation.
    # For replicated slot, lane0 == lane2, lane1 == lane3.
    # Check what (lane0_rot XOR lane1_rot) gives for various rotations:
    print('\n[+] Lane-XOR experiment:')
    for r in [0, 7, 13, 17, 19, 22, 25, 26]:
        cis = []
        for lo64 in los:
            l0 = lo64 & 0xFFFFFFFF
            l1 = (lo64 >> 32) & 0xFFFFFFFF
            r0 = rotl32(l0, r); r1 = rotl32(l1, r)
            x = r0 ^ r1
            cis.append(x)
        sample = [hex(c) for c in cis[:4]]
        small = sum(1 for c in cis if 1 < c < 0x80000)
        print(f'  ROL32({r}) lane0 XOR lane1: small={small}/{len(cis)}  sample={sample}')

    # Approach 2: ROL32 on full slot then XOR low half with high half
    print('\n[+] Slot ROL32-per-lane then lo64 XOR hi64:')
    for r in range(1, 32):
        cis = []
        for _, slot in all_slots:
            s = rol32_lanes(slot, r)
            lo = struct.unpack_from('<Q', s, 0)[0]
            hi = struct.unpack_from('<Q', s, 8)[0]
            x = lo ^ hi
            cis.append(x)
        small = sum(1 for c in cis if 1 < c < 0x80000)
        if small >= 4:
            print(f'  ROL32({r}): small={small}/{len(cis)}  sample={[hex(c) for c in cis[:6]]}')

    # Approach 3: shufflelo + ROL32 + lane0 XOR lane1
    print('\n[+] shufflelo + ROL32 + lane0 XOR lane1:')
    for shuf in range(256):
        for r in range(1, 32):
            cis = []
            ok = True
            for _, slot in all_slots:
                s = shufflelo(slot, shuf)
                s = rol32_lanes(s, r)
                l0 = struct.unpack_from('<I', s, 0)[0]
                l1 = struct.unpack_from('<I', s, 4)[0]
                x = l0 ^ l1
                if not (1 < x < 0x80000): ok = False; break
                cis.append(x)
            if ok and len(set(cis)) == len(cis):
                print(f'  shuffle={shuf:#x} ROL32({r}): unique CIs {cis[:8]}…')

    # Approach 4: shufflelo + ROL32 + extract specific u32 lanes (no XOR)
    print('\n[+] shufflelo + ROL32 + raw lane extract (try each of 4 lanes):')
    for shuf in range(256):
        for r in range(1, 32):
            for lane_idx in range(4):
                cis = []
                ok = True
                for _, slot in all_slots:
                    s = shufflelo(slot, shuf)
                    s = rol32_lanes(s, r)
                    val = struct.unpack_from('<I', s, lane_idx * 4)[0]
                    if not (1 < val < 0x80000): ok = False; break
                    cis.append(val)
                if ok and len(set(cis)) == len(cis):
                    print(f'  shuffle={shuf:#x} ROL32({r}) lane{lane_idx}: unique CIs {cis[:8]}…')

    # Approach 5: ROL32 per-lane, then XOR result with a CONSTANT u64 (cancellation)
    # Try: for each ROL32 amount, compute hi64 after rotation. If it's CONSTANT
    # across all slots (replicated form might preserve), then THAT is the
    # cancellation key. XOR lo64 with that key → CI candidate.
    print('\n[+] Constant-hi64-after-rotation scan:')
    for r in range(1, 32):
        hi_after_rot = []
        for _, slot in all_slots:
            s = rol32_lanes(slot, r)
            hi64 = struct.unpack_from('<Q', s, 8)[0]
            hi_after_rot.append(hi64)
        if len(set(hi_after_rot)) == 1:
            xor_key = hi_after_rot[0]
            cis = []
            ok = True
            for _, slot in all_slots:
                s = rol32_lanes(slot, r)
                lo64 = struct.unpack_from('<Q', s, 0)[0]
                final = lo64 ^ xor_key
                ci = final & 0xFFFFFFFF
                num = final >> 32
                if not (0 <= ci < 0x80000 and num < 0x100): ok = False; break
                cis.append(ci)
            if ok:
                print(f'  ROL32({r}) → constant hi64=0x{xor_key:x}: CIs {cis[:8]}')

    mem.close()
    return 0

if __name__ == '__main__':
    sys.exit(main())
