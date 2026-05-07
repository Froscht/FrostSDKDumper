#!/usr/bin/env python3
"""
Ground-truth-validated FField NamePrivate decoder hunt.

Workflow:
  1. From refSDK, ARFilter has 10 fields with KNOWN names + offsets.
  2. Walk live ARFilter FField chain via /proc/<pid>/mem.
  3. For each FField, get its slot bytes AND its offset_internal (decoded).
  4. Map offset → expected name via refSDK.
  5. For each algorithm variant, compute the candidate CI from the slot.
  6. Use FrostDumper --emu-fname to look up the CI's resolved name.
  7. Score: number of slots whose CI resolves to the EXPECTED ARFilter field name.
  8. Top scoring algorithm wins.

This validates against LIVE memory + LIVE FName resolver — no refSDK trust,
just refSDK as a SOURCE of expected field names.

Single-thread, /proc/<pid>/mem (no kernel module hammering).
"""
import os, struct, sys, subprocess
from itertools import product

REF_SDK_ARFILTER_FIELDS = {
    # offset → expected field name (from refSDK CoreUObject_structs.hpp)
    0x00: 'PackageNames',
    0x10: 'PackagePaths',
    0x20: 'SoftObjectPaths',
    0x30: 'ClassNames',
    0x40: 'ClassPaths',
    0xA0: 'RecursiveClassesExclusionSet',
    0xF0: 'RecursiveClassPathsExclusionSet',
    0x140: 'bRecursivePaths',
    0x141: 'bRecursiveClasses',
    0x142: 'bIncludeOnlyOnDiskAssets',
}

ARFILTER_ADDR = 0x8B9F4DE0  # known live addr from dump_classes.txt

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

# Build a set of algorithm variants (parameterized)
# Output the lo32 of the final value as the CI candidate.
def build_variants():
    variants = []
    # PSHUFB masks to try (live RVAs from refdata):
    PSHUFB_MASKS = {
        'ADEAC80': bytes.fromhex('06000104070302050000000000000000'),
        'AD97CC0': bytes.fromhex('02050007010403060000000000000000'),
        'reversed_ADEAC80': bytes.fromhex('05020307040100060000000000000000'),  # bit-reversed permutation
        'identity': bytes(range(16)),
        'none': None,
    }
    # XOR consts
    XOR_CONSTS = {
        'ADD1110': 0x15DE19C2226E19C2,
        'ADD0CA0': 0x82344B319BA94B71,
        'AD9F790': 0x226E19C213DB15DE,
        'CL1177146_FField': 0x9A492C85DDF6F193,
        'session_const_lo': 0x767E9148,  # LE u32 of the constant `48 91 7e 76`
        'session_const_lo64': 0x767E9148_767E9148,  # replicated
        'zero': 0,
    }
    SHUFFLES = [None, 0x39, 0x1B, 0x2E, 0x4B, 0x72, 0xED, 0x57, 0x4C, 0xC9, 0xB1]
    ROL32_AMTS = [None, 3, 7, 11, 13, 16, 17, 19, 22, 25, 26]
    ROL64_AMTS = [None, 7, 11, 13, 16, 32, 41, 47, 53]
    POST_OPS = ['lo32', 'hi32', 'bswap_lo32', 'lo32_xor_hi32']

    for shuf, r32, mask_name, pre_xor_name, r64, post_op in product(
        SHUFFLES, ROL32_AMTS, PSHUFB_MASKS.keys(), XOR_CONSTS.keys(),
        ROL64_AMTS, POST_OPS
    ):
        mask = PSHUFB_MASKS[mask_name]
        pre_xor_const = XOR_CONSTS[pre_xor_name]
        if pre_xor_const != 0:
            pre_xor_bytes = struct.pack('<Q', pre_xor_const) * 2
        else:
            pre_xor_bytes = None

        def make_xform(shuf=shuf, r32=r32, mask=mask, pre_xor_bytes=pre_xor_bytes,
                       r64=r64, post_op=post_op):
            def xform(slot):
                s = slot
                if shuf is not None:
                    s = shufflelo(s, shuf)
                if r32 is not None:
                    s = rol32_lanes(s, r32)
                if pre_xor_bytes is not None:
                    s = pxor(s, pre_xor_bytes)
                if mask is not None:
                    s = pshufb(s, mask)
                lo64 = struct.unpack_from('<Q', s, 0)[0]
                if r64 is not None:
                    lo64 = rotl64(lo64, r64)
                if post_op == 'lo32':
                    return lo64 & 0xFFFFFFFF
                elif post_op == 'hi32':
                    return (lo64 >> 32) & 0xFFFFFFFF
                elif post_op == 'bswap_lo32':
                    swapped = ((lo64 >> 56) | ((lo64 >> 40) & 0xFF00) |
                               ((lo64 >> 24) & 0xFF0000) | ((lo64 >> 8) & 0xFF000000))
                    return swapped & 0xFFFFFFFF
                elif post_op == 'lo32_xor_hi32':
                    return (lo64 & 0xFFFFFFFF) ^ ((lo64 >> 32) & 0xFFFFFFFF)
            return xform
        tag = f'shuf={shuf}/r32={r32}/mask={mask_name}/xor={pre_xor_name}/r64={r64}/{post_op}'
        variants.append((tag, make_xform()))
    return variants

def decode_offset(stored, xor_key=0xCCCCACBB):
    """offset = bswap32(stored XOR xor_key)."""
    x = stored ^ xor_key
    return ((x >> 24) | ((x >> 8) & 0xFF00) |
            ((x << 8) & 0xFF0000) | ((x << 24) & 0xFFFFFFFF)) & 0xFFFFFFFF

def collect_arfilter_slots(mem):
    """Walk ARFilter's FField chain. Return [(offset, slot_bytes, ff_addr), ...].
    Try BOTH +0x88 and +0x8C for offset_internal — pick the one that gives
    small (< 0x10000) decoded offset."""
    slots = []
    for chain_off in [0x100, 0xC0, 0xE0, 0xB8, 0x118]:
        ff = mem.read_u64(ARFILTER_ADDR + chain_off)
        if ff < 0x100000 or ff >= 0x800000000000:
            continue
        seen = set()
        while ff and ff not in seen and len(slots) < 12:
            seen.add(ff)
            slot = mem.read(ff + 0x30, 16)
            if not slot or all(b == 0 for b in slot): break
            # Try both candidate Offset_Internal positions
            best_off = None
            for try_pos in (0x88, 0x8C):
                stored = mem.read_u32(ff + try_pos)
                cand = decode_offset(stored)
                if cand < 0x10000:  # plausible UE5 field offset
                    best_off = cand
                    break
            slots.append((best_off if best_off is not None else 0xFFFFFFFF, slot, ff))
            ff = mem.read_u64(ff + 0x48)
        if slots:
            return slots
    return slots

def emu_lookup(ci):
    """Use FrostDumper --emu-fname to resolve a CI to its name string."""
    try:
        result = subprocess.run(
            ['sudo', './FrostDumper', '--emu-fname', str(ci)],
            cwd='/media/frost/Coding Stuf/Linux/FrostSDKDumper',
            capture_output=True, text=True, timeout=20,
        )
        for line in result.stdout.splitlines():
            if f'CI {ci} →' in line:
                # extract `"name"`
                start = line.find('"')
                end = line.rfind('"')
                if start != -1 and end > start:
                    return line[start+1:end]
        return None
    except (subprocess.TimeoutExpired, OSError):
        return None

def main():
    pid = find_game_pid()
    if not pid: return 1
    print(f'[+] Game PID: {pid}')
    mem = ProcMem(pid)

    slots = collect_arfilter_slots(mem)
    print(f'[+] Collected {len(slots)} ARFilter FFields:')
    for off, slot, ff in slots:
        expected = REF_SDK_ARFILTER_FIELDS.get(off, '???')
        print(f'  +{off:#x} (FField {ff:#x}): {slot.hex()}  [expected: {expected}]')
    mem.close()

    # Filter to only slots with KNOWN expected names
    known_slots = [(off, slot) for off, slot, ff in slots
                   if off in REF_SDK_ARFILTER_FIELDS]
    if len(known_slots) < 3:
        print(f'[!] Only {len(known_slots)} known-name slots; not enough for ground truth')
        return 1

    print(f'\n[+] Building algorithm variants…')
    variants = build_variants()
    print(f'[+] {len(variants)} variants to test')

    # PRE-FILTER: keep only variants where ALL slot CIs are valid-range and unique.
    # This thins down to a manageable set BEFORE we hit the slow emu lookup.
    print(f'[+] Pre-filtering by valid + unique CIs…')
    candidates = []
    for tag, xform in variants:
        cis = []
        ok = True
        for off, slot in known_slots:
            try: ci = xform(slot)
            except: ok = False; break
            if not (1 < ci < 0x80000): ok = False; break
            cis.append(ci)
        if ok and len(set(cis)) == len(cis):
            candidates.append((tag, cis))

    print(f'[+] {len(candidates)} candidates pass valid+unique filter')
    if not candidates:
        print('[!] No viable candidates found')
        return 1

    # Save candidates for offline analysis
    with open('/tmp/ffield_candidates.txt', 'w') as f:
        for tag, cis in candidates[:200]:
            f.write(f'{tag}: {cis}\n')
    print(f'[+] Saved top 200 to /tmp/ffield_candidates.txt')

    # Pick one CI from the FIRST slot (offset 0x0 = expected "PackageNames")
    # and use the emu to look up names for ALL distinct CIs across candidates.
    # If ANY produce "PackageNames", that's a strong match.
    print(f'\n[+] Validating top candidates against live emu (looking for "PackageNames")…')
    target_name = REF_SDK_ARFILTER_FIELDS[0x00]  # "PackageNames"

    distinct_cis = set()
    for _, cis in candidates:
        distinct_cis.add(cis[0])  # CI for slot offset 0x0
    print(f'[+] {len(distinct_cis)} distinct CI candidates for offset 0x0')

    # Try first 30 distinct CIs via emu (slow — emu takes ~3s each)
    found_match = None
    tried = 0
    for ci in sorted(distinct_cis)[:30]:
        name = emu_lookup(ci)
        tried += 1
        if name and target_name in name:
            print(f'  [HIT] CI={ci} → "{name}"')
            found_match = ci
            break
        elif name:
            short = name[:20] + '…' if len(name) > 20 else name
            print(f'  CI={ci} → "{short}"')

    if found_match:
        print(f'\n[+] Ground truth: ARFilter offset 0x0 ("PackageNames") → CI={found_match}')
        # Now find ALL algorithms that produced this CI for slot 0
        winners = [tag for tag, cis in candidates if cis[0] == found_match]
        print(f'[+] {len(winners)} algorithms produce this CI:')
        for tag in winners[:10]:
            print(f'  {tag}')
    else:
        print(f'\n[!] No algorithm produced "PackageNames" CI within the {tried} candidates tested')
        print(f'    Either: (a) algorithm space is bigger than tested, or')
        print(f'            (b) "PackageNames" is not in live GNamePool (unlikely)')

    return 0

if __name__ == '__main__':
    sys.exit(main())
