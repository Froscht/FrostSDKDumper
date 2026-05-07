#!/usr/bin/env python3
"""
FField NamePrivate decoder hunt with GROUND-TRUTH validation.

Strategy:
  1. Collect ARFilter's 10 FField slots (offsets 0..0x142).
  2. Reference SDK tells us field NAMES for each offset:
       0x00: PackageNames
       0x10: PackagePaths
       0x20: SoftObjectPaths
       0x30: ClassNames
       0x40: ClassPaths
       ...
  3. For each known-name field, scan live GNamePool for that name.
     The FName entry's index in the pool = the CI we want.
  4. Brute-force algorithms that map slot bytes → that exact CI.

GNamePool walking: gnames_base = 0x14DBE9E80; chunks at +0x18, +0x58, etc.
Each chunk has FNameEntry data. Entry header layout (CL-1177678):
  bit 0: isWide
  length = (hdr & 0x3FE) | (hdr >> 15)
After header, length chars of encrypted bytes.

Decryption uses XOR keystream from RVA_FNAME_KEY_TABLE = 0xDB2E894:
  for ANSI: byte[i] ^= u8(keystream[(key + i) & 0x3F] >> 3)
  initial key = length - 10563
"""
import os, struct, sys

# CL-1177678 module / FName decryption constants
MODULE_BASE = 0x140000000
GNAMEPOOL = MODULE_BASE + 0xDBE9E80
KEYSTREAM = MODULE_BASE + 0xDB2E894
LCG_OFFSET = -10563

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
    def read_u16(self, addr):
        d = self.read(addr, 2); return struct.unpack('<H', d)[0] if d else 0
    def close(self): os.close(self.fd)

def decrypt_fname_string(mem, entry_addr, keystream_u16):
    hdr = mem.read_u16(entry_addr)
    if hdr == 0: return None
    is_wide = (hdr & 1) != 0
    length = (hdr & 0x3FE) | (hdr >> 15)
    if length <= 0 or length > 1023: return None
    byte_count = length * 2 if is_wide else length
    if byte_count > 2048: return None
    buf = mem.read(entry_addr + 2, byte_count)
    if not buf: return None
    key = (length + LCG_OFFSET) & 0xFFFF
    out = bytearray(buf)
    if not is_wide:
        for i in range(length):
            out[i] ^= (keystream_u16[(key + i) & 0x3F] >> 3) & 0xFF
        try:
            return out.decode('ascii', errors='replace')
        except: return None
    else:
        # wide: word ^= keystream[(key+i) & 0x3F]
        result = []
        for i in range(length):
            wc = struct.unpack_from('<H', bytes(out), i*2)[0]
            wc ^= keystream_u16[(key + i) & 0x3F]
            if wc < 0x80: result.append(chr(wc))
            else: result.append('?')
        return ''.join(result)

def main():
    pid = find_game_pid()
    if not pid: print('[!] No Game PID'); return 1
    print(f'[+] Game PID: {pid}')
    mem = ProcMem(pid)

    # Read 64-entry u16 keystream
    ks_bytes = mem.read(KEYSTREAM, 64 * 2)
    keystream = list(struct.unpack('<64H', ks_bytes))
    print(f'[+] Keystream first 4 u16s: {[hex(x) for x in keystream[:4]]}')

    # Walk first chunk pointer at GNamePool+0x18
    chunk0_ptr = mem.read_u64(GNAMEPOOL + 0x18)
    print(f'[+] GNamePool first chunk @ {chunk0_ptr:#x}')

    # Names we want CIs for (from reference SDK ARFilter):
    # - ARFilter's 10 fields plus a couple of well-known short names for sanity
    target_names = {
        'PackageNames', 'PackagePaths', 'SoftObjectPaths', 'ClassNames',
        'ClassPaths', 'RecursiveClassesExclusionSet', 'TagsAndValues',
        'bRecursiveClasses', 'bRecursivePaths', 'bIncludeOnlyOnDiskAssets',
        'bWithoutPackageFlags',
        # Sanity:
        'Object', 'None', 'Pawn', 'Actor',
    }

    # Scan first chunk for FNameEntries. Entries are concatenated, header u16
    # then payload, padded to 2-byte alignment. We read ~256KB.
    print(f'[+] Scanning chunk[0] for known names (this may take a moment)...')
    chunk_size = 0x100000  # 1 MB scan
    chunk_data = mem.read(chunk0_ptr, chunk_size)
    if not chunk_data:
        print(f'[!] Could not read chunk[0]')
        mem.close()
        return 1

    found_cis = {}  # name -> first occurrence offset
    # Try parsing entries sequentially
    pos = 0
    entry_count = 0
    while pos + 2 < len(chunk_data):
        hdr = struct.unpack_from('<H', chunk_data, pos)[0]
        if hdr == 0:
            pos += 2
            continue
        is_wide = (hdr & 1) != 0
        length = (hdr & 0x3FE) | (hdr >> 15)
        if length <= 0 or length > 1023:
            pos += 2  # skip malformed
            continue
        byte_count = length * 2 if is_wide else length
        if pos + 2 + byte_count > len(chunk_data):
            break
        # Decrypt in place
        body = chunk_data[pos+2 : pos+2+byte_count]
        key = (length + LCG_OFFSET) & 0xFFFF
        if not is_wide:
            decoded = bytearray(body)
            for i in range(length):
                decoded[i] ^= (keystream[(key + i) & 0x3F] >> 3) & 0xFF
            try:
                s = decoded.decode('ascii', errors='strict')
            except: s = None
        else:
            chars = []
            ok = True
            for i in range(length):
                wc = struct.unpack_from('<H', body, i*2)[0]
                wc ^= keystream[(key + i) & 0x3F]
                if wc < 0x80: chars.append(chr(wc))
                else: ok = False; break
            s = ''.join(chars) if ok else None
        if s and s in target_names:
            if s not in found_cis:
                found_cis[s] = pos
                print(f'  Found "{s}" at chunk_offset {pos:#x}')
        entry_count += 1
        # Advance: header(2) + payload, aligned up to 2 bytes
        adv = 2 + byte_count
        if adv & 1: adv += 1
        pos += adv

    print(f'\n[+] Scanned {entry_count} FNameEntries in chunk[0] ({chunk_size//1024} KB)')
    print(f'[+] Found {len(found_cis)} known names:')
    for name, off in found_cis.items():
        print(f'  {name}: chunk_offset={off:#x}  (= chunk-local index)')

    # Compute a CI hint (need to know how chunk_offset maps to CI — usually
    # CI = (chunk_index << 16) | (chunk_offset / aligned_unit) for simple pools)
    print(f'\n[+] Note: chunk_offset is the FNameEntry byte offset, not the CI directly.')
    print(f'    The CI requires the FName resolver to map chunk_offset → ci.')
    print(f'    But finding the names tells us: the LIVE GNamePool DOES have these names,')
    print(f'    so they can in principle be resolved. The brute-force needs a CI lookup.')

    mem.close()
    return 0

if __name__ == '__main__':
    sys.exit(main())
