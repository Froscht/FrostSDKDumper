#!/usr/bin/env python3
import struct, sys

PID = 12035
MODULE_BASE = 0x140000000
PSHUFB_MASK = [6,5,2,3,4,1,0,7]
AUTO_XOR = 0x5EA772D07F910744
CLASS_META = 0x76598800

def read_mem(pid, addr, sz):
    with open(f"/proc/{pid}/mem", "rb") as f:
        f.seek(addr)
        return f.read(sz)

def pshufb_lo64(data):
    out = bytearray(8)
    for i in range(8):
        idx = PSHUFB_MASK[i]
        out[i] = data[idx] if idx < len(data) else 0
    return struct.unpack('<Q', out)[0]

KnownClasses = [
    0x39789700,   # Actor
    0x765BBB00,   # ActorComponent
    0x76966100,   # GameplayCueNotify_Actor
]

print(f"Expected ClassPrivate (Class metaclass) = 0x{CLASS_META:016X}")
print(f"Auto-discovered XOR key = 0x{AUTO_XOR:016X}")
print()

for cls_addr in KnownClasses:
    data = read_mem(PID, cls_addr, 0xA0)
    vt = struct.unpack_from('<Q', data, 0)[0]
    print(f"UClass @ 0x{cls_addr:X}  vtable=0x{vt:X} (RVA=0x{vt-MODULE_BASE:X})")

    for slot in range(4):
        off = 0x20 + slot * 0x20
        enc = data[off:off+16]
        lo_enc = struct.unpack_from('<Q', enc, 0)[0]

        shuffled = pshufb_lo64(enc)

        ptr_auto = shuffled ^ AUTO_XOR

        needed_xor = shuffled ^ CLASS_META

        name_dec = ((shuffled ^ AUTO_XOR) >> 32 | (shuffled ^ AUTO_XOR) << 32) & 0xFFFFFFFFFFFFFFFF
        name_ci = name_dec & 0xFFFFFFFF

        print(f"  Slot {slot} [{off:02X}]: enc={enc[:8].hex()} shuffled=0x{shuffled:016X}")
        print(f"    ptr(auto_xor)=0x{ptr_auto:016X}  name(ROL32)=CI=0x{name_ci:X}")
        print(f"    XOR needed for 0x{CLASS_META:X} = 0x{needed_xor:016X}")
    print()

print("--- Checking if any XOR key is consistent across objects ---")
for slot in range(4):
    keys = set()
    for cls_addr in KnownClasses:
        data = read_mem(PID, cls_addr, 0xA0)
        enc = data[0x20 + slot * 0x20 : 0x20 + slot * 0x20 + 16]
        shuffled = pshufb_lo64(enc)
        keys.add(shuffled ^ CLASS_META)
    if len(keys) == 1:
        k = keys.pop()
        print(f"  Slot {slot}: CONSISTENT XOR key = 0x{k:016X}")
    else:
        print(f"  Slot {slot}: {len(keys)} different keys (not consistent)")

print("\n--- Try ROL64 variants for pointer slots ---")
for rol in [0, 5, 16, 32, 37]:
    for slot in range(4):
        keys = set()
        for cls_addr in KnownClasses:
            data = read_mem(PID, cls_addr, 0xA0)
            enc = data[0x20 + slot * 0x20 : 0x20 + slot * 0x20 + 16]
            shuffled = pshufb_lo64(enc)
            xored = shuffled ^ AUTO_XOR
            if rol > 0:
                rotated = ((xored << rol) | (xored >> (64 - rol))) & 0xFFFFFFFFFFFFFFFF
            else:
                rotated = xored
            if rotated == CLASS_META:
                print(f"  Slot {slot} ROL64({rol}): 0x{cls_addr:X} → 0x{rotated:X} MATCH!")

print("\n--- Try without PSHUFB, just raw XOR ---")
for slot in range(4):
    keys = set()
    for cls_addr in KnownClasses:
        data = read_mem(PID, cls_addr, 0xA0)
        lo = struct.unpack_from('<Q', data, 0x20 + slot * 0x20)[0]
        keys.add(lo ^ CLASS_META)
    if len(keys) == 1:
        k = keys.pop()
        print(f"  Slot {slot}: raw XOR key = 0x{k:016X}")
    else:
        print(f"  Slot {slot}: {len(keys)} different raw keys")

print("\n--- Try ROL64 on raw bytes ---")
for rol in [5, 16, 32, 37]:
    for slot in range(4):
        for cls_addr in KnownClasses[:1]:
            data = read_mem(PID, cls_addr, 0xA0)
            lo = struct.unpack_from('<Q', data, 0x20 + slot * 0x20)[0]
            rotated = ((lo << rol) | (lo >> (64 - rol))) & 0xFFFFFFFFFFFFFFFF
            if 0x100000 < rotated < 0x800000000000:
                print(f"  Slot {slot} ROL64({rol}): 0x{cls_addr:X} → 0x{rotated:X}")
