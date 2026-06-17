#!/usr/bin/env python3
import struct

PID = 12035
MODULE_BASE = 0x140000000
PSHUFB_MASK = [6,5,2,3,4,1,0,7]
XOR_LO64 = 0x5EA772D07F910744

FNV_PRIME = 0x01000193
HASH_ADD = 0x5619A446

CLASS_META = 0x76598800

def u32(x): return x & 0xFFFFFFFF
def rol32(x, n): return u32((u32(x) << n) | (u32(x) >> (32 - n)))

def read_mem(pid, addr, sz):
    with open(f"/proc/{pid}/mem", "rb") as f:
        f.seek(addr)
        return f.read(sz)

def pshufb_lo64(data):
    out = bytearray(8)
    for i in range(8):
        out[i] = data[PSHUFB_MASK[i]]
    return struct.unpack('<Q', out)[0]

def slot_hash(addr):
    Lo32 = u32(addr + 0x10)
    Hi32 = u32((addr + 0x10) >> 32)
    H = u32(u32(FNV_PRIME * rol32(Lo32, 26)) + HASH_ADD)
    H = u32(u32(FNV_PRIME * rol32(H, 27)) + Hi32 + HASH_ADD)
    H = u32(u32(FNV_PRIME * (H >> 6)) + HASH_ADD)
    H = u32(u32(FNV_PRIME * (H >> 5)) + HASH_ADD)
    return H

def class_slot_selector(h):
    edx = (h >> 16) & 0xFFFFFFFF
    r8d = 0xFFFFFFFF & edx
    r8d = r8d ^ u32(h)
    return r8d & 3

KnownObjects = [
    (0x39789700, "Actor"),
    (0x765BBB00, "ActorComponent"),
    (0x76966100, "GameplayCueNotify_Actor"),
    (0x76598800, "Class"),
    (0x3978EB00, "?_at_3978EB00"),
]

print("=== CORRECTED HASH (obj+0x10, const=0x5619A446, extra mul after ROL27) ===\n")
print(f"Expected ClassPrivate = 0x{CLASS_META:X}")
print()

for Addr, Name in KnownObjects:
    try:
        Data = read_mem(PID, Addr, 0xA0)
    except:
        print(f"{Name} @ 0x{Addr:X}: UNREADABLE\n")
        continue

    H = slot_hash(Addr)
    Ci = class_slot_selector(H)

    print(f"{Name} @ 0x{Addr:X}: hash=0x{H:08X} classSlotIdx={Ci}")

    for Si in range(4):
        Off = 0x20 + Si * 0x20
        Enc = Data[Off:Off+16]
        Shuffled = pshufb_lo64(Enc)
        Ptr = Shuffled ^ XOR_LO64
        Rol = ((Ptr << 32) | (Ptr >> 32)) & 0xFFFFFFFFFFFFFFFF
        NameCi = Rol & 0xFFFFFFFF
        Marker = ""
        if Si == Ci:
            Marker = " ← CLASS SLOT"
        if Ptr == 0:
            Marker += " (null)"
        if 0 < NameCi < 0x200000 and (Ptr >> 32) == 0:
            pass
        elif 0 < (Ptr & 0xFFFFFFFF) < 0x200000 and (Ptr >> 32) != 0:
            Marker += f" (name? CI=0x{Ptr >> 32:X})"
        if 0x10000 < Ptr < 0x800000000000 and (Ptr >> 32) == 0:
            Vt = struct.unpack('<Q', read_mem(PID, Ptr, 8))[0]
            VtRva = (Vt - MODULE_BASE) if Vt > MODULE_BASE else 0
            IsShadow = 0xB400000 <= VtRva < 0xB500000
            Marker += f" → vt=0x{VtRva:X}{'(shadow)' if IsShadow else ''}"

        print(f"  slot[{Si}]: ptr=0x{Ptr:016X}  nameCI=0x{NameCi:X}{Marker}")
    print()

print("\n=== Find which slot of each object decodes to CLASS_META ===")
for Addr, Name in KnownObjects:
    try:
        Data = read_mem(PID, Addr, 0xA0)
    except:
        continue
    for Si in range(4):
        Enc = Data[0x20 + Si * 0x20 : 0x20 + Si * 0x20 + 16]
        Ptr = pshufb_lo64(Enc) ^ XOR_LO64
        if Ptr == CLASS_META:
            print(f"  {Name}: slot[{Si}] = 0x{CLASS_META:X} !")
    else:
        pass

print("\n=== Try various ROL64 on ptr results to find CLASS_META ===")
for Addr, Name in KnownObjects[:3]:
    Data = read_mem(PID, Addr, 0xA0)
    for Si in range(4):
        Enc = Data[0x20 + Si * 0x20 : 0x20 + Si * 0x20 + 16]
        Ptr = pshufb_lo64(Enc) ^ XOR_LO64
        for Rol in range(64):
            Rotated = ((Ptr << Rol) | (Ptr >> (64 - Rol))) & 0xFFFFFFFFFFFFFFFF if Rol > 0 else Ptr
            if Rotated == CLASS_META:
                print(f"  {Name} slot[{Si}] ROL64({Rol}) = 0x{CLASS_META:X} MATCH!")
