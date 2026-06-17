#!/usr/bin/env python3
import struct, collections

PID = 12035
MODULE_BASE = 0x140000000
SHARED_VT_RVA = 0xB447980
PSHUFB = [6,5,2,3,4,1,0,7]
XOR_KEY = 0x5EA772D07F910744
FNV_PRIME = 0x01000193
HASH_ADD = 0x5619A446

def u32(x): return x & 0xFFFFFFFF
def rol32(x, n): return u32((u32(x) << n) | (u32(x) >> (32-n)))
def rol64(x, n): return ((x << n) | (x >> (64-n))) & 0xFFFFFFFFFFFFFFFF if n > 0 else x

def read_u64(addr):
    with open(f'/proc/{PID}/mem', 'rb') as f:
        f.seek(addr)
        d = f.read(8)
        return struct.unpack('<Q', d)[0] if len(d) == 8 else 0

def read_bytes(addr, sz):
    with open(f'/proc/{PID}/mem', 'rb') as f:
        f.seek(addr)
        return f.read(sz)

def pshufb(data):
    out = bytearray(8)
    for i in range(8): out[i] = data[PSHUFB[i]]
    return struct.unpack('<Q', out)[0]

def slot_hash(addr):
    Lo32 = u32(addr + 0x10)
    Hi32 = u32((addr + 0x10) >> 32)
    H = u32(u32(FNV_PRIME * rol32(Lo32, 26)) + HASH_ADD)
    H = u32(u32(FNV_PRIME * rol32(H, 27)) + Hi32 + HASH_ADD)
    H = u32(u32(FNV_PRIME * (H >> 6)) + HASH_ADD)
    H = u32(u32(FNV_PRIME * (H >> 5)) + HASH_ADD)
    return H

def get_class_private(addr):
    try:
        H = slot_hash(addr)
        Ci = ((H >> 16) ^ H) & 3
        Data = read_bytes(addr + 0x20 + Ci * 0x20, 16)
        Shuffled = pshufb(Data)
        Ptr = Shuffled ^ XOR_KEY
        if 0x10000 < Ptr < 0x800000000000:
            return Ptr
    except:
        pass
    return 0

def get_name_ci(addr):
    try:
        H = slot_hash(addr)
        Ci = ((H >> 16) ^ H) & 3
        Ni = Ci ^ 2
        Data = read_bytes(addr + 0x20 + Ni * 0x20, 16)
        Shuffled = pshufb(Data)
        Ptr = Shuffled ^ XOR_KEY
        Rotated = rol64(Ptr, 32)
        return Rotated & 0xFFFFFFFF
    except:
        return 0

KnownTypeObjs = [
    0x39789700,   # Actor (a UClass)
    0x765BBB00,   # ActorComponent (a UClass)
    0x76598800,   # "Class" (the object named "Class")
    0x3978E800,   # Package
    0x3978E200,   # Object
]

print("=== ClassPrivate of known objects ===")
for Addr in KnownTypeObjs:
    Cp = get_class_private(Addr)
    Ci = get_name_ci(Addr)
    print(f"  0x{Addr:X}: ClassPrivate=0x{Cp:X}  nameCi={Ci}")

print("\n=== Scan GUObjectArray for objects with shared vtable ===")
GuobjBase = read_u64(MODULE_BASE + 0xE4F8F60)
NumElements = 0
for Off in range(0x20, 0x180, 4):
    V = struct.unpack('<I', read_bytes(GuobjBase + Off, 4))[0]
    if 10000 < V < 2000000:
        NumElements = V
        break

print(f"GUObjectArray: base=0x{GuobjBase:X}, numElements={NumElements}")

CpFreq = collections.Counter()
SharedVtAddr = MODULE_BASE + SHARED_VT_RVA
MatchCount = 0
Total = 0

ChunkBase = read_u64(GuobjBase)
MaxChunks = 1024

for ChunkIdx in range(MaxChunks):
    ChunkPtr = read_u64(ChunkBase + ChunkIdx * 8)
    if not ChunkPtr or ChunkPtr < 0x10000:
        break
    for ItemIdx in range(0x10000):
        ItemAddr = ChunkPtr + ItemIdx * 0x18
        try:
            ObjPtr = read_u64(ItemAddr)
        except:
            break
        if not ObjPtr or ObjPtr < 0x10000 or ObjPtr >= 0x800000000000:
            continue
        Total += 1
        if Total > NumElements + 1000:
            break
        try:
            Vt = read_u64(ObjPtr)
        except:
            continue
        VtRva = (Vt - MODULE_BASE) if Vt > MODULE_BASE else 0
        if VtRva == SHARED_VT_RVA:
            Cp = get_class_private(ObjPtr)
            if Cp:
                CpFreq[Cp] += 1
                MatchCount += 1
    if Total > NumElements + 1000:
        break

print(f"\nObjects with vtable 0x{SHARED_VT_RVA:X}: {MatchCount} out of {Total}")
print(f"Unique ClassPrivate targets: {len(CpFreq)}")
print(f"\nTop ClassPrivate targets (metaclass candidates):")
for Addr, Cnt in CpFreq.most_common(10):
    Ci = get_name_ci(Addr) if Addr else 0
    CpOfCp = get_class_private(Addr) if Addr else 0
    print(f"  0x{Addr:X}: {Cnt} objects  nameCi={Ci}  classOfClass=0x{CpOfCp:X}")
