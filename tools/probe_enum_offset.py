#!/usr/bin/env python3
import struct

PID = 12035

def read_bytes(addr, sz):
    with open(f'/proc/{PID}/mem', 'rb') as f:
        f.seek(addr)
        return f.read(sz)

def read_u64(addr):
    d = read_bytes(addr, 8)
    return struct.unpack('<Q', d)[0] if len(d) == 8 else 0

def read_u32(addr):
    d = read_bytes(addr, 4)
    return struct.unpack('<I', d)[0] if len(d) == 4 else 0

def read_i64(addr):
    d = read_bytes(addr, 8)
    return struct.unpack('<q', d)[0] if len(d) == 8 else 0

EnumAddrs = [
    0x14E630CD0,
    0x14E630450,
    0x14E6301D0,
    0x14E6305E0,
    0x14E62FA30,
    0x14E630D60,
]

print("=== FFieldClass descriptors ===")
for Addr in EnumAddrs:
    Vt = read_u64(Addr)
    print(f"  0x{Addr:X}: vtable=0x{Vt:X}")

MODULE_BASE = 0x140000000
GUOBJ_RVA = 0xE4F8F60
GuobjBase = read_u64(MODULE_BASE + GUOBJ_RVA)
print(f"\nGUObjectArray base = 0x{GuobjBase:X}")

ChunkBase = read_u64(GuobjBase)
print(f"ChunkBase = 0x{ChunkBase:X}")

for Off in range(0x20, 0x180, 4):
    V = read_u32(GuobjBase + Off)
    if 10000 < V < 2000000:
        print(f"NumElements candidate at +0x{Off:X} = {V}")

NumElements = 0
for Off in range(0x20, 0x180, 4):
    V = read_u32(GuobjBase + Off)
    if 10000 < V < 2000000:
        NumElements = V
        break

EnumNamesOffs = [0x98, 0xA0, 0xA8, 0xB0, 0xB8, 0xC0, 0xC8, 0xD0, 0xD8, 0xE0, 0xE8, 0xF0]

Samples = []
ItemCount = 0
for ChunkIdx in range(200):
    ChunkPtr = read_u64(ChunkBase + ChunkIdx * 8)
    if not ChunkPtr or ChunkPtr < 0x10000:
        break
    for ItemIdx in range(0x10000):
        ItemAddr = ChunkPtr + ItemIdx * 0x18
        try:
            ObjPtr = read_u64(ItemAddr)
        except:
            break
        if not ObjPtr or ObjPtr < 0x10000:
            continue
        ItemCount += 1
        if ItemCount > NumElements + 100:
            break

        for Off in EnumNamesOffs:
            try:
                Ptr = read_u64(ObjPtr + Off)
                Cnt = read_u32(ObjPtr + Off + 8)
                Max = read_u32(ObjPtr + Off + 12)
            except:
                continue
            if Ptr < 0x10000 or Ptr >= 0x800000000000:
                continue
            if Cnt < 2 or Cnt > 200 or Max < Cnt or Max > 200:
                continue

            Plausible = True
            for J in range(min(Cnt, 8)):
                Ep = Ptr + J * 16
                Ci = read_u32(Ep)
                Num = read_u32(Ep + 4)
                Val = read_i64(Ep + 8)
                if Ci == 0 or Ci >= 0x1FFFFFFF:
                    Plausible = False
                    break
                if Num >= 0x100:
                    Plausible = False
                    break
                if Val < -0x10000 or Val > 0x10000:
                    Plausible = False
                    break

            if Plausible:
                Samples.append((ObjPtr, Off, Cnt))
                if len(Samples) >= 20:
                    break

        if len(Samples) >= 20:
            break
    if ItemCount > NumElements + 100 or len(Samples) >= 20:
        break

print(f"\nScanned {ItemCount} objects, found {len(Samples)} enum candidates:")
from collections import Counter
OffCounts = Counter()
for (Addr, Off, Cnt) in Samples:
    OffCounts[Off] += 1
    print(f"  obj=0x{Addr:X} offset=+0x{Off:X} names_count={Cnt}")

print(f"\nOffset frequency:")
for Off, C in OffCounts.most_common():
    print(f"  +0x{Off:X}: {C} hits")
