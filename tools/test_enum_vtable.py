#!/usr/bin/env python3
import struct

PID = 12035
MODULE_BASE = 0x140000000
ENUM_VT_RVA = 0xB462010
GUOBJ_RVA = 0xE632260

def read(addr, sz):
    with open(f'/proc/{PID}/mem', 'rb') as f:
        f.seek(addr)
        return f.read(sz)

def u64(addr):
    d = read(addr, 8)
    return struct.unpack('<Q', d)[0] if len(d) == 8 else 0

def u32(addr):
    d = read(addr, 4)
    return struct.unpack('<I', d)[0] if len(d) == 4 else 0

def i64(addr):
    d = read(addr, 8)
    return struct.unpack('<q', d)[0] if len(d) == 8 else 0

GuobjBase = u64(MODULE_BASE + GUOBJ_RVA)
NumElements = u32(GuobjBase + 0xF4)
print(f"GUObjectArray: base=0x{GuobjBase:X}, numElements={NumElements}")

ChunkTablePtr = u64(GuobjBase)
if ChunkTablePtr < 0x10000:
    for Off in range(0, 0x40, 8):
        Candidate = u64(GuobjBase + Off)
        if Candidate > 0x10000 and Candidate < 0x800000000000:
            ChunkTablePtr = Candidate
            print(f"  chunk table found at +0x{Off:X} = 0x{Candidate:X}")
            break

print(f"ChunkTable: 0x{ChunkTablePtr:X}")

EnumObjs = []
Total = 0

for ChunkIdx in range(512):
    ChunkPtr = u64(ChunkTablePtr + ChunkIdx * 8)
    if not ChunkPtr or ChunkPtr < 0x10000:
        break
    for ItemIdx in range(0x10000):
        ObjPtr = u64(ChunkPtr + ItemIdx * 0x18)
        if not ObjPtr or ObjPtr < 0x10000 or ObjPtr >= 0x800000000000:
            continue
        Total += 1
        if Total > NumElements + 100:
            break
        Vt = u64(ObjPtr)
        VtRva = (Vt - MODULE_BASE) if Vt > MODULE_BASE else 0
        if VtRva == ENUM_VT_RVA:
            EnumObjs.append(ObjPtr)
    if Total > NumElements + 100:
        break

print(f"\nScanned {Total} objects, found {len(EnumObjs)} with UEnum vtable 0x{ENUM_VT_RVA:X}")

if not EnumObjs:
    print("No UEnum objects found!")
    exit()

print(f"\nProbing Names TArray at offsets 0x90..0x120 on first 10 samples:")
from collections import Counter
HitsByOff = Counter()

for Obj in EnumObjs[:10]:
    print(f"\n  obj=0x{Obj:X}")
    for Off in range(0x90, 0x128, 8):
        Ptr = u64(Obj + Off)
        if Ptr < 0x10000 or Ptr >= 0x800000000000:
            continue
        Cnt = u32(Obj + Off + 8)
        Max = u32(Obj + Off + 12)
        if Cnt == 0 or Cnt > 300 or Max < Cnt or Max > 300:
            continue
        Ci0 = u32(Ptr)
        Val0 = i64(Ptr + 8)
        Plausible = True
        for J in range(min(Cnt, 8)):
            Ep = Ptr + J * 16
            Ci = u32(Ep)
            Num = u32(Ep + 4)
            Val = i64(Ep + 8)
            if Ci == 0 or Ci >= 0x1FFFFFFF or Num >= 0x100:
                Plausible = False
                break
            if Val < -0x10000 or Val > 0x10000:
                Plausible = False
                break
        Tag = " ✓ ENUM" if Plausible else ""
        print(f"    +0x{Off:X}: ptr=0x{Ptr:X} cnt={Cnt} max={Max} ci0={Ci0} val0={Val0}{Tag}")
        if Plausible:
            HitsByOff[Off] += 1

print(f"\n=== Offset frequency (plausible enum entries) ===")
for Off, C in HitsByOff.most_common():
    print(f"  +0x{Off:X}: {C}/10 samples")

if HitsByOff:
    BestOff = HitsByOff.most_common(1)[0][0]
    print(f"\n=== Full count with best offset +0x{BestOff:X} across ALL {len(EnumObjs)} objects ===")
    ValidCount = 0
    for Obj in EnumObjs:
        Ptr = u64(Obj + BestOff)
        if Ptr < 0x10000 or Ptr >= 0x800000000000:
            continue
        Cnt = u32(Obj + BestOff + 8)
        Max = u32(Obj + BestOff + 12)
        if Cnt == 0 or Cnt > 300 or Max < Cnt or Max > 300:
            continue
        Plausible = True
        for J in range(min(Cnt, 8)):
            Ep = Ptr + J * 16
            Ci = u32(Ep)
            Num = u32(Ep + 4)
            Val = i64(Ep + 8)
            if Ci == 0 or Ci >= 0x1FFFFFFF or Num >= 0x100:
                Plausible = False
                break
            if Val < -0x10000 or Val > 0x10000:
                Plausible = False
                break
        if Plausible:
            ValidCount += 1
    print(f"  Valid enums: {ValidCount}/{len(EnumObjs)}")
