#!/usr/bin/env python3
import struct, os

PID = 12035
MODULE_BASE = 0x140000000
SHARED_VT_RVA = 0xB447980
ENUM_VT_RVA = 0xB462010
FUNCMAP_OFF = 0x268

def read(addr, sz):
    try:
        with open(f'/proc/{PID}/mem', 'rb') as f:
            f.seek(addr)
            return f.read(sz)
    except:
        return b'\x00' * sz

def u64(addr):
    d = read(addr, 8)
    return struct.unpack('<Q', d)[0] if len(d) == 8 else 0

def u32(addr):
    d = read(addr, 4)
    return struct.unpack('<I', d)[0] if len(d) == 4 else 0

def is_heap(p):
    return 0x10000 < p < 0x800000000000

def is_text(p):
    rva = p - MODULE_BASE
    return 0x1000 <= rva < 0xB3DD000

ObjFile = "SDK_Output-E.txt"
if not os.path.exists(ObjFile):
    ObjFile = "SDK_Output.txt"

print(f"=== FuncMap Probe on PID {PID} ===")
print(f"FuncMap offset: +0x{FUNCMAP_OFF:X}")

SharedVtObjs = []
with open(f'/proc/{PID}/maps', 'r') as f:
    pass

GuobjRva = 0xE632260
GuobjBase = u64(MODULE_BASE + GuobjRva)
NumElem = u32(GuobjBase + 0xF4)
print(f"GUObjectArray: base=0x{GuobjBase:X}, numElements={NumElem}")

GWorldRva = 0xE83FC58
GWorldPtr = u64(MODULE_BASE + GWorldRva)
UWorld = u64(GWorldPtr) if is_heap(GWorldPtr) else 0
print(f"GWorld: ptr=0x{GWorldPtr:X} → UWorld=0x{UWorld:X}")

if not is_heap(UWorld):
    print("ERROR: UWorld invalid")
    exit(1)

PL = u64(UWorld + 0x38)
print(f"PersistentLevel: 0x{PL:X}")

LevelsPtr = u64(PL + 0xB0)
LevelsNum = u32(PL + 0xB8)
print(f"Levels: ptr=0x{LevelsPtr:X} count={LevelsNum}")

AllObjs = set()
for Li in range(min(LevelsNum, 200)):
    Lev = u64(LevelsPtr + Li * 8)
    if not is_heap(Lev):
        continue
    ActorsPtr = u64(Lev + 0xB0)
    ActorsNum = u32(Lev + 0xB8)
    if not is_heap(ActorsPtr) or ActorsNum > 100000:
        continue
    for Ai in range(min(ActorsNum, 50000)):
        Act = u64(ActorsPtr + Ai * 8)
        if is_heap(Act):
            AllObjs.add(Act)

print(f"World traversal: {len(AllObjs)} objects")

SharedVtCount = 0
FuncMapValid = 0
FuncMapEmpty = 0
FuncMapGarbage = 0
NativeFuncCount = 0

OffsetHits = {}
for Off in range(0x200, 0x340, 8):
    OffsetHits[Off] = 0

Samples = []
for Obj in list(AllObjs)[:50000]:
    Vt = u64(Obj)
    VtRva = (Vt - MODULE_BASE) if Vt > MODULE_BASE else 0
    if VtRva != SHARED_VT_RVA:
        continue
    SharedVtCount += 1

    for Off in range(0x200, 0x340, 8):
        PairsData = u64(Obj + Off)
        FmNum = u32(Obj + Off + 8)
        FmMax = u32(Obj + Off + 12)
        AllocFlags = u64(Obj + Off + 0x10)

        EmptyTmap = (PairsData == 0 and FmNum == 0 and FmMax == 0)
        ValidTmap = (is_heap(PairsData) and FmNum > 0 and FmNum <= 4096 and FmMax >= FmNum and FmMax <= 16384)

        if EmptyTmap or ValidTmap:
            OffsetHits[Off] += 1

        if Off == FUNCMAP_OFF:
            if ValidTmap:
                FuncMapValid += 1
                if len(Samples) < 5:
                    Samples.append((Obj, PairsData, FmNum, FmMax, AllocFlags))
            elif EmptyTmap:
                FuncMapEmpty += 1
            else:
                FuncMapGarbage += 1

    NativeFunc = u64(Obj + 0x178)
    if is_text(NativeFunc):
        NativeFuncCount += 1

print(f"\n=== Shared vtable objects: {SharedVtCount} ===")
print(f"At +0x{FUNCMAP_OFF:X}: valid={FuncMapValid} empty={FuncMapEmpty} garbage={FuncMapGarbage}")
print(f"Objects with .text NativeFunc@+0x178: {NativeFuncCount}")

print(f"\n=== Offset frequency (EmptyTMap OR ValidTMap shape) ===")
Sorted = sorted(OffsetHits.items(), key=lambda x: -x[1])
for Off, Cnt in Sorted[:10]:
    if Cnt > 0:
        print(f"  +0x{Off:X}: {Cnt}/{SharedVtCount} objects")

print(f"\n=== Sample FuncMaps at +0x{FUNCMAP_OFF:X} ===")
for Obj, PairsData, FmNum, FmMax, AllocFlags in Samples:
    print(f"  obj=0x{Obj:X}: data=0x{PairsData:X} num={FmNum} max={FmMax} allocflags=0x{AllocFlags:X}")
    for I in range(min(FmNum, 4)):
        Entry = PairsData + I * 0x18
        FnameHandle = u64(Entry)
        UfuncPtr = u64(Entry + 8)
        if is_heap(UfuncPtr):
            FnVt = u64(UfuncPtr)
            FnVtRva = (FnVt - MODULE_BASE) if FnVt > MODULE_BASE else 0
            NativeFunc = u64(UfuncPtr + 0x178)
            NfValid = "✓ .text" if is_text(NativeFunc) else "✗"
            print(f"    [{I}] fname=0x{FnameHandle:X} ufunc=0x{UfuncPtr:X} vt_rva=0x{FnVtRva:X} native={NfValid}")
