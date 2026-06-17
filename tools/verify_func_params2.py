#!/usr/bin/env python3
import struct, os

PID = 1195523
ModBase = 0x140000000
CHILDPROPS = 0x118
FFIELD_NAMEPRIVATE = 0x90
FFIELD_OWNER = 0xA8
FFIELD_NEXT = 0xB0
GOBJARRAY_RVA = 0xE632260

FuncVtRva = 0xB447980

def ReadMem(Addr, Size):
    try:
        Fd = os.open(f"/proc/{PID}/mem", os.O_RDONLY)
        os.lseek(Fd, Addr, os.SEEK_SET)
        Data = os.read(Fd, Size)
        os.close(Fd)
        return Data if len(Data) == Size else None
    except:
        return None

def ReadU64(Addr):
    D = ReadMem(Addr, 8)
    return struct.unpack("<Q", D)[0] if D else 0

def ReadU32(Addr):
    D = ReadMem(Addr, 4)
    return struct.unpack("<I", D)[0] if D else 0

def IsValidPtr(P):
    return P > 0x10000 and P < 0x800000000000

def Pshuflw(Val, Imm):
    Words = [(Val >> (I*16)) & 0xFFFF for I in range(4)]
    Out = [0]*4
    Out[0] = Words[(Imm >> 0) & 3]
    Out[1] = Words[(Imm >> 2) & 3]
    Out[2] = Words[(Imm >> 4) & 3]
    Out[3] = Words[(Imm >> 6) & 3]
    Result = 0
    for I in range(4):
        Result |= (Out[I] & 0xFFFF) << (I*16)
    return Result & 0xFFFFFFFFFFFFFFFF

def Rol16Each(Val, N):
    Result = 0
    for I in range(4):
        W = (Val >> (I*16)) & 0xFFFF
        W = ((W << N) | (W >> (16-N))) & 0xFFFF
        Result |= W << (I*16)
    return Result

def Rol64(Val, N):
    Val &= 0xFFFFFFFFFFFFFFFF
    return ((Val << N) | (Val >> (64-N))) & 0xFFFFFFFFFFFFFFFF

def V616Ci(Enc):
    V = Pshuflw(Enc, 0x1E)
    V ^= 0x365789E8756FBA38
    V &= 0xFFFFFFFFFFFFFFFF
    V = Rol16Each(V, 1)
    V = Rol64(V, 32)
    return V & 0xFFFFFFFF

NumElems = ReadU32(ModBase + GOBJARRAY_RVA + 0xF4)
print(f"NumElements={NumElems}")

FuncObjs = []
ChunkTableAddr = ModBase + GOBJARRAY_RVA + 0x10

for ChunkI in range(512):
    ChunkPtr = ReadU64(ChunkTableAddr + ChunkI * 8)
    if not ChunkPtr or ChunkPtr < 0x10000:
        continue

    for ElemI in range(256):
        ObjAddr = ReadU64(ChunkPtr + ElemI * 8)
        if not IsValidPtr(ObjAddr):
            continue
        Vt = ReadU64(ObjAddr)
        if not Vt:
            continue
        VtRva = Vt - ModBase
        if VtRva == FuncVtRva:
            FuncObjs.append(ObjAddr)
            if len(FuncObjs) >= 200:
                break
    if len(FuncObjs) >= 200:
        break

print(f"Found {len(FuncObjs)} UFunction objects with vtable RVA 0x{FuncVtRva:X}")

if not FuncObjs:
    print("Trying all known func vtables...")
    KnownFuncVts = [0xB447980, 0xB8EDA70, 0xB8EDEC0]
    for Vt in KnownFuncVts:
        print(f"  Checking vtable 0x{Vt:X}...")

TotalParams = 0
ZeroEnc = 0
ValidEnc = 0
ZeroEncValidOwner = 0
ZeroEncZeroOwner = 0

for FAddr in FuncObjs[:100]:
    Cp = ReadU64(FAddr + CHILDPROPS)
    if not IsValidPtr(Cp):
        continue

    Ff = Cp
    Depth = 0
    while IsValidPtr(Ff) and Depth < 30:
        Depth += 1
        TotalParams += 1

        EncData = ReadMem(Ff + FFIELD_NAMEPRIVATE, 8)
        if not EncData:
            break
        Enc = struct.unpack("<Q", EncData)[0]
        Owner = ReadU64(Ff + FFIELD_OWNER)
        OwnerClean = Owner & ~1

        if Enc == 0:
            ZeroEnc += 1
            if IsValidPtr(OwnerClean):
                ZeroEncValidOwner += 1
            else:
                ZeroEncZeroOwner += 1
        else:
            Ci = V616Ci(Enc)
            if 1 < Ci < 0x6A00000:
                ValidEnc += 1
            else:
                ZeroEnc += 1

        Ff = ReadU64(Ff + FFIELD_NEXT)

print(f"\nUFunction param stats ({min(100, len(FuncObjs))} funcs, {TotalParams} params):")
print(f"  valid_ci:           {ValidEnc}")
print(f"  zero/bad_enc:       {ZeroEnc}")
print(f"    with valid owner: {ZeroEncValidOwner}")
print(f"    with zero owner:  {ZeroEncZeroOwner}")
print(f"  naming rate:        {ValidEnc}/{TotalParams} ({100*ValidEnc/max(TotalParams,1):.1f}%)")

print(f"\n=== Sample UFunction with params ===")
for FAddr in FuncObjs[:10]:
    Cp = ReadU64(FAddr + CHILDPROPS)
    if not IsValidPtr(Cp):
        continue

    ParamCount = 0
    ValidCount = 0
    Ff = Cp
    while IsValidPtr(Ff) and ParamCount < 10:
        ParamCount += 1
        EncData = ReadMem(Ff + FFIELD_NAMEPRIVATE, 8)
        if EncData:
            Enc = struct.unpack("<Q", EncData)[0]
            Ci = V616Ci(Enc) if Enc else 0
            Owner = ReadU64(Ff + FFIELD_OWNER)
            Status = "VALID" if (Enc and 1 < Ci < 0x6A00000) else ("ZERO-ENC" if Enc == 0 else f"BAD-CI({Ci})")
            if Status == "VALID":
                ValidCount += 1
            print(f"    param[{ParamCount-1}] ff=0x{Ff:X} enc=0x{Enc:016X} ci={Ci if Enc else 0} owner=0x{Owner:X} → {Status}")
        Ff = ReadU64(Ff + FFIELD_NEXT)

    print(f"  func=0x{FAddr:X} params={ParamCount} valid={ValidCount}")
    if ParamCount > 0:
        break
