#!/usr/bin/env python3
import struct, os, re

PID = 1195523
ModBase = 0x140000000
CHILDPROPS = 0x118
FFIELD_NAMEPRIVATE = 0x90
FFIELD_OWNER = 0xA8
FFIELD_NEXT = 0xB0

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

def IsValidPtr(P):
    return P > 0x10000 and P < 0x800000000000

ObjAddrs = {}
with open("/media/frost/Coding Stuf/Linux/FrostSDKDumper/dump_objects.txt") as F:
    for Line in F:
        Line = Line.strip()
        if Line.startswith("//") or not Line:
            continue
        M = re.match(r'\[(\d+)\]\s+0x([A-Fa-f0-9]+)\s+\|\s+0x([A-Fa-f0-9]+)\s+\|\s+(.*)', Line)
        if M:
            Addr = int(M.group(2), 16)
            ClassAddr = int(M.group(3), 16)
            Name = M.group(4).strip()
            ObjAddrs[Addr] = (ClassAddr, Name)

FuncClassAddr = None
for Addr, (CAddr, Name) in ObjAddrs.items():
    if Name == 'Function':
        FuncClassAddr = Addr
        break

print(f"Loaded {len(ObjAddrs)} objects")
print(f"UFunction metaclass = 0x{FuncClassAddr:X}" if FuncClassAddr else "UFunction metaclass NOT FOUND")

FuncVtRvas = set()
FuncObjs = []
for Addr, (CAddr, Name) in ObjAddrs.items():
    if 'Function' in Name and CAddr != Addr:
        Vt = ReadU64(Addr)
        if Vt and Vt > ModBase:
            FuncVtRvas.add(Vt - ModBase)

print(f"Found {len(FuncVtRvas)} unique UFunction vtable RVAs")

FuncAddrs = []
for Addr, (CAddr, Name) in ObjAddrs.items():
    Vt = ReadU64(Addr)
    if Vt and (Vt - ModBase) in FuncVtRvas:
        FuncAddrs.append((Addr, Name))

print(f"Found {len(FuncAddrs)} UFunction objects")

TotalParams = 0
ZeroEnc = 0
ValidEnc = 0
OwnerZeroCount = 0

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

ZeroSamples = []

for FuncAddr, FuncName in FuncAddrs[:1000]:
    Cp = ReadU64(FuncAddr + CHILDPROPS)
    if not IsValidPtr(Cp):
        continue

    Ff = Cp
    for _ in range(50):
        if not IsValidPtr(Ff):
            break
        TotalParams += 1

        Owner = ReadU64(Ff + FFIELD_OWNER)
        OwnerClean = Owner & ~1
        if OwnerClean == 0:
            OwnerZeroCount += 1

        EncData = ReadMem(Ff + FFIELD_NAMEPRIVATE, 8)
        if not EncData:
            break
        Enc = struct.unpack("<Q", EncData)[0]

        if Enc == 0:
            ZeroEnc += 1
            if len(ZeroSamples) < 5:
                ZeroSamples.append((Ff, FuncAddr, FuncName, Owner))
        else:
            Ci = V616Ci(Enc)
            if 1 < Ci < 0x6A00000:
                ValidEnc += 1
            else:
                ZeroEnc += 1

        Ff = ReadU64(Ff + FFIELD_NEXT)

print(f"\nUFunction parameter FField stats (from {min(1000, len(FuncAddrs))} functions):")
print(f"  total_params:   {TotalParams}")
print(f"  valid_ci616:    {ValidEnc}")
print(f"  zero_enc:       {ZeroEnc}")
print(f"  owner_zero:     {OwnerZeroCount}")

if ZeroSamples:
    print(f"\nZero-enc param samples:")
    for Ff, FuncAddr, FuncName, Owner in ZeroSamples:
        FullData = ReadMem(Ff, 0xC8)
        if FullData:
            Enc0 = struct.unpack("<Q", FullData[0x90:0x98])[0]
            Enc1 = struct.unpack("<Q", FullData[0x98:0xA0])[0]
            Vt = struct.unpack("<Q", FullData[0:8])[0]
            Nxt = struct.unpack("<Q", FullData[0xB0:0xB8])[0]
            OwnerV = struct.unpack("<Q", FullData[0xA8:0xB0])[0]
            print(f"  ff=0x{Ff:X} func={FuncName} vt_rva=0x{(Vt-ModBase):X}")
            print(f"    enc=0x{Enc0:016X} enc1=0x{Enc1:016X} owner=0x{OwnerV:X} next=0x{Nxt:X}")

            for Off in range(0, 0xC0, 8):
                V = struct.unpack("<Q", FullData[Off:Off+8])[0]
                if V != 0 and Off != 0:
                    VCi = V616Ci(V) if V < 0xFFFFFFFFFFFFFFFF else 0
                    Mark = f" CI={VCi}" if 1 < VCi < 0x6A00000 else ""
                    if Off == FFIELD_NAMEPRIVATE:
                        Mark += " ← NamePrivate"
                    print(f"    +0x{Off:02X} = 0x{V:016X}{Mark}")
