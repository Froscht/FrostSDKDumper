#!/usr/bin/env python3
import struct, os, re

PID = 1195523
ModBase = 0x140000000
FFIELD_NAMEPRIVATE = 0x90
FFIELD_OWNER = 0xA8
FFIELD_NEXT = 0xB0
CHILDPROPS = 0x118

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

ClassAddrs = {}
with open("/media/frost/Coding Stuf/Linux/FrostSDKDumper/dump_classes.txt") as F:
    for Line in F:
        Line = Line.strip()
        if Line.startswith("//") or not Line:
            continue
        M = re.match(r'\[(\d+)\]\s+0x([A-Fa-f0-9]+)\s+\|\s+(\S+)', Line)
        if M:
            Addr = int(M.group(2), 16)
            Name = M.group(3)
            ClassAddrs[Addr] = Name

TotalFf = 0
ZeroEnc = 0
ValidCi616 = 0
ValidCiKeyless = 0
FailCi = 0
OwnerValid = 0
OwnerZero = 0

OwnerZeroSamples = []
FailSamples = []

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

for Addr, Name in list(ClassAddrs.items())[:500]:
    Cp = ReadU64(Addr + CHILDPROPS)
    if not IsValidPtr(Cp):
        continue

    Ff = Cp
    for _ in range(200):
        if not IsValidPtr(Ff):
            break
        TotalFf += 1

        Owner = ReadU64(Ff + FFIELD_OWNER)
        OwnerClean = Owner & ~1
        if OwnerClean == 0:
            OwnerZero += 1
            if len(OwnerZeroSamples) < 3:
                OwnerZeroSamples.append(Ff)
        elif IsValidPtr(OwnerClean):
            OwnerValid += 1

        EncData = ReadMem(Ff + FFIELD_NAMEPRIVATE, 8)
        if not EncData:
            Ff = ReadU64(Ff + FFIELD_NEXT)
            continue
        Enc = struct.unpack("<Q", EncData)[0]

        if Enc == 0:
            ZeroEnc += 1
        else:
            Ci = V616Ci(Enc)
            if 1 < Ci < 0x6A00000:
                ValidCi616 += 1
            else:
                FailCi += 1
                if len(FailSamples) < 5:
                    FailSamples.append((Ff, Enc, Ci, Owner))

        Ff = ReadU64(Ff + FFIELD_NEXT)

print(f"Total FFields walked: {TotalFf}")
print(f"  owner_valid: {OwnerValid}")
print(f"  owner_zero:  {OwnerZero}")
print(f"  enc_zero:    {ZeroEnc}")
print(f"  valid_ci616: {ValidCi616}")
print(f"  fail_ci:     {FailCi}")

print(f"\nBreakdown of enc_zero by owner:")
ZeroEncOwnerValid = 0
ZeroEncOwnerZero = 0
for Addr, Name in list(ClassAddrs.items())[:500]:
    Cp = ReadU64(Addr + CHILDPROPS)
    if not IsValidPtr(Cp):
        continue
    Ff = Cp
    for _ in range(200):
        if not IsValidPtr(Ff):
            break
        Owner = ReadU64(Ff + FFIELD_OWNER)
        OwnerClean = Owner & ~1
        EncData = ReadMem(Ff + FFIELD_NAMEPRIVATE, 8)
        if EncData:
            Enc = struct.unpack("<Q", EncData)[0]
            if Enc == 0:
                if OwnerClean == 0:
                    ZeroEncOwnerZero += 1
                elif IsValidPtr(OwnerClean):
                    ZeroEncOwnerValid += 1
        Ff = ReadU64(Ff + FFIELD_NEXT)

print(f"  enc_zero + owner_valid: {ZeroEncOwnerValid}")
print(f"  enc_zero + owner_zero:  {ZeroEncOwnerZero}")

if OwnerZeroSamples:
    print(f"\nOwner-zero samples:")
    for Ff in OwnerZeroSamples:
        FullData = ReadMem(Ff, 0xC8)
        if FullData:
            Enc = struct.unpack("<Q", FullData[FFIELD_NAMEPRIVATE:FFIELD_NAMEPRIVATE+8])[0]
            Owner = struct.unpack("<Q", FullData[FFIELD_OWNER:FFIELD_OWNER+8])[0]
            Next = struct.unpack("<Q", FullData[FFIELD_NEXT:FFIELD_NEXT+8])[0]
            Vt = struct.unpack("<Q", FullData[0:8])[0]
            print(f"  ff=0x{Ff:X} vt=0x{Vt:X} enc=0x{Enc:016X} owner=0x{Owner:X} next=0x{Next:X}")

if FailSamples:
    print(f"\nFail CI samples:")
    for Ff, Enc, Ci, Owner in FailSamples:
        print(f"  ff=0x{Ff:X} enc=0x{Enc:016X} ci={Ci} (0x{Ci:08X}) owner=0x{Owner:X}")
