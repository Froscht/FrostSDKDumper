#!/usr/bin/env python3
import struct, os

PID = 1195523
ModBase = 0x140000000
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

TestAddrs = [0xf29e0610, 0x1b897a300, 0x93203f50]

for Addr in TestAddrs:
    print(f"\n=== Object 0x{Addr:X} ===")
    for Off in range(0x60, 0x200, 8):
        Head = ReadU64(Addr + Off)
        if not IsValidPtr(Head):
            continue
        Vt = ReadU64(Head)
        if not Vt or Vt < ModBase or Vt > ModBase + 0x20000000:
            continue

        Owner = ReadU64(Head + FFIELD_OWNER)
        OwnerClean = Owner & ~1
        Enc = ReadU64(Head + FFIELD_NAMEPRIVATE)
        Next = ReadU64(Head + FFIELD_NEXT)

        Ci = V616Ci(Enc) if Enc else 0
        CiValid = 1 < Ci < 0x6A00000 if Enc else False

        OwnerMatch = "MATCH" if OwnerClean == Addr else f"DIFF(0x{OwnerClean:X})"
        EncStr = "ZERO" if Enc == 0 else f"CI={Ci}({'OK' if CiValid else 'BAD'})"

        ChainLen = 0
        ZeroCount = 0
        F = Head
        while IsValidPtr(F) and ChainLen < 100:
            ChainLen += 1
            E = ReadU64(F + FFIELD_NAMEPRIVATE)
            if E == 0:
                ZeroCount += 1
            F = ReadU64(F + FFIELD_NEXT)

        print(f"  +0x{Off:03X}: head=0x{Head:X} vt_rva=0x{(Vt-ModBase):X} owner={OwnerMatch}")
        print(f"         enc={EncStr} chain_len={ChainLen} zero_enc={ZeroCount}")
