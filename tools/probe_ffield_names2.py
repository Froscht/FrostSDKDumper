#!/usr/bin/env python3
import struct, sys, os, json

PID = 9046
MODULE_BASE = 0x140000000

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

CHILDPROPS_OFF = 0x118
FFIELD_NAME_OFF = 0x90
FFIELD_NEXT_OFF = 0xB0
FPROP_OFFSET_OFF = 0xE4
FPROP_ELEMSZ_OFF = 0x118
PROP_OFFSET_XOR = 0xEAABEC11

SHUF_IMM = 0x1E
XOR_KEY = 0x365789E8756FBA38
ROL64_AMT = 32
ROL16_AMT = 1

def DecryptCi(Enc):
    if Enc == 0:
        return 0
    Words = [
        (Enc >>  0) & 0xFFFF,
        (Enc >> 16) & 0xFFFF,
        (Enc >> 32) & 0xFFFF,
        (Enc >> 48) & 0xFFFF,
    ]
    Shuffled = [
        Words[(SHUF_IMM >> 0) & 3],
        Words[(SHUF_IMM >> 2) & 3],
        Words[(SHUF_IMM >> 4) & 3],
        Words[(SHUF_IMM >> 6) & 3],
    ]
    Val = 0
    for I in range(4):
        Val |= (Shuffled[I] & 0xFFFF) << (I * 16)
    Val ^= XOR_KEY
    NewWords = []
    for I in range(4):
        W = (Val >> (I * 16)) & 0xFFFF
        W = ((W << ROL16_AMT) | (W >> (16 - ROL16_AMT))) & 0xFFFF
        NewWords.append(W)
    Val = 0
    for I in range(4):
        Val |= (NewWords[I] & 0xFFFF) << (I * 16)
    Val = ((Val << ROL64_AMT) | (Val >> (64 - ROL64_AMT))) & 0xFFFFFFFFFFFFFFFF
    return Val & 0xFFFFFFFF

GobjectArrayRva = 0xE4F8F60
GobjectArrayAddr = MODULE_BASE + GobjectArrayRva

with open("/media/frost/Coding Stuf/Linux/FrostSDKDumper/decrypt_export.json") as F:
    Cfg = json.load(F)
for K, V in Cfg.items():
    if "guobjectarray" in K.lower():
        print(f"Config: {K} = {V}")

ChunksAddr = ReadU64(GobjectArrayAddr + 0x10)
NumChunks = ReadU32(GobjectArrayAddr + 0x08)
print(f"GUObjectArray at 0x{GobjectArrayAddr:X}, chunks_ptr=0x{ChunksAddr:X}, num_chunks={NumChunks}")

if not ChunksAddr or ChunksAddr < 0x10000:
    GobjectArrayRva = 0xE676F60
    GobjectArrayAddr = MODULE_BASE + GobjectArrayRva
    ChunksAddr = ReadU64(GobjectArrayAddr + 0x10)
    NumChunks = ReadU32(GobjectArrayAddr + 0x08)
    print(f"Retry: GUObjectArray at 0x{GobjectArrayAddr:X}, chunks_ptr=0x{ChunksAddr:X}, num_chunks={NumChunks}")

AsClassRva = 0xBC8DE90
AsStructRva = 0xBB7FB90

print("\n=== Walking 1000 UClass objects for ChildProperties ===")

TotalFF = 0
ZeroName = 0
CiZero = 0
CiSmall = 0
CiOk = 0
CiTooLarge = 0
FailSamples = []
SmallCiSamples = {}

ObjAddrs = []

if ChunksAddr and ChunksAddr > 0x10000:
    for ChunkI in range(min(NumChunks, 500)):
        ChunkPtr = ReadU64(ChunksAddr + ChunkI * 8)
        if not ChunkPtr or ChunkPtr < 0x10000:
            continue
        for Elem in range(0, 65536, 24):
            ObjPtr = ReadU64(ChunkPtr + Elem)
            if ObjPtr and ObjPtr > 0x10000 and ObjPtr < 0x800000000000:
                ObjAddrs.append(ObjPtr)
        if len(ObjAddrs) > 200000:
            break

print(f"Collected {len(ObjAddrs)} objects from GUObjectArray")

ClassCount = 0
for ObjAddr in ObjAddrs:
    Vt = ReadU64(ObjAddr)
    VtRva = Vt - MODULE_BASE if Vt > MODULE_BASE else 0
    if VtRva != AsClassRva:
        continue
    ClassCount += 1
    if ClassCount > 1000:
        break

    Cp = ReadU64(ObjAddr + CHILDPROPS_OFF)
    if not Cp or Cp < 0x10000 or Cp > 0x800000000000:
        continue

    Ff = Cp
    Visited = set()
    ChainLen = 0
    while Ff and Ff > 0x10000 and Ff < 0x800000000000 and Ff not in Visited and ChainLen < 500:
        Visited.add(Ff)
        ChainLen += 1
        TotalFF += 1

        Enc = ReadU64(Ff + FFIELD_NAME_OFF)
        if Enc == 0:
            ZeroName += 1
        else:
            Ci = DecryptCi(Enc)
            if Ci == 0:
                CiZero += 1
                if len(FailSamples) < 10:
                    FailSamples.append((Ff, Enc, Ci, "ci=0"))
            elif Ci <= 10:
                CiSmall += 1
                SmallCiSamples.setdefault(Ci, []).append(Ff)
            elif Ci >= 0x06A00000:
                CiTooLarge += 1
                if len(FailSamples) < 10:
                    FailSamples.append((Ff, Enc, Ci, "ci_too_large"))
            else:
                CiOk += 1

        Ff = ReadU64(Ff + FFIELD_NEXT_OFF)

print(f"\nClasses checked: {ClassCount}")
print(f"Total FFields walked: {TotalFF}")
print(f"Zero name slot (enc=0): {ZeroName} ({100*ZeroName/max(TotalFF,1):.1f}%)")
print(f"CI=0 (non-zero enc): {CiZero} ({100*CiZero/max(TotalFF,1):.1f}%)")
print(f"CI 1-10 (suspicious): {CiSmall} ({100*CiSmall/max(TotalFF,1):.1f}%)")
print(f"CI valid: {CiOk} ({100*CiOk/max(TotalFF,1):.1f}%)")
print(f"CI too large: {CiTooLarge} ({100*CiTooLarge/max(TotalFF,1):.1f}%)")

print(f"\nFail samples:")
for Ff, Enc, Ci, Reason in FailSamples:
    print(f"  ff=0x{Ff:X} enc=0x{Enc:016X} ci={Ci} ({Reason})")

print(f"\nSmall CI samples:")
for Ci, Addrs in sorted(SmallCiSamples.items()):
    print(f"  CI={Ci}: {len(Addrs)} hits (first: 0x{Addrs[0]:X})")

if FailSamples:
    print(f"\n=== Detailed dump of first fail sample ===")
    Ff = FailSamples[0][0]
    Data = ReadMem(Ff, 0x150)
    if Data:
        for Off in range(0, len(Data), 16):
            Hex = " ".join(f"{Data[Off+I]:02X}" for I in range(min(16, len(Data)-Off)))
            print(f"  +0x{Off:03X}: {Hex}")
