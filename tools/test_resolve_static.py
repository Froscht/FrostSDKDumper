#!/usr/bin/env python3
import struct, os, ctypes

PID = 9046
ModBase = 0x140000000

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

def ReadU16(Addr):
    D = ReadMem(Addr, 2)
    return struct.unpack("<H", D)[0] if D else 0

def Rotl32(V, N):
    V &= 0xFFFFFFFF
    return ((V << N) | (V >> (32 - N))) & 0xFFFFFFFF

def Rotl64(V, N):
    V &= 0xFFFFFFFFFFFFFFFF
    return ((V << N) | (V >> (64 - N))) & 0xFFFFFFFFFFFFFFFF

GnpRva = 0xE577700
GnpAddr = ModBase + GnpRva

HashPrime = 0x01000193
ShardHashAdd = 0xD4CEBC36
ShardHashRolA = 27
ShardHashRolB = 18
ShardBlockBaseOff = 32
ShardHashSeedOff = 16

EntryXor = 0xE5C864C1A6B54C7F
EntryRol64 = 39
EntryPshufbMask = bytes([0x02, 0x06, 0x03, 0x01, 0x00, 0x04, 0x07, 0x05,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
EntryXorMask = bytes([0xFC, 0x10, 0xD3, 0xFB, 0xCE, 0x56, 0x88, 0x68,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])

FnvPrime = 0x100000001B3
FnvAdd = 0x124CB31365185276
FnvRol1 = 54
FnvRol2 = 32

def PshufbLo8(Data8, Mask8):
    Src = list(Data8)
    Out = [0] * 8
    for I in range(8):
        Idx = Mask8[I] & 0x0F
        if Mask8[I] & 0x80:
            Out[I] = 0
        elif Idx < 8:
            Out[I] = Src[Idx]
        else:
            Out[I] = 0
    return bytes(Out)

def DecBlock616(Raw16):
    V = struct.unpack("<Q", Raw16[:8])[0]
    Hi = struct.unpack("<Q", Raw16[8:])[0] if len(Raw16) >= 16 else 0
    V128Lo = V
    V128Hi = Hi
    RolLo = Rotl64(V128Lo, EntryRol64)
    RolHi = Rotl64(V128Hi, EntryRol64)
    RolBytes = struct.pack("<QQ", RolLo, RolHi)
    Shuffled = PshufbLo8(RolBytes[:8], EntryPshufbMask[:8])
    ShufU64 = struct.unpack("<Q", Shuffled)[0]
    XorMaskU64 = struct.unpack("<Q", EntryXorMask[:8])[0]
    Xored = ShufU64 ^ XorMaskU64
    Final = Xored ^ EntryXor
    return Final

def ResolveNamePtr616(Ci):
    CiU = Ci & 0xFFFFFFFF
    NameOff = CiU & 0xFFFF
    ChkOff = (CiU >> 8) & 0xFFFF00
    ChunkAddr = GnpAddr + ChkOff

    HashAddr = ChunkAddr + ShardHashSeedOff
    HLo = HashAddr & 0xFFFFFFFF
    HHi = (HashAddr >> 32) & 0xFFFFFFFF

    S1 = Rotl32(HLo, ShardHashRolA)
    S2 = (HashPrime * S1 + ShardHashAdd) & 0xFFFFFFFF
    S3 = Rotl32(S2, ShardHashRolB)
    S4 = (HashPrime * S3 + HHi + ShardHashAdd) & 0xFFFFFFFF
    S5 = Rotl32(S4, ShardHashRolA)
    S6 = (HashPrime * S5 + ShardHashAdd) & 0xFFFFFFFF
    V20 = Rotl32(S6, ShardHashRolB)

    Pa = (ctypes.c_int8(-109).value * (V20 & 0xFFFFFFFF) + 54) & 0xFF
    Pb = ((HashPrime * V20 + ShardHashAdd) >> 16) & 0xFF
    V10 = Pa ^ Pb
    Bidx1 = V10 & 7
    Bidx2 = (V10 + 1) & 7
    BlockBase = ChunkAddr + ShardBlockBaseOff

    Sb1 = ReadMem(BlockBase + 32 * Bidx1, 16)
    Sb2 = ReadMem(BlockBase + 32 * Bidx2, 16)
    if not Sb1 or not Sb2:
        return 0, "read_fail"

    Block1 = DecBlock616(Sb1)
    Block2 = DecBlock616(Sb2)

    Fv1 = (FnvPrime * Rotl64(Block1, FnvRol1) + FnvAdd) & 0xFFFFFFFFFFFFFFFF
    Fv2 = (FnvPrime * Rotl64(Fv1, FnvRol2) + FnvAdd) & 0xFFFFFFFFFFFFFFFF

    EntryPtr = (Block1 + (Block2 ^ Fv2) + 2 * NameOff) & 0xFFFFFFFFFFFFFFFF

    return EntryPtr, "ok"

def DecryptNameString(EntryPtr):
    Hdr = ReadU16(EntryPtr)
    if not Hdr:
        return "", f"hdr_read_fail at 0x{EntryPtr:X}"

    Length = ((Hdr << 2) | (Hdr >> 14)) & 0x3FF
    IsWide = (Hdr & 0x0040) != 0

    if Length == 0 or Length > 256:
        return "", f"bad_length={Length} hdr=0x{Hdr:04X}"

    DataOff = 2
    if IsWide:
        Raw = ReadMem(EntryPtr + DataOff, Length * 2)
        if not Raw:
            return "", "wide_read_fail"
        Chars = []
        for I in range(Length):
            Wc = struct.unpack("<H", Raw[I*2:I*2+2])[0]
            Chars.append(chr(Wc) if 32 <= Wc < 127 else '?')
        return "".join(Chars), f"wide len={Length}"
    else:
        Raw = ReadMem(EntryPtr + DataOff, Length)
        if not Raw:
            return "", "narrow_read_fail"
        return Raw.decode('ascii', errors='replace'), f"narrow len={Length}"

KnownGoodCis = [100, 200, 500, 1000, 5000, 10000, 50000, 100000]
FailCis = [675568, 523312, 680252, 680396, 153502, 170928, 368440]

print("=== Testing known CIs with v20260616 resolve ===\n")

for Label, CiList in [("GOOD", KnownGoodCis), ("FAIL", FailCis)]:
    print(f"--- {Label} CIs ---")
    for Ci in CiList:
        EntryPtr, Status = ResolveNamePtr616(Ci)
        if EntryPtr and EntryPtr > 0x1000 and EntryPtr < 0x800000000000:
            Name, Detail = DecryptNameString(EntryPtr)
            print(f"  CI={Ci:>8}: ptr=0x{EntryPtr:X} name='{Name}' ({Detail})")
        else:
            print(f"  CI={Ci:>8}: ptr=0x{EntryPtr:X} ({Status})")
    print()
