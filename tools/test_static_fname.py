#!/usr/bin/env python3
import struct, os

PID = 1195523
ModBase = 0x140000000
PoolBaseRva = 0xE376A80
KeystreamRva = 0xE2B57F4

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

def Rol32(V, N):
    V &= 0xFFFFFFFF
    return ((V << N) | (V >> (32 - N))) & 0xFFFFFFFF

def Rol64(V, N):
    V &= 0xFFFFFFFFFFFFFFFF
    return ((V << N) | (V >> (64 - N))) & 0xFFFFFFFFFFFFFFFF

def Pshuflw(V128Lo, Imm):
    Words = [(V128Lo >> (I * 16)) & 0xFFFF for I in range(4)]
    Out = [0] * 4
    Out[0] = Words[(Imm >> 0) & 3]
    Out[1] = Words[(Imm >> 2) & 3]
    Out[2] = Words[(Imm >> 4) & 3]
    Out[3] = Words[(Imm >> 6) & 3]
    R = 0
    for I in range(4):
        R |= (Out[I] & 0xFFFF) << (I * 16)
    return R & 0xFFFFFFFFFFFFFFFF

def Pshufb(Data8, Mask8):
    Out = bytearray(8)
    for I in range(8):
        Idx = Mask8[I]
        if Idx & 0x80:
            Out[I] = 0
        else:
            Out[I] = Data8[Idx & 0x0F]
    return bytes(Out)

def U64ToBytes(V):
    return struct.pack("<Q", V & 0xFFFFFFFFFFFFFFFF)

def BytesToU64(B):
    return struct.unpack("<Q", B[:8])[0]

PoolBase = ModBase + PoolBaseRva
KeystreamBase = ModBase + KeystreamRva

XmmB4233C0 = bytes([0x02, 0x06, 0x03, 0x01, 0x00, 0x04, 0x07, 0x05])
XmmB4233D0Lo = 0x685688CEFBD310FC
XmmB4233E0Lo = struct.unpack("<Q", bytes([0xDA, 0x67, 0x0E, 0x6A, 0x1C, 0xB3, 0x20, 0x4D]))[0]
XmmB4233F0Lo = struct.unpack("<Q", bytes([0x13, 0xD7, 0xFB, 0x6D, 0x75, 0x2A, 0x40, 0x61]))[0]
XmmB423870Lo = struct.unpack("<Q", bytes([0x40, 0x61, 0x75, 0x2A, 0x75, 0x2A, 0x40, 0x61]))[0]
XmmB423800Lo = bytes([0xCE, 0xFB, 0xFC, 0xD3, 0x56, 0x68, 0x10, 0x88])
XmmB423810Lo = bytes([0x31, 0x04, 0x03, 0x2C, 0xA9, 0x97, 0xEF, 0x77])
XmmB423880Lo = struct.unpack("<Q", bytes([0x40, 0x61, 0x75, 0x2A, 0x13, 0xD7, 0xFB, 0x6D]))[0]
XmmB423580Lo = struct.unpack("<Q", bytes([0x20, 0x4D, 0x1C, 0xB3, 0xDA, 0x67, 0x0E, 0x6A]))[0]
XmmB423590Lo = struct.unpack("<Q", bytes([0xDF, 0xB2, 0xE3, 0x4C, 0x25, 0x98, 0xF1, 0x95]))[0]
XmmB423740Lo = struct.unpack("<Q", bytes([0xEC, 0x28, 0x04, 0x92, 0x8A, 0xD5, 0xBF, 0x9E]))[0]

FNV32_PRIME = 0x01000193
FNV64_PRIME = 0x100000001B3
FNV64_OFFSET = 0x124CB31365185276
POOL_XOR_CONST = 0xE5C864C1A6B54C7F

print("=== Pool structure analysis ===")
print(f"Pool base (live): 0x{PoolBase:X}")

InitGuard = ReadMem(PoolBase - 8, 1)
print(f"Init guard @ 0x{PoolBase-8:X}: {InitGuard[0] if InitGuard else 'FAIL'}")

PoolHeader = ReadMem(PoolBase, 256)
if PoolHeader:
    print(f"Pool first 64 bytes:")
    for I in range(0, 64, 16):
        Hex = ' '.join(f'{B:02X}' for B in PoolHeader[I:I+16])
        print(f"  +0x{I:02X}: {Hex}")

print(f"\n=== Block structure test ===")
Block0 = PoolBase
print(f"Block 0 at 0x{Block0:X}")

SlotData = ReadMem(Block0 + 0xC60, 256)
if SlotData:
    print(f"Slot data at +0xC60:")
    for S in range(8):
        SlotBytes = SlotData[S*32:(S+1)*32]
        Lo = struct.unpack("<Q", SlotBytes[:8])[0]
        Hi = struct.unpack("<Q", SlotBytes[8:16])[0]
        print(f"  slot[{S}]: lo=0x{Lo:016X} hi=0x{Hi:016X}")

Hdr3152 = ReadMem(Block0 + 0xC50, 16)
if Hdr3152:
    print(f"\nBlock header at +0xC50:")
    print(f"  {' '.join(f'{B:02X}' for B in Hdr3152)}")

print(f"\n=== sub_2404F0 pipeline implementation ===")

def CoreResolve(DecodedV5):
    WordOff = DecodedV5 & 0xFFFF
    BlockOff = (DecodedV5 >> 8) & 0xFFFF00
    BlockAddr = PoolBase + BlockOff

    FnvInput = (BlockAddr + 3152) & 0xFFFFFFFF
    FnvInputHi = ((BlockAddr + 3152) >> 32) & 0xFFFFFFFF

    H = (FNV32_PRIME * (((FnvInput | (16 << 32)) >> 5) & 0xFFFFFFFF) - 724648906) & 0xFFFFFFFF
    H = Rol32(H, 18)
    H = (FNV32_PRIME * H + FnvInputHi - 724648906) & 0xFFFFFFFF
    H = Rol32(H, 27)
    H = (FNV32_PRIME * H - 724648906) & 0xFFFFFFFF
    V9 = Rol32(H, 18)

    MixA = ((-109 * V9 + 54) & 0xFF)
    MixB = (((FNV32_PRIME * V9 - 724648906) & 0xFFFFFFFF) >> 16) & 0xFF
    SlotIdx = (MixA ^ MixB) & 7
    SlotIdx2 = (SlotIdx + 1) & 7

    Slot1Addr = BlockAddr + 32 * SlotIdx + 3168
    Slot2Addr = BlockAddr + 32 * SlotIdx2 + 3168

    Slot1Raw = ReadU64(Slot1Addr)
    Slot2Raw = ReadU64(Slot2Addr)

    if not Slot1Raw:
        return None

    Slot1Rot = Rol64(Slot1Raw, 39)
    S1Bytes = U64ToBytes(Slot1Rot)
    V13 = BytesToU64(Pshufb(S1Bytes, XmmB4233C0)) ^ XmmB4233D0Lo

    Slot2Rot = Rol64(Slot2Raw, 39)
    S2Bytes = U64ToBytes(Slot2Rot)
    S2Xored = bytearray(8)
    for I in range(8):
        Bit = S2Bytes[I]
        S2Xored[I] = (Bit & XmmB423810Lo[I]) | (~Bit & XmmB423800Lo[I]) & 0xFF
    SecondDec = BytesToU64(Pshufb(bytes(S2Xored), XmmB4233C0))

    Base = V13 ^ POOL_XOR_CONST
    Fnv1 = (FNV64_PRIME * Rol64(Base, 54) + FNV64_OFFSET) & 0xFFFFFFFFFFFFFFFF
    Fnv2 = (FNV64_PRIME * Rol64(Fnv1, 32) + FNV64_OFFSET) & 0xFFFFFFFFFFFFFFFF

    EntryPtr = (Base + (Fnv2 ^ SecondDec ^ POOL_XOR_CONST) + 2 * WordOff) & 0xFFFFFFFFFFFFFFFF

    return EntryPtr

def DecryptString(EntryAddr):
    Hdr = ReadU16(EntryAddr)
    if not Hdr:
        return None

    Length = (Hdr >> 14) | ((Hdr >> 4) & 0x3FC)
    IsWide = bool(Hdr & 0x20)

    if Length == 0 or Length > 1024:
        return None

    if IsWide:
        RawBytes = ReadMem(EntryAddr + 2, Length * 2)
    else:
        RawBytes = ReadMem(EntryAddr + 2, Length)

    if not RawBytes:
        return None

    Buf = bytearray(RawBytes)

    KeyBase = KeystreamBase + 96 * 2

    if not IsWide:
        Key = (Length - 76) & 0xFF
        KeyV12 = (Key + 46) & 0xFF
        I = 0
        while I + 1 < Length:
            K1Idx = ((KeyV12 - 46) & 0x3F) + 96
            K2Idx = (KeyV12 & 0x3F) + 96
            Ks1 = ReadU16(KeystreamBase + K1Idx * 2)
            Ks2 = ReadU16(KeystreamBase + K2Idx * 2)
            Buf[I] ^= (Ks1 >> 3) & 0xFF
            Buf[I + 1] ^= (Ks2 >> 3) & 0xFF
            I += 2
            KeyV12 = (KeyV12 - 36) & 0xFF
        if Length & 1:
            KIdx = ((KeyV12 - 46) & 0x3F) + 96
            Ks = ReadU16(KeystreamBase + KIdx * 2)
            Buf[I] ^= (Ks >> 3) & 0xFF

        try:
            return Buf[:Length].decode('utf-8', errors='replace')
        except:
            return None
    else:
        Key = (Length + 21172) & 0xFFFF
        I = 0
        while I + 1 < Length:
            K1Idx = (Key & 0x3F) + 96
            K2Idx = ((Key + 46) & 0x3F) + 96
            Ks1 = ReadU16(KeystreamBase + K1Idx * 2)
            Ks2 = ReadU16(KeystreamBase + K2Idx * 2)
            W1 = struct.unpack("<H", Buf[I*2:I*2+2])[0]
            W2 = struct.unpack("<H", Buf[I*2+2:I*2+4])[0]
            struct.pack_into("<H", Buf, I*2, W1 ^ Ks1)
            struct.pack_into("<H", Buf, I*2+2, W2 ^ Ks2)
            I += 2
            Key = (Key + 2012) & 0xFFFF
        if Length & 1:
            KIdx = (Key & 0x3F) + 96
            Ks = ReadU16(KeystreamBase + KIdx * 2)
            W = struct.unpack("<H", Buf[I*2:I*2+2])[0]
            struct.pack_into("<H", Buf, I*2, W ^ Ks)

        try:
            return Buf[:Length*2].decode('utf-16le', errors='replace')
        except:
            return None

print("\n=== Keystream table dump ===")
KsData = ReadMem(KeystreamBase, 64)
if KsData:
    print(f"Keystream @ 0x{KeystreamBase:X}:")
    for I in range(0, 32, 8):
        Vals = [struct.unpack("<H", KsData[J:J+2])[0] for J in range(I, I+8, 2)]
        print(f"  +{I}: {' '.join(f'0x{V:04X}' for V in Vals)}")

KsData96 = ReadMem(KeystreamBase + 96*2, 128)
if KsData96:
    print(f"Keystream @ +96 (used for decrypt):")
    for I in range(0, 64, 8):
        Vals = [struct.unpack("<H", KsData96[J:J+2])[0] for J in range(I, I+8, 2)]
        print(f"  +{96 + I//2}: {' '.join(f'0x{V:04X}' for V in Vals)}")

print(f"\n=== Testing with known CIs ===")
TestCis = [1, 2, 3, 10, 100, 1000, 143179, 8194631]

for Ci in TestCis:
    V3 = Ci & 0xFFFFFFFF
    V3Rot = Rol32(V3, 22)
    V3Shuf = Pshuflw(V3Rot, 0x1E)
    V10 = V3Shuf ^ XmmB4233E0Lo ^ XmmB4233F0Lo

    print(f"\n  CI={Ci}:")
    print(f"    ROL32(CI,22)=0x{V3Rot:08X}")
    print(f"    PSHUFLW(0x1E)=0x{V3Shuf:016X}")
    print(f"    v10 (XOR'd)=0x{V10:016X}")

    FinalV = Pshuflw(V10, 0xEB)
    FinalV ^= XmmB423870Lo
    V5Lo32 = FinalV & 0xFFFFFFFF
    V5Lo32 ^= 0xB31C4D20
    V5 = Rol32(V5Lo32, 10)

    WordOff = V5 & 0xFFFF
    BlockOff = (V5 >> 8) & 0xFFFF00

    print(f"    intermediate: PSHUFLW(0xEB)=0x{Pshuflw(V10, 0xEB):016X}")
    print(f"    v5=0x{V5:08X} word_off={WordOff} block_off=0x{BlockOff:X}")

    EntryPtr = CoreResolve(V5)
    if EntryPtr:
        print(f"    entry_ptr=0x{EntryPtr:016X}")

        if 0x10000 < EntryPtr < 0x800000000000:
            Name = DecryptString(EntryPtr)
            if Name:
                print(f"    → \"{Name}\"")
            else:
                Hdr = ReadU16(EntryPtr)
                Raw = ReadMem(EntryPtr, 16)
                print(f"    → decrypt failed (hdr=0x{Hdr:04X} raw={' '.join(f'{B:02X}' for B in (Raw or b''))[:48]})")
        else:
            print(f"    → invalid entry ptr!")
    else:
        print(f"    → resolve failed")
