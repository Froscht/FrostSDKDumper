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

def ReadU16(Addr):
    D = ReadMem(Addr, 2)
    return struct.unpack("<H", D)[0] if D else 0

def Rol32(V, N):
    V &= 0xFFFFFFFF
    return ((V << N) | (V >> (32 - N))) & 0xFFFFFFFF

def Rol64(V, N):
    V &= 0xFFFFFFFFFFFFFFFF
    return ((V << N) | (V >> (64 - N))) & 0xFFFFFFFFFFFFFFFF

def Pshufb8(DataBytes, MaskBytes):
    Out = bytearray(8)
    for I in range(8):
        Idx = MaskBytes[I]
        Out[I] = 0 if (Idx & 0x80) else DataBytes[Idx & 0x0F]
    return bytes(Out)

def U64ToBytes(V):
    return struct.pack("<Q", V & 0xFFFFFFFFFFFFFFFF)

def BytesToU64(B):
    return struct.unpack("<Q", B[:8])[0]

PoolBase = ModBase + PoolBaseRva
KsBase = ModBase + KeystreamRva

PshufbMask = bytes([0x02, 0x06, 0x03, 0x01, 0x00, 0x04, 0x07, 0x05])
SlotXorConst = BytesToU64(bytes([0xFC, 0x10, 0xD3, 0xFB, 0xCE, 0x56, 0x88, 0x68]))
BlendXor800 = bytes([0xCE, 0xFB, 0xFC, 0xD3, 0x56, 0x68, 0x10, 0x88])
BlendXor810 = bytes([0x31, 0x04, 0x03, 0x2C, 0xA9, 0x97, 0xEF, 0x77])

FNV32P = 0x01000193
FNV64P = 0x100000001B3
FNV64_OFF = 0x124CB31365185276
POOL_XOR = 0xE5C864C1A6B54C7F

def CoreResolve(Ci):
    WordOff = Ci & 0xFFFF
    BlockOff = (Ci >> 8) & 0xFFFF00
    BlockAddr = PoolBase + BlockOff

    FnvLoAddr = (BlockAddr + 3152) & 0xFFFFFFFF
    FnvHiAddr = ((BlockAddr + 3152) >> 32) & 0xFFFFFFFF

    V8 = (16 << 32) | FnvLoAddr
    H = (FNV32P * ((V8 >> 5) & 0xFFFFFFFF) - 724648906) & 0xFFFFFFFF
    H = Rol32(H, 18)
    H = (FNV32P * H + FnvHiAddr - 724648906) & 0xFFFFFFFF
    H = Rol32(H, 27)
    H = (FNV32P * H - 724648906) & 0xFFFFFFFF
    V9 = Rol32(H, 18)

    MixA = ((-109 * V9 + 54) & 0xFF) & 0xFF
    V12 = (FNV32P * V9 - 724648906) & 0xFFFFFFFF
    MixB = (V12 >> 16) & 0xFF
    SlotIdx = (MixA ^ MixB) & 7
    SlotIdx2 = (SlotIdx + 1) & 7

    Slot1Addr = BlockAddr + 32 * SlotIdx + 3168
    Slot2Addr = BlockAddr + 32 * SlotIdx2 + 3168

    Slot1 = ReadU64(Slot1Addr)
    Slot2 = ReadU64(Slot2Addr)
    if not Slot1:
        return None

    S1Rot = Rol64(Slot1, 39)
    S1Bytes = U64ToBytes(S1Rot)
    V13 = BytesToU64(Pshufb8(S1Bytes, PshufbMask)) ^ SlotXorConst

    S2Rot = Rol64(Slot2, 39)
    S2B = U64ToBytes(S2Rot)
    Hmm = bytearray(8)
    for I in range(8):
        Bit = S2B[I]
        Hmm[I] = 0
        for B in range(8):
            M = 1 << B
            if Bit & M:
                Hmm[I] |= BlendXor810[I] & M
            else:
                Hmm[I] |= BlendXor800[I] & M
    SecDec = BytesToU64(Pshufb8(bytes(Hmm), PshufbMask))

    Base = V13 ^ POOL_XOR
    Fnv1 = (FNV64P * Rol64(Base, 54) + FNV64_OFF) & 0xFFFFFFFFFFFFFFFF
    Fnv2 = (FNV64P * Rol64(Fnv1, 32) + FNV64_OFF) & 0xFFFFFFFFFFFFFFFF

    EntryPtr = (Base + (Fnv2 ^ SecDec ^ POOL_XOR) + 2 * WordOff) & 0xFFFFFFFFFFFFFFFF
    return EntryPtr

def ReadString(Addr):
    if Addr < 0x10000 or Addr > 0x800000000000:
        return None
    Hdr = ReadU16(Addr)
    if Hdr is None or Hdr == 0:
        return None
    Length = (Hdr >> 14) | ((Hdr >> 4) & 0x3FC)
    IsWide = bool(Hdr & 0x20)
    if Length == 0 or Length > 1024:
        return None
    ByteLen = Length * 2 if IsWide else Length
    Raw = ReadMem(Addr + 2, ByteLen)
    if not Raw:
        return None
    Buf = bytearray(Raw)
    if not IsWide:
        Key = (Length - 76) & 0xFF
        KV = (Key + 46) & 0xFF
        I = 0
        while I + 1 < Length:
            K1I = ((KV - 46) & 0x3F) + 96
            K2I = (KV & 0x3F) + 96
            Ks1 = ReadU16(KsBase + K1I * 2)
            Ks2 = ReadU16(KsBase + K2I * 2)
            if Ks1 is None or Ks2 is None:
                break
            Buf[I] ^= (Ks1 >> 3) & 0xFF
            Buf[I+1] ^= (Ks2 >> 3) & 0xFF
            I += 2
            KV = (KV - 36) & 0xFF
        if Length & 1 and I < Length:
            KI = ((KV - 46) & 0x3F) + 96
            Ks = ReadU16(KsBase + KI * 2)
            if Ks:
                Buf[I] ^= (Ks >> 3) & 0xFF
        try:
            return Buf[:Length].decode('ascii', errors='replace')
        except:
            return None
    else:
        return f"<wide:{Length}>"

LargeCis = [3, 10, 100, 1000, 143179, 8194631, 11627615, 11626469, 10323790, 10323724, 11706041]
for Ci in LargeCis:
    Ep = CoreResolve(Ci)
    if Ep and 0x10000 < Ep < 0x800000000000:
        Name = ReadString(Ep)
        Print = Name[:60] if Name else "NULL"
        print(f"CI={Ci:>10}: ep=0x{Ep:016X} -> {Print}")
    else:
        print(f"CI={Ci:>10}: FAILED (ep={Ep})")
