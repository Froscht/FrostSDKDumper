#!/usr/bin/env python3
import struct, ctypes

PID = 12035
MODULE_BASE = 0x140000000
PSHUFB_MASK = [6,5,2,3,4,1,0,7]
XOR_LO64 = 0x5EA772D07F910744

FNV_PRIME = 0x01000193
OLD_HASH_ADD = 0x8F957A95
NEW_HASH_ADD = 0x5619E046

CLASS_META = 0x76598800

def u32(x): return x & 0xFFFFFFFF
def rol32(x, n): return u32((x << n) | (x >> (32 - n)))

def read_mem(pid, addr, sz):
    with open(f"/proc/{pid}/mem", "rb") as f:
        f.seek(addr)
        return f.read(sz)

def pshufb_lo64(data):
    out = bytearray(8)
    for i in range(8):
        idx = PSHUFB_MASK[i]
        out[i] = data[idx] if idx < len(data) else 0
    return struct.unpack('<Q', out)[0]

def new_slot_hash(addr):
    Val = u32(addr + 0x10)
    Hi32 = ((addr + 0x10) >> 32) & 0xFFFFFFFF
    H = u32(FNV_PRIME * rol32(Val, 26) + NEW_HASH_ADD)
    H = u32(rol32(H, 27) + Hi32 + NEW_HASH_ADD)
    H = u32(FNV_PRIME * (H >> 6) + NEW_HASH_ADD)
    H = u32(FNV_PRIME * (H >> 5) + NEW_HASH_ADD)
    return H

def old_slot_hash(addr):
    E = u32(addr)
    Hi32 = (addr >> 32) & 0xFFFFFFFF
    H = u32(FNV_PRIME * rol32(E, 26) + OLD_HASH_ADD)
    H = u32(rol32(H, 27) + Hi32 + OLD_HASH_ADD)
    H = u32(FNV_PRIME * (H >> 6) + OLD_HASH_ADD)
    H = u32(FNV_PRIME * (H >> 5) + OLD_HASH_ADD)
    return H

def class_slot_idx(h):
    return ((h & 0xFF) ^ ((h >> 16) & 0xFF)) & 3

def name_slot_idx_old(h):
    return (((h & 0xFF) ^ ((h >> 8) & 0xFF)) & 3) ^ 2

KnownObjects = [
    (0x39789700, "Actor", 0x76598800),
    (0x765BBB00, "ActorComponent", 0x76598800),
    (0x76966100, "GameplayCueNotify_Actor", 0x76598800),
]

print("=== NEW HASH (obj+0x10, const=0x5619E046) ===\n")

for Addr, Name, ExpectedClass in KnownObjects:
    Data = read_mem(PID, Addr, 0xA0)
    H = new_slot_hash(Addr)
    ClassIdx = class_slot_idx(H)

    Off = 0x20 + ClassIdx * 0x20
    Enc = Data[Off:Off+16]
    Shuffled = pshufb_lo64(Enc)
    Ptr = Shuffled ^ XOR_LO64

    print(f"{Name} @ 0x{Addr:X}: hash=0x{H:08X} classSlot={ClassIdx}")
    print(f"  slot[{ClassIdx}] enc={Enc[:8].hex()} → ptr=0x{Ptr:016X}")
    print(f"  expected=0x{ExpectedClass:016X} match={Ptr == ExpectedClass}")

    for Si in range(4):
        O = 0x20 + Si * 0x20
        E = Data[O:O+16]
        S = pshufb_lo64(E)
        P = S ^ XOR_LO64
        R = ((P << 32) | (P >> 32)) & 0xFFFFFFFFFFFFFFFF
        Ci = R & 0xFFFFFFFF
        print(f"  slot[{Si}] ptr=0x{P:016X}  nameCI=0x{Ci:X}")
    print()

print("\n=== OLD HASH (obj, const=0x8F957A95) ===\n")

for Addr, Name, ExpectedClass in KnownObjects:
    Data = read_mem(PID, Addr, 0xA0)
    H = old_slot_hash(Addr)
    NameIdx = name_slot_idx_old(H)
    ClassIdx = class_slot_idx(H)

    NameOff = 0x20 + NameIdx * 0x20
    ClassOff = 0x20 + ClassIdx * 0x20

    NameEnc = Data[NameOff:NameOff+16]
    NameShuf = pshufb_lo64(NameEnc)
    NameXor = NameShuf ^ XOR_LO64
    NameRol = ((NameXor << 32) | (NameXor >> 32)) & 0xFFFFFFFFFFFFFFFF
    Ci = NameRol & 0xFFFFFFFF

    ClassEnc = Data[ClassOff:ClassOff+16]
    ClassShuf = pshufb_lo64(ClassEnc)
    ClassPtr = ClassShuf ^ XOR_LO64

    print(f"{Name} @ 0x{Addr:X}: hash=0x{H:08X}")
    print(f"  nameSlot={NameIdx} → CI=0x{Ci:X}")
    print(f"  classSlot={ClassIdx} → ptr=0x{ClassPtr:016X} (expected=0x{ExpectedClass:016X})")
    print()

print("\n=== BRUTE-FORCE: try all combos of input/constant for hash ===")
for UseNewAddr in [False, True]:
    for Const in [OLD_HASH_ADD, NEW_HASH_ADD]:
        HitsClass = 0
        HitsName = 0
        for Addr, Name, ExpectedClass in KnownObjects:
            Data = read_mem(PID, Addr, 0xA0)
            if UseNewAddr:
                Val = u32(Addr + 0x10)
                Hi32 = ((Addr + 0x10) >> 32) & 0xFFFFFFFF
            else:
                Val = u32(Addr)
                Hi32 = (Addr >> 32) & 0xFFFFFFFF
            H = u32(FNV_PRIME * rol32(Val, 26) + Const)
            H = u32(rol32(H, 27) + Hi32 + Const)
            H = u32(FNV_PRIME * (H >> 6) + Const)
            H = u32(FNV_PRIME * (H >> 5) + Const)

            Ci = class_slot_idx(H)
            O = 0x20 + Ci * 0x20
            E = Data[O:O+16]
            S = pshufb_lo64(E)
            P = S ^ XOR_LO64
            if P == ExpectedClass:
                HitsClass += 1

            for Si in range(4):
                O2 = 0x20 + Si * 0x20
                E2 = Data[O2:O2+16]
                S2 = pshufb_lo64(E2)
                P2 = S2 ^ XOR_LO64
                R2 = ((P2 << 32) | (P2 >> 32)) & 0xFFFFFFFFFFFFFFFF
                Ci2 = R2 & 0xFFFFFFFF
                if 0 < Ci2 < 0x100000 and Si == Ci:
                    pass

        Lbl = f"addr={'obj+0x10' if UseNewAddr else 'obj':>8s} const=0x{Const:08X}"
        print(f"  {Lbl}: classHits={HitsClass}/{len(KnownObjects)}")
