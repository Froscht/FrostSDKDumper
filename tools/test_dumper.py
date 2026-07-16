#!/usr/bin/env python3
"""Python test harness for FrostSDKDumper — rapid iteration without rebuild.

Usage:
    sudo python3 tools/test_dumper.py [PID]           # full run
    sudo python3 tools/test_dumper.py [PID] --fname CI # test FName for CompIndex
    sudo python3 tools/test_dumper.py [PID] --probe    # probe NumElements only
    sudo python3 tools/test_dumper.py [PID] --vtables  # classify and print vtable histogram
"""

import sys, os, struct, ctypes, ctypes.util, json, argparse
from collections import defaultdict

MODULE_BASE = 0x140000000

RVA_GOBJECT_ARRAY = 0xE7ADF20
RVA_GNAMES_POOL   = 0xE4F2A00
RVA_KEYTABLE       = 0xE4318DC
RVA_SIMD_BLOCK     = 0xE4317F4
RVA_BLOCK_FNV_XOR  = 0xB523C50

SHARD_HASH_ADD     = 0xD5AF8E52
SHARD_HASH_ROL_A   = 17
SHARD_HASH_ROL_B   = 13
FNV32_PRIME        = 0x01000193

BLOCK_ROL64        = 13
BLOCK_PSHUFLW      = 0x93
BLOCK_FNV_XOR      = 0x19EA7DF486E7194E

FNV64_PRIME        = 0x100000001B3
FNV64_ADD          = 0x10F3A73711CE0312
FNV_ROL1           = 37
FNV_ROL2           = 40

PTR_XOR1           = 0x14329DBF
PTR_XOR2           = 0x2E3400000000
PTR_XOR3           = 0xBF9D1C2000000000

HDR_LENGTH_SHIFT   = 6
HDR_IS_WIDE_BIT    = 0x20

KEY_INIT_ADD       = 0xA7B4

CHUNK_SEED_OFF     = 0x2F90
CHUNK_BLOCK_OFF    = 0x2FA0
BLOCK_STRIDE       = 32
ITEMS_PER_CHUNK    = 65536

UOBJ_SLOT_ROL64    = 29
UOBJ_SLOT_PSHUFLW  = 0x39
UOBJ_SLOT_ROL32    = 5

SLOT_HASH_ADD      = 0xF3D8DA36

FFIELD_NAME_XOR    = 0x8FFAB191C340B792
FFIELD_NAME_PSHUFB = bytes([0x07,0x06,0x04,0x05,0x02,0x03,0x00,0x01])
FFIELD_NAME_ROL16  = 12
FFIELD_NAME_ROL64  = 32

PROP_OFFSET_XOR    = 0xA271DBC5

OFFSET_SUPER_STRUCT     = 0xB0
OFFSET_CHILD_PROPERTIES = 0xF0
OFFSET_PROPERTIES_SIZE  = 0xD0
OFFSET_FFIELD_NEXT      = 0x78
OFFSET_FFIELD_NAME      = 0xA0
OFFSET_FFIELD_OWNER     = 0x80
OFFSET_FFIELD_CLASS     = 0xB8
OFFSET_PROP_ELEM_SIZE   = 0xD0
OFFSET_PROP_OFFSET_INT  = 0xE4
OFFSET_PROP_ARRAY_DIM   = 0x110
OFFSET_PROP_SUB         = 0x138
OFFSET_BOOL_FIELD_SIZE  = 0x138

CHUNKS_MGR_PSHUFLW_IMM = 0x1B
CHUNKS_MGR_ROL32       = 7
CHUNKS_MGR_XOR_KEY     = 0x878588013124D57F


LIBC = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

class Iovec(ctypes.Structure):
    _fields_ = [("iov_base", ctypes.c_void_p), ("iov_len", ctypes.c_size_t)]

_process_vm_readv = LIBC.process_vm_readv
_process_vm_readv.restype = ctypes.c_ssize_t
_process_vm_readv.argtypes = [
    ctypes.c_int,
    ctypes.POINTER(Iovec), ctypes.c_ulong,
    ctypes.POINTER(Iovec), ctypes.c_ulong,
    ctypes.c_ulong,
]


class MemReader:
    def __init__(self, Pid):
        self.Pid = Pid
        self.DevFd = -1
        try:
            self.DevFd = os.open("/dev/memreader", os.O_RDWR)
        except OSError:
            pass

    def read(self, Addr, Size):
        if self.DevFd >= 0:
            return self._read_dev(Addr, Size)
        return self._read_vm(Addr, Size)

    def _read_dev(self, Addr, Size):
        import fcntl

        class Req(ctypes.Structure):
            _fields_ = [
                ("pid", ctypes.c_int), ("_pad", ctypes.c_int),
                ("address", ctypes.c_ulong), ("size", ctypes.c_ulong),
                ("buffer", ctypes.c_void_p),
            ]
        Buf = (ctypes.c_ubyte * Size)()
        R = Req(pid=self.Pid, _pad=0, address=Addr, size=Size,
                buffer=ctypes.cast(Buf, ctypes.c_void_p))
        Ioctl = (3 << 30) | (ctypes.sizeof(R) << 16) | (ord('M') << 8) | 1
        try:
            fcntl.ioctl(self.DevFd, Ioctl, R)
            return bytes(Buf)
        except OSError:
            return None

    def _read_vm(self, Addr, Size):
        Buf = (ctypes.c_ubyte * Size)()
        Local = Iovec(ctypes.cast(Buf, ctypes.c_void_p), Size)
        Remote = Iovec(ctypes.c_void_p(Addr), Size)
        Ret = _process_vm_readv(self.Pid, ctypes.byref(Local), 1,
                                ctypes.byref(Remote), 1, 0)
        if Ret < 0:
            return None
        return bytes(Buf)

    def u32(self, Addr):
        D = self.read(Addr, 4)
        return struct.unpack("<I", D)[0] if D else None

    def u64(self, Addr):
        D = self.read(Addr, 8)
        return struct.unpack("<Q", D)[0] if D else None

    def u16(self, Addr):
        D = self.read(Addr, 2)
        return struct.unpack("<H", D)[0] if D else None


M32 = 0xFFFFFFFF
M64 = 0xFFFFFFFFFFFFFFFF

def Rol32(V, N):
    V &= M32
    N &= 31
    return ((V << N) | (V >> (32 - N))) & M32

def Rol64(V, N):
    V &= M64
    N &= 63
    return ((V << N) | (V >> (64 - N))) & M64

def Rol16(V, N):
    V &= 0xFFFF
    N &= 15
    return ((V << N) | (V >> (16 - N))) & 0xFFFF

def Bswap64(V):
    return int.from_bytes(V.to_bytes(8, 'little'), 'big')

def Bswap32(V):
    return int.from_bytes((V & M32).to_bytes(4, 'little'), 'big')

def Pshuflw(V, Imm):
    B = V.to_bytes(8, 'little')
    Lo = [struct.unpack_from("<H", B, i*2)[0] for i in range(4)]
    Shuffled = [Lo[(Imm >> (i*2)) & 3] for i in range(4)]
    Out = bytearray(8)
    for i in range(4):
        struct.pack_into("<H", Out, i*2, Shuffled[i])
    return int.from_bytes(Out, 'little')

def Pshufb8(V, Mask):
    Vb = V.to_bytes(8, 'little')
    Out = bytearray(8)
    for i in range(8):
        Idx = Mask[i]
        Out[i] = Vb[Idx & 7] if Idx < 8 else 0
    return int.from_bytes(Out, 'little')

def IsHeap(P):
    return P > 0x10000 and P < 0x800000000000 and not (P >= MODULE_BASE and P < MODULE_BASE + 0x12000000)

def IsModuleVt(Vt):
    return Vt >= MODULE_BASE and Vt < MODULE_BASE + 0x12000000


KeyTable = None

def LoadKeyTable(Reader):
    global KeyTable
    Addr = MODULE_BASE + RVA_KEYTABLE
    D = Reader.read(Addr, 128)
    if not D:
        Addr2 = MODULE_BASE + RVA_SIMD_BLOCK + 0xE8
        D = Reader.read(Addr2, 128)
    if D:
        KeyTable = [struct.unpack_from("<H", D, i*2)[0] for i in range(64)]
        Nz = sum(1 for V in KeyTable if V != 0)
        print(f"[fname] KeyTable loaded: {Nz}/64 non-zero entries")
    else:
        print("[fname] FAILED to load KeyTable")


def FNameResolve(Reader, Ci):
    if KeyTable is None:
        return None

    NameOff = Ci & 0xFFFF
    ChunkOff = (Ci >> 8) & 0xFFFF00
    ChunkAddr = (MODULE_BASE + RVA_GNAMES_POOL) + ChunkOff

    SeedAddr = ChunkAddr + CHUNK_SEED_OFF
    SeedData = Reader.read(SeedAddr, 8)
    if not SeedData:
        return None
    Lo = struct.unpack_from("<I", SeedData, 0)[0]
    Hi = struct.unpack_from("<I", SeedData, 4)[0]

    H = (FNV32_PRIME * Rol32(Lo, SHARD_HASH_ROL_A) + SHARD_HASH_ADD) & M32
    H = (FNV32_PRIME * Rol32(H, SHARD_HASH_ROL_B) + Hi + SHARD_HASH_ADD) & M32
    H = (FNV32_PRIME * Rol32(H, SHARD_HASH_ROL_A) + SHARD_HASH_ADD) & M32
    T = Rol32(H, SHARD_HASH_ROL_B)

    Pa = ((-109 * T + 82) & M32) & 0xFF
    Pb = (((FNV32_PRIME * T + SHARD_HASH_ADD) & M32) >> 16) & 0xFF
    Bidx1 = (Pa ^ Pb) & 7
    Bidx2 = (Bidx1 + 1) & 7

    BlockBase = ChunkAddr + CHUNK_BLOCK_OFF

    def DecBlock(Idx):
        D = Reader.read(BlockBase + Idx * BLOCK_STRIDE, 8)
        if not D:
            return 0
        Raw = struct.unpack("<Q", D)[0]
        Rotated = Rol64(Raw, BLOCK_ROL64)
        Shuffled = Pshuflw(Rotated, BLOCK_PSHUFLW)
        return (Shuffled ^ BLOCK_FNV_XOR) & M64

    V13 = DecBlock(Bidx1)
    V15 = DecBlock(Bidx2)

    Fv1 = (FNV64_PRIME * Rol64(V13, FNV_ROL1) + FNV64_ADD) & M64
    Fv2 = (FNV64_PRIME * Rol64(Fv1, FNV_ROL2) + FNV64_ADD) & M64
    RawPtr = (V13 + (V15 ^ Fv2) + 2 * NameOff) & M64

    Step1 = Bswap64((RawPtr ^ PTR_XOR1) & M64)
    Step2 = (Step1 ^ PTR_XOR2) & M64
    EntryPtr = Bswap64((Step2 ^ PTR_XOR3) & M64)

    if not IsHeap(EntryPtr):
        return None

    HdrData = Reader.read(EntryPtr, 2)
    if not HdrData:
        return None
    Hdr = struct.unpack("<H", HdrData)[0]
    Length = Hdr >> HDR_LENGTH_SHIFT
    IsWide = (Hdr & HDR_IS_WIDE_BIT) != 0

    if Length == 0 or Length > 1024:
        return None

    if IsWide:
        StrData = Reader.read(EntryPtr + 2, Length * 2)
        if not StrData:
            return None
        Sb = bytearray(StrData)
        Key = (Length + KEY_INIT_ADD) & 0xFFFF
        for I in range(0, Length * 2, 4):
            Kv = KeyTable[Key & 0x3F] >> 3
            if I < len(Sb): Sb[I] ^= (Kv & 0xFF)
            if I+1 < len(Sb): Sb[I+1] ^= ((Kv >> 8) & 0xFF)
            Idx2 = ((Key * 0xFFFF584C + 0xF629) & 0xFFFF) & 0x3D
            Kv2 = KeyTable[Idx2] >> 3
            if I+2 < len(Sb): Sb[I+2] ^= (Kv2 & 0xFF)
            if I+3 < len(Sb): Sb[I+3] ^= ((Kv2 >> 8) & 0xFF)
            Key = (Key * 0x6DDC5690 + 0x5EBF2255) & 0xFFFFFFFF
        try:
            return bytes(Sb).decode('utf-16-le', errors='replace')
        except:
            return None
    else:
        StrData = Reader.read(EntryPtr + 2, Length)
        if not StrData:
            return None
        Sb = bytearray(StrData)
        Key = (Length + KEY_INIT_ADD) & 0xFFFF
        for I in range(0, Length, 2):
            Kv = (KeyTable[Key & 0x3F] >> 3) & 0xFF
            Sb[I] ^= Kv
            if I + 1 < Length:
                Idx2 = ((Key * 0xFFFF584C + 0xF629) & 0xFFFF) & 0x3D
                Kv2 = (KeyTable[Idx2] >> 3) & 0xFF
                Sb[I+1] ^= Kv2
            Key = (Key * 0x6DDC5690 + 0x5EBF2255) & 0xFFFFFFFF
        try:
            return bytes(Sb).decode('ascii', errors='replace')
        except:
            return None


def Rol64Lane2(Lo, Hi, N):
    return Rol64(Lo, N), Rol64(Hi, N)

def Rol32Lane4(D0, D1, D2, D3, N):
    return Rol32(D0, N), Rol32(D1, N), Rol32(D2, N), Rol32(D3, N)

def Pshuflw128(Lo64, Hi64, Imm):
    B = Lo64.to_bytes(8, 'little')
    Words = [struct.unpack_from("<H", B, i*2)[0] for i in range(4)]
    Shuffled = [Words[(Imm >> (i*2)) & 3] for i in range(4)]
    Out = bytearray(8)
    for i in range(4):
        struct.pack_into("<H", Out, i*2, Shuffled[i])
    return int.from_bytes(Out, 'little'), Hi64

def DecodeUObjectSlot128(Enc16):
    Lo = struct.unpack_from("<Q", Enc16, 0)[0]
    Hi = struct.unpack_from("<Q", Enc16, 8)[0]
    Lo, Hi = Rol64Lane2(Lo, Hi, UOBJ_SLOT_ROL64)
    Lo, Hi = Pshuflw128(Lo, Hi, UOBJ_SLOT_PSHUFLW)
    D0 = Lo & M32
    D1 = (Lo >> 32) & M32
    D2 = Hi & M32
    D3 = (Hi >> 32) & M32
    D0, D1, D2, D3 = Rol32Lane4(D0, D1, D2, D3, UOBJ_SLOT_ROL32)
    ResultLo = (D1 << 32) | D0
    Ci = (ResultLo >> 32) & M32
    Number = ResultLo & M32
    return Ci, Number

def DecodeUObjectSlot(Reader, ObjAddr):
    IsCi = lambda H: H > 1 and H < 0x2000000
    for SlotIdx in range(4):
        Addr = ObjAddr + 0x20 + SlotIdx * 0x20
        Enc = Reader.read(Addr, 16)
        if not Enc or len(Enc) < 16:
            continue
        if all(B == 0 for B in Enc):
            continue
        Ci, Number = DecodeUObjectSlot128(Enc)
        if IsCi(Ci):
            return Ci, Number
    return None, None


def DecodeFFieldName(Reader, FieldAddr):
    Raw = Reader.u64(FieldAddr + OFFSET_FFIELD_NAME)
    if Raw is None:
        return None
    V = (Raw ^ FFIELD_NAME_XOR) & M64

    B = V.to_bytes(8, 'little')
    Words = [struct.unpack_from("<H", B, i*2)[0] for i in range(4)]
    Words = [Rol16(W, FFIELD_NAME_ROL16) for W in Words]
    V2 = 0
    for i in range(4):
        V2 |= (Words[i] << (i*16))

    V3 = Pshufb8(V2, FFIELD_NAME_PSHUFB)
    Ci = Rol64(V3, FFIELD_NAME_ROL64) & M64

    Ci32 = Ci & 0xFFFFFFFF
    if Ci32 == 0 or Ci32 > 0x2000000:
        return None
    return Ci32


def ValidateChunksMgr(Reader, Cand):
    if not IsHeap(Cand):
        return False
    for VtOff in [0x80, 0x60, 0xA0]:
        VtPtr = Reader.u64(Cand + VtOff)
        if VtPtr and IsModuleVt(VtPtr):
            return True
    return False


def DecryptChunksManager(Reader, GobjAbs):
    for Off in range(0x80, 0x140, 0x10):
        Raw = Reader.u64(GobjAbs + Off)
        if Raw is None:
            continue

        Xored = (Raw ^ CHUNKS_MGR_XOR_KEY) & M64
        Lo = Rol32(Xored & M32, CHUNKS_MGR_ROL32)
        Hi = Rol32((Xored >> 32) & M32, CHUNKS_MGR_ROL32)
        Rotated = (Hi << 32) | Lo
        Mgr = Pshuflw(Rotated, CHUNKS_MGR_PSHUFLW_IMM)

        if ValidateChunksMgr(Reader, Mgr):
            print(f"[py] chunks_manager=0x{Mgr:X} @ GObj+0x{Off:X} "
                  f"(XOR+ROL32({CHUNKS_MGR_ROL32})+PSHUFLW(0x{CHUNKS_MGR_PSHUFLW_IMM:X}))")
            return Mgr, Off

    print("[py] chunks_manager not found via XOR+ROL32+PSHUFLW — trying heap probe")
    return None, 0


ImageSizeCache = [0]

def GetImageSize(Reader):
    if ImageSizeCache[0]:
        return ImageSizeCache[0]
    DosHdr = Reader.read(MODULE_BASE, 0x40)
    if not DosHdr:
        return 0x12000000
    ELfanew = struct.unpack_from("<I", DosHdr, 0x3C)[0]
    PeHdr = Reader.read(MODULE_BASE + ELfanew, 0x18 + 0x70)
    if not PeHdr:
        return 0x12000000
    ImgSize = struct.unpack_from("<I", PeHdr, 0x18 + 0x38)[0]
    ImageSizeCache[0] = ImgSize
    return ImgSize

RdataCache = [None, 0, 0]

def EnsureRdataCache(Reader):
    if RdataCache[0] is not None:
        return
    ImgSize = GetImageSize(Reader)
    RdataStart = 0xA000000
    RdataSize = min(ImgSize - RdataStart, 0x6000000)
    if RdataSize <= 0:
        RdataCache[0] = b''
        return
    ChunkSize = 0x100000
    Chunks = []
    Addr = MODULE_BASE + RdataStart
    Remain = RdataSize
    while Remain > 0:
        Sz = min(ChunkSize, Remain)
        D = Reader.read(Addr, Sz)
        if not D:
            D = b'\x00' * Sz
        Chunks.append(D)
        Addr += Sz
        Remain -= Sz
    RdataCache[0] = b''.join(Chunks)
    RdataCache[1] = RdataStart
    RdataCache[2] = RdataSize
    print(f"[emu] cached .rdata: 0x{RdataStart:X}..0x{RdataStart+RdataSize:X} ({RdataSize//1024//1024}MB)")

def EmulateSIMDFunction(Reader, FuncRva, BlobAddr):
    try:
        from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_MEM_READ_UNMAPPED
        from unicorn.x86_const import (UC_X86_REG_XMM0, UC_X86_REG_XMM1, UC_X86_REG_XMM2,
                                        UC_X86_REG_XMM3, UC_X86_REG_RAX, UC_X86_REG_RCX,
                                        UC_X86_REG_RDX, UC_X86_REG_RSP, UC_X86_REG_RIP)
    except ImportError:
        return None

    EnsureRdataCache(Reader)

    FuncAddr = MODULE_BASE + FuncRva
    Code = Reader.read(FuncAddr, 0x2000)
    if not Code:
        return None

    Blob = Reader.read(BlobAddr, 16)
    if not Blob:
        return None

    Uc_ = Uc(UC_ARCH_X86, UC_MODE_64)

    StackBase = 0x20000000
    DataBase = 0x30000000

    Uc_.mem_map(MODULE_BASE, 0x1000)
    CodePage = FuncAddr & ~0xFFF
    CodeSize = ((len(Code) + 0xFFF) & ~0xFFF) + 0x1000
    Uc_.mem_map(CodePage, CodeSize)
    Uc_.mem_write(FuncAddr, Code)

    if RdataCache[0] and len(RdataCache[0]) > 0:
        RdStart = MODULE_BASE + RdataCache[1]
        RdSize = (len(RdataCache[0]) + 0xFFF) & ~0xFFF
        try:
            Uc_.mem_map(RdStart, RdSize)
            Uc_.mem_write(RdStart, RdataCache[0])
        except Exception:
            pass

    Uc_.mem_map(StackBase, 0x10000)
    Uc_.mem_map(DataBase, 0x10000)

    Uc_.mem_write(DataBase, Blob)

    Uc_.reg_write(UC_X86_REG_RSP, StackBase + 0x8000)
    Uc_.reg_write(UC_X86_REG_RCX, DataBase)
    Uc_.reg_write(UC_X86_REG_RDX, DataBase)

    Uc_.reg_write(UC_X86_REG_XMM0, int.from_bytes(Blob, 'little'))

    def HookUnmapped(Uc, Access, Addr, Size, Value, Data):
        Page = Addr & ~0xFFF
        D = Reader.read(Page, 0x1000)
        if D:
            try:
                Uc.mem_map(Page, 0x1000)
                Uc.mem_write(Page, D)
            except Exception:
                pass
            return True
        return False
    Uc_.hook_add(UC_HOOK_MEM_READ_UNMAPPED, HookUnmapped)

    try:
        RetBytes = b'\xc3'
        RetAddr = CodePage + CodeSize - 0x10
        Uc_.mem_write(RetAddr, RetBytes)
        Uc_.mem_write(StackBase + 0x8000, struct.pack("<Q", RetAddr))

        Uc_.emu_start(FuncAddr, RetAddr, timeout=2000000, count=2000)
        Xmm0 = Uc_.reg_read(UC_X86_REG_XMM0)
        Result = Xmm0 & M64
        return Result
    except Exception as E:
        print(f"[emu] emulation failed: {E}")
        return None


def Vt2InterpretChunkArray(Reader, ChunksMgr):
    for VtOff in [0x80, 0x60, 0xA0]:
        VtPtr = Reader.u64(ChunksMgr + VtOff)
        if not VtPtr or not IsModuleVt(VtPtr):
            continue
        for VtIdx in [6, 5, 7, 3, 4]:
            FnPtr = Reader.u64(VtPtr + VtIdx * 8)
            if not FnPtr or not IsModuleVt(FnPtr):
                continue
            FnRva = FnPtr - MODULE_BASE
            for BlobOff in [0xB0, 0x90, 0xA0, 0x70, 0xC0, 0xD0]:
                Result = EmulateSIMDFunction(Reader, FnRva, ChunksMgr + BlobOff)
                if Result and IsHeap(Result):
                    Score = ValidateChunkArray(Reader, Result)
                    if Score >= 1:
                        print(f"[py] chunk_array=0x{Result:X} via Unicorn emu "
                              f"(vt[{VtIdx}]@+0x{VtOff:X}, blob@+0x{BlobOff:X}, score={Score})")
                        return Result
    return None


def ValidateChunkArray(Reader, Arr):
    Score = 0
    for I in range(min(3, 256)):
        Cp = Reader.u64(Arr + I * 8)
        if not Cp or not IsHeap(Cp):
            break
        Obj = Reader.u64(Cp)
        if not Obj or not IsHeap(Obj):
            break
        Vt = Reader.u64(Obj)
        if not Vt or not IsModuleVt(Vt):
            break
        Score += 1
    return Score


def FindChunkArray(Reader, ChunksMgr):
    BestArr = None
    BestScore = 0
    BestOff = 0

    for Off in range(0, 0x400, 8):
        Ptr = Reader.u64(ChunksMgr + Off)
        if Ptr is None or not IsHeap(Ptr):
            continue
        Score = ValidateChunkArray(Reader, Ptr)
        if Score >= 2 and Score > BestScore:
            BestScore = Score
            BestArr = Ptr
            BestOff = Off

    if BestArr:
        print(f"[py] chunk_array=0x{BestArr:X} @ chunks_mgr+0x{BestOff:X} (score={BestScore})")
        return BestArr

    print("[py] plaintext scan failed — trying Unicorn SIMD emulation...")
    Arr = Vt2InterpretChunkArray(Reader, ChunksMgr)
    if Arr:
        return Arr

    print("[py] chunk_array not found")
    return None


def ProbeChunkArrayDirect(Reader, GobjAbs):
    print("[py] trying direct chunk_array probe from GObj data...")
    GobjData = Reader.read(GobjAbs, 0x200)
    if not GobjData:
        return None

    for Off in range(0, 0x200, 8):
        Ptr = struct.unpack_from("<Q", GobjData, Off)[0]
        if not IsHeap(Ptr):
            continue
        Cp0 = Reader.u64(Ptr)
        if Cp0 is None or not IsHeap(Cp0):
            continue
        Obj0 = Reader.u64(Cp0)
        if Obj0 is None or not IsHeap(Obj0):
            continue
        Vt0 = Reader.u64(Obj0)
        if Vt0 and IsModuleVt(Vt0):
            Cp1 = Reader.u64(Ptr + 8)
            if Cp1 and IsHeap(Cp1):
                Obj1 = Reader.u64(Cp1)
                if Obj1 and IsHeap(Obj1):
                    Vt1 = Reader.u64(Obj1)
                    if Vt1 and IsModuleVt(Vt1):
                        print(f"[py] chunk_array=0x{Ptr:X} @ GObj+0x{Off:X} (direct probe)")
                        return Ptr
    return None


def WalkChunks(Reader, ChunkArr, MaxChunks=256):
    ChunkPtrData = Reader.read(ChunkArr, MaxChunks * 8)
    if not ChunkPtrData:
        print("[py] failed to read chunk pointer array")
        return []

    ChunkPtrs = []
    for I in range(MaxChunks):
        Cp = struct.unpack_from("<Q", ChunkPtrData, I*8)[0]
        if not IsHeap(Cp):
            break
        ChunkPtrs.append(Cp)

    print(f"[py] {len(ChunkPtrs)} valid chunk pointers")

    Strides = [16, 20, 24, 32]
    BestStride = 20
    BestHits = 0
    if ChunkPtrs:
        for Stride in Strides:
            ProbeSize = 256 * Stride
            D = Reader.read(ChunkPtrs[0], ProbeSize)
            if not D:
                continue
            Hits = 0
            for I in range(256):
                Off = I * Stride
                if Off + 8 > len(D):
                    break
                Obj = struct.unpack_from("<Q", D, Off)[0]
                if not IsHeap(Obj):
                    continue
                Vt = Reader.u64(Obj)
                if Vt and IsModuleVt(Vt):
                    Hits += 1
            print(f"[py] stride={Stride}: {Hits}/256 valid UObjects")
            if Hits > BestHits:
                BestHits = Hits
                BestStride = Stride
        print(f"[py] using stride={BestStride}")

    Objects = []
    for Ci, Cp in enumerate(ChunkPtrs):
        N = ITEMS_PER_CHUNK
        BufSize = N * BestStride
        D = Reader.read(Cp, BufSize)
        if not D:
            continue
        ChunkObjs = 0
        for I in range(N):
            Off = I * BestStride
            if Off + 8 > len(D):
                break
            Obj = struct.unpack_from("<Q", D, Off)[0]
            if IsHeap(Obj):
                Objects.append(Obj)
                ChunkObjs += 1
        if Ci < 5 or ChunkObjs > 0:
            print(f"[py] chunk[{Ci}]: {ChunkObjs} objects")

    print(f"[py] walked {len(ChunkPtrs)} chunks, found {len(Objects)} UObjects")
    return Objects


def ClassifyByVtable(Reader, Objects, Vtables):
    VtHist = defaultdict(int)
    ObjByVt = defaultdict(list)

    for Obj in Objects:
        Vt = Reader.u64(Obj)
        if not Vt or not IsModuleVt(Vt):
            continue
        Rva = Vt - MODULE_BASE
        VtHist[Rva] += 1
        if len(ObjByVt[Rva]) < 5:
            ObjByVt[Rva].append(Obj)

    ClassCount = 0
    StructCount = 0
    EnumCount = 0
    FuncCount = 0
    OtherCount = 0

    StructRvas = set()
    ClassRvas = set()
    EnumRvas = set()
    FuncRvas = set()

    if Vtables.get("script_struct_rva"):
        StructRvas.add(int(Vtables["script_struct_rva"], 16))
    if Vtables.get("asstruct_rva"):
        StructRvas.add(int(Vtables["asstruct_rva"], 16))
    if Vtables.get("class_native_rva"):
        ClassRvas.add(int(Vtables["class_native_rva"], 16))
    if Vtables.get("asclass_rva"):
        ClassRvas.add(int(Vtables["asclass_rva"], 16))
    for K in ["bpgc_rva", "wbpgc_rva", "smbpgc_rva", "anim_bpgc_rva"]:
        if Vtables.get(K):
            ClassRvas.add(int(Vtables[K], 16))
    if Vtables.get("enum_rva"):
        EnumRvas.add(int(Vtables["enum_rva"], 16))
    if Vtables.get("function_rva"):
        FuncRvas.add(int(Vtables["function_rva"], 16))

    TypeObjs = {"struct": [], "class": [], "enum": [], "func": [], "other": []}

    for Rva, Cnt in VtHist.items():
        if Rva in StructRvas:
            StructCount += Cnt
            TypeObjs["struct"].extend(ObjByVt[Rva])
        elif Rva in ClassRvas:
            ClassCount += Cnt
            TypeObjs["class"].extend(ObjByVt[Rva])
        elif Rva in EnumRvas:
            EnumCount += Cnt
            TypeObjs["enum"].extend(ObjByVt[Rva])
        elif Rva in FuncRvas:
            FuncCount += Cnt
            TypeObjs["func"].extend(ObjByVt[Rva])
        else:
            OtherCount += Cnt

    print(f"\n[vtable] Classification:")
    print(f"  Structs:   {StructCount}")
    print(f"  Classes:   {ClassCount}")
    print(f"  Enums:     {EnumCount}")
    print(f"  Functions: {FuncCount}")
    print(f"  Other:     {OtherCount}")
    print(f"  Total:     {sum(VtHist.values())}")

    TopVt = sorted(VtHist.items(), key=lambda x: -x[1])[:20]
    print(f"\n[vtable] Top 20 vtable RVAs:")
    for Rva, Cnt in TopVt:
        Tag = ""
        if Rva in StructRvas: Tag = " [Struct]"
        elif Rva in ClassRvas: Tag = " [Class]"
        elif Rva in EnumRvas: Tag = " [Enum]"
        elif Rva in FuncRvas: Tag = " [Function]"
        print(f"  0x{Rva:X}: {Cnt}{Tag}")

    return TypeObjs, VtHist


def AutoClassifyUnknownVtables(Reader, TypeObjs, VtHist, Vtables, Objects):
    StructRvas = set()
    ClassRvas = set()
    FuncRvas = set()

    if Vtables.get("script_struct_rva"):
        StructRvas.add(int(Vtables["script_struct_rva"], 16))
    if Vtables.get("asstruct_rva"):
        StructRvas.add(int(Vtables["asstruct_rva"], 16))
    if Vtables.get("class_native_rva"):
        ClassRvas.add(int(Vtables["class_native_rva"], 16))
    if Vtables.get("asclass_rva"):
        ClassRvas.add(int(Vtables["asclass_rva"], 16))
    for K in ["bpgc_rva", "wbpgc_rva", "smbpgc_rva", "anim_bpgc_rva"]:
        if Vtables.get(K):
            ClassRvas.add(int(Vtables[K], 16))
    if Vtables.get("enum_rva"):
        pass
    if Vtables.get("function_rva"):
        FuncRvas.add(int(Vtables["function_rva"], 16))

    AllKnown = StructRvas | ClassRvas | FuncRvas
    if Vtables.get("enum_rva"):
        AllKnown.add(int(Vtables["enum_rva"], 16))
    if Vtables.get("package_rva"):
        AllKnown.add(int(Vtables["package_rva"], 16))

    TopVt = sorted(VtHist.items(), key=lambda x: -x[1])[:50]
    ObjByVt = defaultdict(list)
    for Obj in Objects:
        Vt = Reader.u64(Obj)
        if not Vt or not IsModuleVt(Vt):
            continue
        Rva = Vt - MODULE_BASE
        if Rva not in AllKnown and len(ObjByVt[Rva]) < 3:
            ObjByVt[Rva].append(Obj)

    NewStruct = 0
    NewClass = 0
    NewFunc = 0
    for Rva, Cnt in TopVt:
        if Rva in AllKnown or Cnt < 50:
            continue
        Samples = ObjByVt.get(Rva, [])
        if not Samples:
            continue
        Ci, _ = DecodeUObjectSlot(Reader, Samples[0])
        if Ci is None:
            continue
        Name = FNameResolve(Reader, Ci)
        if not Name:
            continue
        if Name.startswith("Default__ASStruct"):
            for Obj in Objects:
                Vt2 = Reader.u64(Obj)
                if Vt2 and (Vt2 - MODULE_BASE) == Rva:
                    TypeObjs["struct"].append(Obj)
                    NewStruct += 1
            AllKnown.add(Rva)
            print(f"[auto] 0x{Rva:X} -> ASStruct ({Cnt} objs, CDO={Name})")
        elif Name.startswith("Default__ASClass"):
            for Obj in Objects:
                Vt2 = Reader.u64(Obj)
                if Vt2 and (Vt2 - MODULE_BASE) == Rva:
                    TypeObjs["class"].append(Obj)
                    NewClass += 1
            AllKnown.add(Rva)
            print(f"[auto] 0x{Rva:X} -> ASClass ({Cnt} objs, CDO={Name})")
        elif "Function" in Name or Name.startswith("Default__ASFunction"):
            for Obj in Objects:
                Vt2 = Reader.u64(Obj)
                if Vt2 and (Vt2 - MODULE_BASE) == Rva:
                    TypeObjs["func"].append(Obj)
                    NewFunc += 1
            AllKnown.add(Rva)
            print(f"[auto] 0x{Rva:X} -> ASFunction ({Cnt} objs, CDO={Name})")
        else:
            print(f"[auto] 0x{Rva:X} unknown ({Cnt} objs, CDO={Name})")

    if NewStruct or NewClass or NewFunc:
        print(f"[auto] classified: +{NewStruct} struct, +{NewClass} class, +{NewFunc} func")


def CountProperties(Reader, TypeObjs):
    TotalProps = 0
    TotalFuncs = 0
    TypePropsCount = {"struct": 0, "class": 0, "enum": 0}

    AllTypeObjs = []
    for Kind in ["struct", "class"]:
        Seen = set()
        for Obj in TypeObjs[Kind]:
            if Obj in Seen:
                continue
            Seen.add(Obj)
            AllTypeObjs.append((Kind, Obj))

    print(f"\n[props] Walking ChildProperties for {len(AllTypeObjs)} type objects...")

    for Kind, Obj in AllTypeObjs:
        ChildPtr = Reader.u64(Obj + OFFSET_CHILD_PROPERTIES)
        if not ChildPtr or not IsHeap(ChildPtr):
            continue

        PropCount = 0
        Cur = ChildPtr
        Visited = set()
        while Cur and IsHeap(Cur) and Cur not in Visited and PropCount < 500:
            Visited.add(Cur)
            PropCount += 1
            Next = Reader.u64(Cur + OFFSET_FFIELD_NEXT)
            Cur = Next

        TotalProps += PropCount
        TypePropsCount[Kind] = TypePropsCount.get(Kind, 0) + PropCount

    StructObjs = len(set(TypeObjs["struct"]))
    ClassObjs = len(set(TypeObjs["class"]))
    EnumObjs = len(set(TypeObjs["enum"]))
    FuncObjs = len(set(TypeObjs["func"]))

    ChildFuncs = 0
    for Kind in ["struct", "class"]:
        Seen = set()
        for Obj in TypeObjs[Kind]:
            if Obj in Seen:
                continue
            Seen.add(Obj)
            ChildrenPtr = Reader.u64(Obj + OFFSET_CHILD_PROPERTIES - 0x28)
            if ChildrenPtr and IsHeap(ChildrenPtr):
                Cur = ChildrenPtr
                ChVisited = set()
                while Cur and IsHeap(Cur) and Cur not in ChVisited:
                    ChVisited.add(Cur)
                    ChildFuncs += 1
                    Next = Reader.u64(Cur + 0x48)
                    Cur = Next

    print(f"\n{'='*50}")
    print(f"  Classes:    {ClassObjs}")
    print(f"  Structs:    {StructObjs}")
    print(f"  Enums:      {EnumObjs}")
    print(f"  Functions:  {FuncObjs} (vtable-classified)")
    print(f"  Properties: {TotalProps}")
    print(f"{'='*50}")


def TestFName(Reader, Ci):
    Name = FNameResolve(Reader, Ci)
    if Name:
        print(f"CI {Ci} (0x{Ci:X}) -> \"{Name}\"")
    else:
        print(f"CI {Ci} (0x{Ci:X}) -> FAILED")


def ProbeNumElements(Reader):
    GobjAbs = MODULE_BASE + RVA_GOBJECT_ARRAY
    print(f"[probe] GUObjectArray @ 0x{GobjAbs:X}")
    Candidates = []
    for Off in [0x08, 0x10, 0x14, 0x18, 0x20, 0x28, 0x30, 0x38,
                0x44, 0x48, 0x50, 0x54, 0x58, 0x5C, 0x60, 0x64,
                0x68, 0x70, 0x78, 0x80, 0xFC, 0x100]:
        V = Reader.u32(GobjAbs + Off)
        if V is not None and 1000 <= V <= 2_000_000:
            Candidates.append((Off, V))
            print(f"  +0x{Off:02X} = {V:>10d} (0x{V:08X})")
    if Candidates:
        Best = max(Candidates, key=lambda x: x[1])
        print(f"[probe] largest: +0x{Best[0]:02X} = {Best[1]}")
    else:
        print("[probe] no plausible NumElements found")


def LoadConfig():
    CfgPath = os.path.join(os.path.dirname(os.path.dirname(__file__)), "decrypt_export.json")
    if not os.path.exists(CfgPath):
        CfgPath = "decrypt_export.json"
    try:
        with open(CfgPath) as F:
            return json.load(F)
    except:
        return {}


def FindPid():
    for Entry in os.listdir("/proc"):
        if not Entry.isdigit():
            continue
        Pid = int(Entry)
        try:
            with open(f"/proc/{Pid}/comm") as F:
                Comm = F.read().strip()
        except:
            continue
        if "GameThread" not in Comm:
            continue
        try:
            with open(f"/proc/{Pid}/cmdline", "rb") as F:
                Cmdline = F.read()
        except:
            continue
        if b"CrashReportClient" in Cmdline:
            continue
        return Pid
    return 0


def Main():
    Parser = argparse.ArgumentParser(description="Python SDK dump test harness")
    Parser.add_argument("pid", nargs="?", type=int, default=0, help="Game PID (auto-detect if 0)")
    Parser.add_argument("--fname", type=str, help="Test FName for CompIndex (hex or decimal)")
    Parser.add_argument("--probe", action="store_true", help="Only probe NumElements")
    Parser.add_argument("--vtables", action="store_true", help="Only classify by vtable")
    Parser.add_argument("--slot", type=str, help="Test UObject slot decode for address (hex)")
    Parser.add_argument("--field-name", type=str, help="Test FField NamePrivate decode for address (hex)")
    Parser.add_argument("--chunk-array", type=str, help="Override chunk_array address (hex)")
    Args = Parser.parse_args()

    Pid = Args.pid
    if Pid == 0:
        Pid = FindPid()
        if Pid == 0:
            print("Game process not found")
            sys.exit(1)
    print(f"[+] PID: {Pid}")

    Reader = MemReader(Pid)
    TestRead = Reader.u64(MODULE_BASE)
    if TestRead is None:
        print("[-] Cannot read MODULE_BASE — game not accessible")
        sys.exit(1)
    print(f"[+] MODULE_BASE readable (first 8B: 0x{TestRead:X})")

    Config = LoadConfig()
    Vtables = Config.get("autodiscovery", {}).get("vtables", {})

    LoadKeyTable(Reader)

    if Args.fname:
        Ci = int(Args.fname, 16) if Args.fname.startswith("0x") else int(Args.fname)
        TestFName(Reader, Ci)
        return

    if Args.slot:
        Addr = int(Args.slot, 16)
        Ci, Num = DecodeUObjectSlot(Reader, Addr)
        if Ci is not None:
            print(f"CI={Ci} (0x{Ci:X}), Number={Num}")
            Name = FNameResolve(Reader, Ci)
            if Name:
                print(f"Name: \"{Name}\"")
        else:
            print("Slot decode failed — dumping all 4 slots:")
            for Si in range(4):
                SlotAddr = Addr + 0x20 + Si * 0x20
                Enc = Reader.read(SlotAddr, 16)
                if Enc and len(Enc) >= 16:
                    Lo = struct.unpack_from("<Q", Enc, 0)[0]
                    Hi = struct.unpack_from("<Q", Enc, 8)[0]
                    Ci2, Num2 = DecodeUObjectSlot128(Enc)
                    print(f"  slot[{Si}] @+0x{0x20+Si*0x20:X}: lo=0x{Lo:016X} hi=0x{Hi:016X} -> CI=0x{Ci2:X} Num={Num2}")
        return

    if Args.field_name:
        Addr = int(Args.field_name, 16)
        Ci = DecodeFFieldName(Reader, Addr)
        if Ci is not None:
            print(f"FField CI={Ci} (0x{Ci:X})")
            Name = FNameResolve(Reader, Ci)
            if Name:
                print(f"Name: \"{Name}\"")
        else:
            print("FField NamePrivate decode failed")
        return

    if Args.probe:
        ProbeNumElements(Reader)
        return

    GobjAbs = MODULE_BASE + RVA_GOBJECT_ARRAY
    print(f"\n[gobj] GUObjectArray @ 0x{GobjAbs:X}")

    ProbeNumElements(Reader)

    ChunkArr = None
    if Args.chunk_array:
        ChunkArr = int(Args.chunk_array, 16)
        print(f"[py] chunk_array=0x{ChunkArr:X} (CLI override)")
    else:
        ChunksMgr, MgrOff = DecryptChunksManager(Reader, GobjAbs)
        if ChunksMgr:
            ChunkArr = FindChunkArray(Reader, ChunksMgr)
        if not ChunkArr:
            ChunkArr = ProbeChunkArrayDirect(Reader, GobjAbs)

    if not ChunkArr:
        print("[-] Cannot find chunk_array — aborting")
        sys.exit(1)

    Objects = WalkChunks(Reader, ChunkArr)
    if not Objects:
        print("[-] No objects found")
        sys.exit(1)

    print(f"\n[names] Testing FName resolution on first 10 objects...")
    NameSucc = 0
    NameFail = 0
    for Obj in Objects[:50]:
        Ci, _ = DecodeUObjectSlot(Reader, Obj)
        if Ci is None:
            NameFail += 1
            continue
        Name = FNameResolve(Reader, Ci)
        if Name and len(Name) > 0 and Name[0].isalpha():
            NameSucc += 1
            if NameSucc <= 10:
                print(f"  0x{Obj:X} CI={Ci} -> \"{Name}\"")
        else:
            NameFail += 1
    print(f"[names] {NameSucc} success, {NameFail} fail out of 50 samples")

    if NameSucc < 5:
        print("[-] FName resolution mostly failing — check constants")
        print("    Trying alternate KeyTable offsets...")
        for KtOff in [0xE8, 0xF0, 0xE0, 0x100]:
            global KeyTable
            Addr = MODULE_BASE + RVA_SIMD_BLOCK + KtOff
            D = Reader.read(Addr, 128)
            if D:
                Kt = [struct.unpack_from("<H", D, i*2)[0] for i in range(64)]
                Nz = sum(1 for V in Kt if V != 0)
                if Nz > 10:
                    print(f"    SimdBlock+0x{KtOff:X}: {Nz}/64 non-zero")
                    KeyTable = Kt
                    TestCi, _ = DecodeUObjectSlot(Reader, Objects[0])
                    if TestCi:
                        TestName = FNameResolve(Reader, TestCi)
                        if TestName:
                            print(f"    -> \"{TestName}\" (works!)")
                            break

    TypeObjs, VtHist = ClassifyByVtable(Reader, Objects, Vtables)

    if not Args.vtables:
        AutoClassifyUnknownVtables(Reader, TypeObjs, VtHist, Vtables, Objects)
        CountProperties(Reader, TypeObjs)


if __name__ == "__main__":
    Main()
