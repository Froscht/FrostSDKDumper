import json
import struct
import subprocess
import sys

PID = 23750
KEY_OFFSET_XOR = 0xCCCCACBB

OFF_VTABLE      = 0x00
OFF_VTABLE2     = 0x08
OFF_NAMEPRIVATE = 0x30
OFF_PROPFLAGS   = 0x40
OFF_NEXT        = 0x48
OFF_CLASSPRIV   = 0x50
OFF_OWNER       = 0x58
OFF_ARRAYDIM    = 0x78
OFF_ELEMSIZE    = 0x7C
OFF_OFFSET_BOOL = 0x88
OFF_OFFSET_PROP = 0x8C
FFIELD_SIZE     = 0x100

def McpRead(Address, Size):
    Cmd = [
        "claude-mcp-cli", "memory-reader", "read_memory",
        "--pid", str(PID), "--address", hex(Address), "--size", str(Size)
    ]
    Result = subprocess.run(Cmd, capture_output=True, text=True)
    return bytes.fromhex(json.loads(Result.stdout)["bytes_hex"])

def DecodeOffset(Stored):
    return struct.unpack("<I", struct.pack(">I", Stored ^ KEY_OFFSET_XOR))[0]

def DumpFField(Data):
    Vt   = struct.unpack_from("<Q", Data, OFF_VTABLE)[0]
    Vt2  = struct.unpack_from("<Q", Data, OFF_VTABLE2)[0]
    NpLo = struct.unpack_from("<Q", Data, OFF_NAMEPRIVATE)[0]
    NpHi = struct.unpack_from("<Q", Data, OFF_NAMEPRIVATE + 8)[0]
    Pf   = struct.unpack_from("<Q", Data, OFF_PROPFLAGS)[0]
    Nx   = struct.unpack_from("<Q", Data, OFF_NEXT)[0]
    Cp   = struct.unpack_from("<Q", Data, OFF_CLASSPRIV)[0]
    Ow   = struct.unpack_from("<Q", Data, OFF_OWNER)[0]
    Ad   = struct.unpack_from("<I", Data, OFF_ARRAYDIM)[0]
    Es   = struct.unpack_from("<I", Data, OFF_ELEMSIZE)[0]
    OffB = struct.unpack_from("<I", Data, OFF_OFFSET_BOOL)[0]
    OffP = struct.unpack_from("<I", Data, OFF_OFFSET_PROP)[0]
    print(f"  vtable        +0x00 = 0x{Vt:016X}")
    print(f"  vtable2       +0x08 = 0x{Vt2:016X}")
    print(f"  NamePrivate   +0x30 = 0x{NpLo:016X} 0x{NpHi:016X}")
    print(f"  PropertyFlags +0x40 = 0x{Pf:016X}")
    print(f"  Next          +0x48 = 0x{Nx:016X}")
    print(f"  ClassPrivate  +0x50 = 0x{Cp:016X}")
    print(f"  Owner         +0x58 = 0x{Ow:016X} (raw={Ow & ~1:X}, tag={Ow & 1})")
    print(f"  ArrayDim      +0x78 = {Ad}")
    print(f"  ElementSize   +0x7C = {Es}")
    print(f"  Offset@+0x88  bool  = stored 0x{OffB:08X} -> {DecodeOffset(OffB):#x}")
    print(f"  Offset@+0x8C  other = stored 0x{OffP:08X} -> {DecodeOffset(OffP):#x}")
    return Nx

def Main():
    PostProcessAddr = 0x88211560
    print(f"=== UScriptStruct PostProcessSettings @ 0x{PostProcessAddr:X} ===")
    print(f"ChildProperties at +0x100 -> follow Next chain at FField+0x48")

if __name__ == "__main__":
    Main()
