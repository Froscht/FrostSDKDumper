#!/usr/bin/env python3
"""
usmap_dump.py - Parse UE5 .usmap (Unversioned Property Mappings) files.

Format reference: https://github.com/CUE4Parse/CUE4Parse (Mappings/UsmapParser)
                  https://github.com/FabianFG/CUE4Parse

Header (v3):
    u16 magic         = 0x30C4
    u8  version       (Initial=0, PackageVersioning=1, LongFName=2, LargeEnums=3)
    u8  bHasVersioning (v>=PackageVersioning)
        if bHasVersioning:
            i32 fileVersionUE4
            i32 fileVersionUE5
            u32 customVersionsCount
            customVersionsCount * (FGuid(16) + i32)
            u32 netCL
    u8  compression   (None=0, Oodle=1, Brotli=2, ZStandard=3)
    u32 compSize
    u32 decompSize

Body (after decompression):
    u32 nameCount
    for nameCount:
        if version>=LongFName: u16 nameLen ; else u8 nameLen
        utf8 bytes
    u32 enumCount
    for enumCount:
        i32 nameIdx
        u8/u16 numEntries (LargeEnums => u16 else u8)
        for numEntries: i32 nameIdx
    u32 structCount
    for structCount:
        i32 nameIdx
        i32 superIdx
        u16 propCount         (total properties UE knows about, sparse)
        u16 serializableCount (number of EPropertyMapping records that follow)
        for serializableCount:
            u16 schemaIdx     (slot index inside the struct, NOT byte offset)
            u8  arrayDim
            i32 nameIdx
            EPropertyType (recursive - see _read_property)

NOTE: usmap does NOT contain raw byte offsets. It contains the *property order*
inside the reflected struct (schemaIdx) plus property type info. Real offsets
must still be derived at runtime from sizeof(prev) + alignment, OR by walking
UProperty->Offset_Internal in memory. usmap is the 'shape & names' oracle, not
the 'offsets' oracle.
"""

import struct
import sys
from pathlib import Path

USMAP_PATH = "/home/frost/Downloads/5.3.1169740+pioneer_1.26.x-PioneerGame_[unknowncheats.me]_/Mappings/5.3.2-1169740+pioneer_1.26.x-PioneerGame.usmap"

# usmap version constants
V_INITIAL = 0
V_PACKAGE_VERSIONING = 1
V_LONG_FNAME = 2
V_LARGE_ENUMS = 3

# EPropertyType (matches CUE4Parse Mappings/Types/EPropertyType.cs ordering)
PROP_TYPES = [
    "ByteProperty", "BoolProperty", "IntProperty", "FloatProperty", "ObjectProperty",
    "NameProperty", "DelegateProperty", "DoubleProperty", "ArrayProperty", "StructProperty",
    "StrProperty", "TextProperty", "InterfaceProperty", "MulticastDelegateProperty",
    "WeakObjectProperty", "LazyObjectProperty", "AssetObjectProperty", "SoftObjectProperty",
    "UInt64Property", "UInt32Property", "UInt16Property", "Int64Property", "Int16Property",
    "Int8Property", "MapProperty", "SetProperty", "EnumProperty", "FieldPathProperty",
    "OptionalProperty", "Utf8StrProperty", "AnsiStrProperty", "Unknown",
]


class Reader:
    def __init__(self, data):
        self.d = data
        self.p = 0

    def u8(self):
        v = self.d[self.p]
        self.p += 1
        return v

    def u16(self):
        v = struct.unpack_from('<H', self.d, self.p)[0]
        self.p += 2
        return v

    def i32(self):
        v = struct.unpack_from('<i', self.d, self.p)[0]
        self.p += 4
        return v

    def u32(self):
        v = struct.unpack_from('<I', self.d, self.p)[0]
        self.p += 4
        return v

    def i64(self):
        v = struct.unpack_from('<q', self.d, self.p)[0]
        self.p += 8
        return v


def read_property(r, version):
    """Recursively read EPropertyType. Returns dict describing the type."""
    t = r.u8()
    if t >= len(PROP_TYPES):
        return {"type": f"Invalid({t})"}
    name = PROP_TYPES[t]
    out = {"type": name}
    if name == "EnumProperty":
        out["inner"] = read_property(r, version)
        out["enum"] = r.i32()
    elif name == "StructProperty":
        out["struct"] = r.i32()
    elif name == "SetProperty" or name == "ArrayProperty" or name == "OptionalProperty":
        out["inner"] = read_property(r, version)
    elif name == "MapProperty":
        out["key"] = read_property(r, version)
        out["value"] = read_property(r, version)
    # ByteProperty in usmap is just a u8; no enum index follows
    return out


def parse_usmap(path):
    raw = Path(path).read_bytes()
    print(f"file size: {len(raw)} bytes")

    magic = struct.unpack_from('<H', raw, 0)[0]
    version = raw[2]
    print(f"magic=0x{magic:04X} version={version}")
    if magic != 0x30C4:
        raise ValueError("not a usmap")

    has_versioning = raw[3]
    compression = raw[4]
    # Pioneer build uses a fixed 16-byte header even with versioning=0:
    #   [0..1] magic   [2] version   [3] hasVersioning   [4] compression
    #   [5..7] reserved/padding   [8..11] compSize   [12..15] decompSize
    comp_size = struct.unpack_from('<I', raw, 8)[0]
    decomp_size = struct.unpack_from('<I', raw, 12)[0]
    comp_names = {0: "None", 1: "Oodle", 2: "Brotli", 3: "ZStandard"}
    print(f"hasVersioning={has_versioning} "
          f"compression={comp_names.get(compression, compression)} "
          f"compSize={comp_size} decompSize={decomp_size}")

    body = raw[16:16 + comp_size] if comp_size else raw[16:]
    if compression == 0:
        body_dec = body
    elif compression == 1:
        raise RuntimeError("Oodle compression - proprietary, install oodle SDK or pre-decompress")
    elif compression == 3:
        import zstandard as zstd
        body_dec = zstd.ZstdDecompressor().decompress(body)
    elif compression == 2:
        import brotli
        body_dec = brotli.decompress(body)
    else:
        raise RuntimeError(f"unknown compression {compression}")

    if len(body_dec) != decomp_size:
        print(f"WARNING: decompressed {len(body_dec)} != expected {decomp_size}")

    rb = Reader(body_dec)
    name_count = rb.u32()
    names = []
    for _ in range(name_count):
        if version >= V_LONG_FNAME:
            ln = rb.u16()
        else:
            ln = rb.u8()
        names.append(body_dec[rb.p:rb.p + ln].decode('utf-8', errors='replace'))
        rb.p += ln
    print(f"names: {len(names)} (e.g. {names[:5]})")

    enum_count = rb.u32()
    enums = []
    for _ in range(enum_count):
        ni = rb.i32()
        if version >= V_LARGE_ENUMS:
            ec = rb.u16()
        else:
            ec = rb.u8()
        members = [rb.i32() for _ in range(ec)]
        enums.append((ni, members))
    print(f"enums: {len(enums)}")

    struct_count = rb.u32()
    print(f"struct_count={struct_count} pos={rb.p}")
    structs = []
    for sidx in range(struct_count):
        try:
            ni = rb.i32()
            si = rb.i32()
            prop_count = rb.u16()
            ser_count = rb.u16()
            props = []
            for _ in range(ser_count):
                schema_idx = rb.u16()
                array_dim = rb.u8()
                pn = rb.i32()
                ptype = read_property(rb, version)
                props.append((schema_idx, array_dim, pn, ptype))
            structs.append({
                "name_idx": ni, "super_idx": si,
                "prop_count": prop_count, "ser_count": ser_count,
                "props": props,
            })
        except Exception as e:
            sname = names[ni] if 0 <= ni < len(names) else "?"
            print(f"struct[{sidx}] '{sname}' failed at pos {rb.p}: {e}")
            break
    print(f"structs: {len(structs)}")
    print(f"body bytes consumed: {rb.p}/{len(body_dec)}")

    return names, enums, structs


def fmt_type(t, names):
    n = t["type"]
    if n == "StructProperty":
        return f"struct<{names[t['struct']] if t['struct']>=0 else '?'}>"
    if n == "EnumProperty":
        return f"enum<{names[t['enum']] if t['enum']>=0 else '?'}>({fmt_type(t['inner'],names)})"
    if n == "ByteProperty":
        return "byte"
    if n in ("ArrayProperty", "SetProperty", "OptionalProperty"):
        return f"{n[:-8].lower()}<{fmt_type(t['inner'],names)}>"
    if n == "MapProperty":
        return f"map<{fmt_type(t['key'],names)},{fmt_type(t['value'],names)}>"
    return n.replace("Property", "")


def dump_examples(names, structs, wanted=("PlayerState", "Pawn", "Character",
                                          "PlayerController", "Actor")):
    print("\n=== example class layouts ===")
    by_name = {names[s["name_idx"]]: s for s in structs if s["name_idx"] >= 0}
    found = 0
    for cn in wanted:
        s = by_name.get(cn)
        if not s:
            print(f"[miss] {cn}")
            continue
        super_name = names[s["super_idx"]] if s["super_idx"] >= 0 else "<root>"
        print(f"\n-- {cn} : {super_name}  "
              f"(propCount={s['prop_count']} serializable={s['ser_count']})")
        # Sort by schemaIdx so order matches reflection layout
        sorted_props = sorted(s["props"], key=lambda x: x[0])
        for schema_idx, arr_dim, name_idx, ptype in sorted_props[:8]:
            pname = names[name_idx] if name_idx >= 0 else "?"
            print(f"   slot[{schema_idx:3}] dim={arr_dim} "
                  f"{pname:32}  {fmt_type(ptype, names)}")
        found += 1
        if found >= 5:
            break


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else USMAP_PATH
    names, enums, structs = parse_usmap(path)
    dump_examples(names, structs)
