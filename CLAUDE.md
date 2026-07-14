# FrostSDKDumper — Consolidated Reference

## Project Overview
External SDK dumper for ARC Raiders (Unreal Engine 5, Theia-obfuscated). Reads game memory via `/dev/memreader` kernel module (or `process_vm_readv` fallback). Outputs `SDK_Output.txt` + per-class `.hpp` files. Runs on Linux against Wine-hosted game process.

Build: `g++ -std=c++17 -O2 -march=native -mavx2 -msse4.1 -I KernelDriver/include -o FrostDumper main.cpp build/Zydis.o -lcapstone -lunicorn -lm`
Run: `sudo ./build_and_run.sh [PID]`

## Current Patch: CL-1315578 (2026-07-09)
Live-verified 2026-07-14 against PID 8082. Image size 0x117E1000.
UObject slot decode: ROL64(29) → PSHUFLW(0x39) → ROL32(5) → lo64, CI in hi32.
FField NamePrivate: XOR(0x8FFAB191C340B792) → ROL16(12) → PSHUFB([07,06,04,05,02,03,00,01]) → ROL64(32).
PropertyOffsetXor: 0xA271DBC5. Field offsets shifted +0x50 from CL-1299607.
FName shard hash uses `-109*T+82` slot-select formula (NOT `H^(H>>16)` like CL-1299607).

SDK stats (2026-07-14): 27602 classes, 14450 structs, 2930 enums, 40124 functions, 286137 properties (285140 named), 0% FProperty_Unknown.

Previous patch (CL-1299607, 2026-07-07): FField NamePrivate: PSHUFB→XOR→ROL64. Shard hash: -109*T+166 slot-select. PropertyOffsetXor: 0x057F15E5.

Previous patch (CL-1233465, 2026-06-18): 0% FProperty_Unknown, 283196 properties, 9138 classes.

### CL-1233465 Theia Limitations
- UScriptStruct::ChildProperties stripped → struct field listings impossible
- UEnum::Names TArray stripped → enum value listings impossible
- UObject name slots zeroed for UScriptStruct/UEnum → FField-style name at +0x88/+0x90 used instead
- All FProperty subclasses share the same vtable → FFieldClass-only or structural probing for type detection
- FFieldClass hardcoded map (CL-1201801 addresses) disabled — wrong addresses on CL-1233465
- ProbePropertyTypeStructural() is the PRIMARY type detector (sub-pointers + elem_size + bool fields)

Previous patch (CL-1201801): 99.85% naming, ~298K properties, 33200 classes, 11194 structs, 2881 enums, 55106 functions.

## Architecture

### Files
| File | Purpose |
|------|---------|
| `main.cpp` | Entry point, orchestrates phases 1-8, SDK output |
| `auto_discovery.h` | AOB sig-scan for all runtime constants (no hardcoded RVAs) |
| `auto_chunks_emu.h` | Unicorn-emulated chunks_manager vtable decrypt |
| `arc_decrypt.h` | Compile-time fallback constants, struct offset definitions |
| `fname_decrypt.h` | FName/FField name resolution pipeline |
| `gobjects.h` | GUObjectArray walk, chunk table, seed objects |
| `sdk_generator.h` | SDK file generation, property type table, enum bodies |
| `auto_offsets.h` | FField/FProperty sub-pointer offset auto-probing |
| `sig_scan.h` / `sig_scan_v2.h` | AOB pattern scanner (page-aware, VMP-tolerant) |
| `emu_fname.h` | Unicorn-based FName emulation (EMU mode, slower fallback) |

### Discovery Phases (auto_discovery.h)
0. Module bounds (PE header parse)
1. Engine vtable discovery (score-density clustering of GObjectArray seed objects)
   - 1.5: Dedup + anchor-based correction
   - 1.6: ScriptStruct oracle validation (main.cpp)
2. FField NamePrivate XOR key extraction
3. FProperty Offset_Internal XOR key + bswap extraction
4. UObject slot decrypt params (PSHUFB mask + PXOR constant + ROL64 amount)
5. FName function RVA (via xor+bswap caller-frame anchor)
6. GNamePool base (call-chain .data LEA walk from FName fn)
7. FName keystream table (clustered .rdata loads in FName call chain)
8. FFieldClass globals (5-arg constructor pattern)

### What Auto-Discovers vs. Hardcoded
**Auto-discovers (survives patches zero-touch):**
- PE binary base, module bounds
- 6+ RVAs via sig-scan
- FName decrypt entry function
- FName XOR/ROL constants (extracted from function body)
- FProperty Offset XOR key
- UObject slot decrypt SIMD params
- GNamePool base + keystream table
- Engine vtable RVAs (UClass, UScriptStruct, UFunction, UEnum, UPackage, BPGC)
- chunks_manager via Unicorn emulation of vtable[7]

**Auto-discovers (Phase 2c/2d, new):**
- FField layout: NamePrivate, Next, ChildProperties offsets + decrypt constants (XOR, PSHUFB, ROL16, ROL64)
- FProperty layout: Offset_Internal, ElementSize, ArrayDim offsets + XOR key

**Hardcoded fallbacks (arc_decrypt.h, manual update if drift):**
- UStruct/FField::Owner/ClassPrivate offsets (not yet auto-discovered)
- FName entry header bitmasks (HDR_LENGTH_SHIFT, HDR_IS_WIDE_BIT)
- SHARD_HASH_ADD, FNV_ADD, BLOCK_FNV_XOR, block ROL/PSHUFLW constants
- FField NamePrivate decode (now auto-discovered by Phase 2c — fallback still exists)
- GUObjectArray NumElements offset (+0x5C on CL-1315578)

## Key Constants (CL-1315578 / v20260709)

### Decrypt Constants
| Constant | Value | Used For |
|----------|-------|----------|
| UOBJ_SLOT_ROL64_FIRST | 29 | UObject slot ROL64 (first step) |
| UOBJ_SLOT_PSHUFLW | 0x39 | UObject slot PSHUFLW (second step) |
| UOBJ_SLOT_ROL32_PER | 5 | UObject slot ROL32 (per-dword, third step) |
| SLOT_HASH_ADD | 0xF3D8DA36 | FNV32 slot selector hash seed |
| SHARD_HASH_ADD | 0xD5AF8E52 | FNamePool shard hash |
| SHARD_HASH_ROL_A | 17 | Shard hash ROL step A |
| SHARD_HASH_ROL_B | 13 | Shard hash ROL step B |
| BLOCK_ROL64 | 13 | Block decrypt ROL64 |
| BLOCK_PSHUFLW | 0x93 | Block decrypt PSHUFLW |
| BLOCK_FNV_XOR | 0x19EA7DF486E7194E | Block decrypt XOR (loaded from RVA 0xB523C50) |
| FNV_ADD | 0x10F3A73711CE0312 | FName entry FNV hash offset |
| FNV_ROL1 | 37 | FNV fold ROL64 step 1 |
| FNV_ROL2 | 40 | FNV fold ROL64 step 2 |
| FNAME_PTR_XOR1 | 0x14329DBF | bswap64(RawPtr ^ XOR1) |
| FNAME_PTR_XOR2 | 0x2E3400000000 | Step1 ^ XOR2 |
| FNAME_PTR_XOR3 | 0xBF9D1C2000000000 | bswap64(Step2 ^ XOR3) = EntryPtr |
| FFIELD_NAME_XOR_KEY | 0x8FFAB191C340B792 | FField NamePrivate XOR |
| FFIELD_NAME_PSHUFB | [07,06,04,05,02,03,00,01] | FField NamePrivate PSHUFB mask |
| FFIELD_NAME_ROL16 | 12 | FField NamePrivate ROL16 (new step) |
| FFIELD_NAME_ROL64 | 32 | FField NamePrivate final ROL64 |
| PropertyOffsetXor | 0xA271DBC5 | bswap32(stored ^ key) = real offset |
| HDR_LENGTH_SHIFT | 6 | FNameEntry header >> 6 = length |
| HDR_IS_WIDE_BIT | 0x20 | FNameEntry wide-string flag |

### CL-1299607 Constants (previous patch, for reference)
| Constant | Value |
|----------|-------|
| UOBJ_SLOT_XOR_64 | 0x9A492C85DDF6F193 |
| SHARD_HASH_ADD | 0x282106A6 |
| FNV_ADD | 0xEB1E82D44384D6E6 |
| FFIELD_NAME_PSHUFB | [01,03,00,02,05,04,06,07] |
| FFIELD_NAME_XOR_KEY | 0x2BC795817F5A4D23 |
| PropertyOffsetXor | 0x057F15E5 |

### CL-1233465 Constants (previous patch, for reference)
| Constant | Value |
|----------|-------|
| UOBJ_SLOT_XOR_64 | 0x5EA772D07F910744 (PSHUFB+XOR+ROL64(32)) |
| SLOT_HASH_ADD | 0x5619A446 |
| SHARD_HASH_ADD | 0x4A3617A2 |
| FFIELD_NAME_SHUF | 0x1E (PSHUFLW+XOR+ROL16+ROL64) |
| PropertyOffsetXor | 0xEAABEC11 |

### UObject Slot Decode Pipeline (CL-1299607)
```
ROL32(13) → lo64 → XOR(0x9A492C85DDF6F193) → ROL64(7)
Result: lo32 = CompIndex, hi32 = FName::Number
(Equivalently: ROL64(39) then CI = hi32. 39-7=32 swaps halves.)
Slot selector: FNV32(prime=0x01000193, add=0x5A5A703F)
  p = obj + 0x10; Lo = lo32(p), Hi = hi32(p)
  H = ROL32(Lo, 25) * P + ADD
  H = ROL32(H, 15) * P + Hi + ADD
  H = ROL32(H, 25) * P + ADD
  H = ROL32(H, 15) * P + ADD
  idx = (H ^ (H>>16)) & 3 ^ 2
Base: obj + 0x20, stride 0x20 (4 slots)
```

### CL-1315578 FName Pipeline (live-verified 2026-07-14)
```
CI → chunk: identity (SIMD pipeline cancels algebraically — confirmed for CL-1315578)
  NameOff = CI & 0xFFFF, ChunkOff = (CI >> 8) & 0xFFFF00
  ChunkAddr = GNamePool(0xE4F2A00) + ChunkOff

Shard Hash (FNV32, 3-step + slot-select):
  SeedAddr = ChunkAddr + 0x2F90
  Lo = lo32(SeedAddr), Hi = hi32(SeedAddr)
  H = P * ROL32(Lo, 17) + 0xD5AF8E52
  H = P * ROL32(H, 13) + Hi + 0xD5AF8E52
  H = P * ROL32(H, 17) + 0xD5AF8E52
  T = ROL32(H, 13)
  Pa = (uint8)(-109*T + 82)
  Pb = (uint8)((P*T + 0xD5AF8E52) >> 16)
  Bidx1 = (Pa ^ Pb) & 7, Bidx2 = (Bidx1 + 1) & 7

Block Decode (8 blocks at ChunkAddr + 0x2FA0, stride 32):
  Block = PSHUFLW(ROL64(raw, 13), 0x93) ^ 0x19EA7DF486E7194E (FnvXor from RVA 0xB523C50)
  V13 = DecBlock(Block1), V15 = DecBlock(Block2)

FNV64 Chain:
  Fv1 = 0x100000001B3 * ROL64(V13, 37) + 0x10F3A73711CE0312
  Fv2 = 0x100000001B3 * ROL64(Fv1, 40) + 0x10F3A73711CE0312
  RawPtr = V13 + (V15 ^ Fv2) + 2*NameOff

Pointer XOR Chain:
  Step1 = bswap64(RawPtr ^ 0x14329DBF)
  Step2 = Step1 ^ 0x2E3400000000
  EntryPtr = bswap64(Step2 ^ 0xBF9D1C2000000000)

String Header (16-bit):
  length = hdr >> 6
  isWide = (hdr & 0x20) != 0

String Decrypt:
  KeyTable: ushort[64] at RVA 0xE4318DC (offset +0xE8 from SIMD block)
  Key = length + 0xA7B4
  Narrow (paired): byte[2k] ^= (KeyTable[Key & 0x3F] >> 3)
    Idx2 = (Key * 0xFFFF584C + 0xF629) & 0x3D
    byte[2k+1] ^= (KeyTable[Idx2] >> 3)
    Key = Key * 0x6DDC5690 + 0x5EBF2255
```

### CL-1299607 FName Pipeline (for reference)
```
GNamePool @ 0xE4A3A00. SeedOff=0x6FD0. BlockOff=0x6FE0.
Shard hash: 3-step FNV32 with ROLs 24,19,24. T=H>>13. Slot: (-109*T+166) ^ ((P*T+ADD)>>16) & 7.
Block: ROL64(10), PSHUFLW(0x1B), XOR 0x1BC3B58FFB88504C.
FNV: ROL(51)+0xEB1E82D44384D6E6, ROL(39).
Header: length=(hdr>>12)|((hdr>>2)&0x3F8). Key=length+0xFFFF9D4E.
```

### GNamePool Static Resolve Pipeline (CL-1233465, sub_2404F0)
```
CI → V5 (identity, 4-step PSHUFLW+XOR cancels algebraically)
V5 → WordOff = V5 & 0xFFFF, BlockOff = (V5 >> 8) & 0xFFFF00
ChunkAddr = PoolBase + BlockOff

Shard Hash (FNV32, 3-step):
  SeedAddr = ChunkAddr + 3152 (0xC50)
  V8 = (16 << 32) | Lo32(SeedAddr)
  H = P * (V8 >> 5) + 0xD4CEBC36; H = ROL32(H, 18)
  H = P * H + Hi32(SeedAddr) + 0xD4CEBC36; H = ROL32(H, 27)
  H = P * H + 0xD4CEBC36; V9 = ROL32(H, 18)
  SlotIdx = ((-109*V9+54)&0xFF ^ (P*V9+ADD)>>16&0xFF) & 7

Block Decode (8 encrypted slots at ChunkAddr + 3168):
  Slot1: ROL64(raw, 39) → PSHUFB(mask) → XOR(0x685688CEFBD310FC)
  Slot2: ROL64(raw, 39) → XOR(B423800=0x88106856D3FCFBCE) → PSHUFB(mask)
  (PSHUFB mask = 02 06 03 01 00 04 07 05)

FNV64 Chain:
  Base = Slot1_dec ^ 0xE5C864C1A6B54C7F
  Fnv1 = 0x100000001B3 * ROL64(Base, 54) + 0x124CB31365185276
  Fnv2 = 0x100000001B3 * ROL64(Fnv1, 32) + 0x124CB31365185276
  EntryPtr = Base + (Fnv2 ^ Slot2_dec ^ 0xE5C864C1A6B54C7F) + 2*WordOff

String Decrypt (sub_234CE0):
  Header: length = (hdr >> 14) | ((hdr >> 4) & 0x3FC), wide = hdr & 0x20
  Narrow: paired key schedule, key_init = (length - 76) & 0xFF
    KV = key + 46; per pair: ks[(KV-46)&0x3F+96]>>3, ks[KV&0x3F+96]>>3; KV -= 36
  Wide: key_init = (length + 21172) & 0xFFFF; KV += 2012 per pair
  Keystream: uint16_t[160] at RVA 0xE2B57F4, decrypt entries at index +96
```

### FField NamePrivate Decode (CL-1315578)
```
XOR(0x8FFAB191C340B792) → ROL16(12) → PSHUFB([07,06,04,05,02,03,00,01]) → ROL64(32)
```

### FField/FProperty Layout (CL-1315578)
| Field | Offset | Notes |
|-------|--------|-------|
| FField::VTable | +0x00 | vtable pointer (ALL FProperty subclasses share one vtable!) |
| FField::Owner | +0x80 | Owner UStruct (tagged: bit0=1 if UObject) |
| FField::NamePrivate | +0xA0 | Encrypted FName CI |
| FField::SaltSentinel | +0xB0 | Session salt |
| FField::ClassPrivate | +0xB8 | FFieldClass pointer |
| FField::Next | +0x78 | Next FField in chain |
| FProperty::ElementSize | +0xD0 | int32 |
| FProperty::Offset_Internal | +0xE4 | bswap(real ^ 0xA271DBC5) |
| FProperty::ArrayDim | +0x110 | int32 |
| FStructProperty::Struct | +0x138 | UScriptStruct* |
| FObjectProperty::PropertyClass | +0x138 | UClass* |
| FEnumProperty::UnderlyingProp | +0x138 | FProperty* (numeric) |
| FEnumProperty::Enum | +0x140 | UEnum* |
| FMapProperty::KeyProp | +0x138 | FProperty* |
| FMapProperty::ValueProp | +0x140 | FProperty* |
| FBoolProperty::FieldSize | +0x138 | byte (1/2/4/8) |
| FBoolProperty::ByteOffset | +0x139 | byte index |
| FBoolProperty::ByteMask | +0x13A | 1-bit mask (0x01..0x80) |
| FBoolProperty::FieldMask | +0x13B | all-bools-in-byte mask |
| FArrayProperty::Inner | +0x138 | FProperty* |

### UStruct/UClass/UEnum Layout (CL-1315578)
| Field | Offset | Notes |
|-------|--------|-------|
| UStruct::SuperStruct | +0xB0 | UStruct* parent |
| UStruct::ChildProperties | +0xF0 | FField* head (auto-discovered from binary) |
| UStruct::PropertiesSize | +0xD0 | int32 total struct size |
| UFunction::NativeFunc | +0x150 | void* native function pointer |
| UEnum::Names | +0xB0 | TArray<TPair<FName,int64>> (stripped by Theia — always empty) |

### Property Type Detection (CL-1315578)
All FProperty subclasses share the same vtable on CL-1299607 (Theia virtualizes them).
Type detection uses ProbePropertyTypeStructural() which checks:
1. elem_size == 80 → MapProperty/SetProperty (check sub-FField at +0xE8/+0xF0)
2. Valid FField at +0xE8 with reasonable inner elem_size → ArrayProperty
3. elem_size == 40 → SoftObjectProperty/SoftClassProperty
4. Bool fields at +0xE8..+0xEB → BoolProperty (FieldSize, ByteMask pattern)
5. Valid UObject at +0xE8 AND +0xF0 → EnumProperty or ClassProperty
6. Valid UObject at +0xE8 only → StructProperty or ObjectProperty (disambiguated by vtable RVA)
7. elem_size fallback: 0→Bool, 1→Byte, 2→UInt16, 4→Int, 8→Double, 16→Str, 24→Text, 32→Delegate, 48→MulticastDelegate, >8→Struct

## IDA Signatures (CL-1201801, IDA format, wildcard operands)

### FNamePool::FindOrStore (0x231FA0)
```
41 57 41 56 41 55 41 54 56 57 55 53 48 83 EC ? 4C 89 C0 48 89 D6 48 89 CB
```
Shard hash-table lookup. Entry point for FName resolution. Contains SHARD_HASH_ADD constant (decompiler may show wrong value).

### FField::NamePrivate decode (0x3B8A70)
```
41 57 41 56 41 54 56 57 53 48 81 EC ? ? ? ? 66 44 0F 7F 84 24 ? ? ? ? 66 0F 7F BC 24 ? ? ? ? 66 0F 7F B4 24
```
Decodes FField::NamePrivate to CompIndex. Contains FFIELD_NAME_KEY1, KEY2, SHUF, ROL constants. Found via xref to "PropertyBool.cpp" string (FBoolProperty::GetCPPType caller).

### FFieldClass::NamePrivate decode (0x34F690)
```
41 57 41 56 41 55 41 54 56 57 55 53 48 81 EC ? ? ? ? 66 0F 7F 7C 24 ? 66 0F 7F 74 24 ? 48 89 D7
```
Decodes FFieldClass name handle. Contains FFIELD_CLASS_NAME_KEY.

### FProperty base constructor (0x433460)
```
41 57 41 56 41 55 41 54 56 57 55 53 48 81 EC ? ? ? ? 4C 89 CB 4C 89 C7 49 89 D6 48 89 CE 48 8B 05 ? ? ? ? 48 31 E0 48 89 84 24 ? ? ? ? 41 8B 68
```
Initializes all FProperty fields. Contains Offset_Internal XOR key, ArrayDim/ElementSize init offsets. Primary source for field layout verification.

### FBoolProperty constructor (0x434670)
```
41 57 41 56 56 57 55 53 48 83 EC ? 4C 89 C7 48 89 CE 48 8B 05 ? ? ? ? 48 31 E0 48 89 44 24 ? 49 B9
```
Bool-specific field init. FieldSize/ByteOffset/ByteMask/FieldMask setup.

### Auto-discovered signatures (in auto_discovery.h)
| Pattern | Purpose |
|---------|---------|
| `35 ?? ?? ?? ?? 0F C8` | FProperty offset encode site (xor eax,imm32; bswap eax) |
| `F2 0F 70 C8 ?? 66 0F 38 00 ...` | UObject slot decrypt PSHUFB+PXOR |
| `48 8D 1D ?? ?? ?? ?? 48 8D 3C 1E 48 81 C7 C0 00 00 00` | Legacy FFieldClass anchor |

## Patch-Day Triage Playbook

### When a new patch breaks the dumper:
1. **Check log for auto-discovery success/fail** — phases 0-7 print their results
2. **If FName resolution fails**: check SHARD_HASH_ADD, FNV_ADD, entry header bitmasks (HDR_LENGTH_LO_MASK etc.)
3. **If slot decode fails**: PSHUFB mask or XOR constant drifted — Phase 4 auto-discovers these
4. **If field offsets wrong**: FField layout shifted (has happened -0x40 between CL-1177146→1177678). Look at FProperty ctor in IDA
5. **If property count low**: FField NamePrivate decode constants changed (KEY1/KEY2/SHUF/ROL)
6. **If enum bodies empty**: UEnum::Names offset drifted, or canonical chunk walk variability (retry)
7. **If GObjectArray count wrong**: NumElements offset moved (+0x30 vs +0xFC); probed as u32, range [10000,2M]

### Offset drift history
| Field | CL-1177146 | CL-1177678 | CL-1201801 | CL-1233465 | CL-1299607 | CL-1315578 |
|-------|-----------|-----------|-----------|-----------|-----------|-----------|
| FField::NamePrivate | +0x70 | +0x30 | +0x40 | +0x90 | +0x40 | +0xA0 |
| FField::Next | +0x80 | +0x48 | +0x50 | +0xB0 | +0x60 | +0x78 |
| FField::ClassPrivate | +0x90 | +0x50 | +0x60 | +0xC0 | +0x70 | +0xB8 |
| FField::Owner | +0x10 | +0x10 | +0x70 | +0xA8 | +0x58 | +0x80 |
| FProperty::Offset_Internal | +0xC4 | +0x88 | +0x94 | +0xE4 | +0x94 | +0xE4 |
| FProperty::ElementSize | — | — | +0xC8 | +0x118 | +0x7C | +0xD0 |
| FProperty::ArrayDim | — | — | +0xC0 | +0x110 | +0xC0 | +0x110 |
| FStructProperty::Struct | +0x108 | +0xC8 | +0xE8 | +0x130 | +0xE8 | +0x138 |
| FArrayProperty::Inner | +0xF0 | +0xC8 | +0xF8 | +0x140 | +0xE8 | +0x138 |
| FBoolProperty::FieldSize | — | — | +0xF0 | +0x138 | +0xE8 | +0x138 |
| UStruct::ChildProperties | +0x168 | +0xB0 | +0x108 | +0x118 | +0xC8 | +0xF0 |
| UStruct::PropertiesSize | — | — | +0x110 | +0xE0 | +0x90 | +0xD0 |
| PropertyOffsetXor | — | — | 0xBAB939DB | 0xEAABEC11 | 0x057F15E5 | 0xA271DBC5 |

## Critical Rules (Learned from Past Bugs)

### Never do:
- **Never spawn 2+ parallel agents touching /dev/memreader** — kernel rate-limit overflow → system hang
- **Never hardcode SIMD-table RVAs** — they relocate every patch; sig+disasm+emulate instead
- **Never trust a single sig-scan hit** — require consensus (≥2 sites with same key/offset)
- **Never brute-force decoders without ground-truth** — false positives look plausible but produce wrong names
- **Never use `pick_best_for_kind` by absolute score** — use score DENSITY (score/num_names) to avoid ASClass/UClass confusion

### Always do:
- **Validate EVERY chunk in heap scan** — last-item readability + ≥30% density + cap-8 plausibility
- **Collect ALL objects sharing metaclass names** — not just first; needed for 14K+ type detection
- **Scan ALL ChildProperties offsets 0x80-0x140** — not just one fixed offset
- **Filter GameThread PID by /proc/pid/cmdline** — CrashReportClient.exe inherits the thread name
- **Probe GObjectArray NumElements as u32** (not u64), range [10000, 2M], offsets +0x20..+0x17C
- **Tie-break GNamePool candidates via heap-pointer probe** — FNamePool has chunk pointers (heap), SIMD blocks have inline constants only

## External Resources

| Resource | Location | Purpose |
|----------|----------|---------|
| Reference SDK | `refSDK/SDK/` (6172 .hpp) | Ground-truth field names from CL-1177146 |
| SDK post-processor | `tools/sdk_postprocess.py` | Overlay ref names onto live SDK output |
| Python FName harness | `tools/fname_pipeline.py` | Stage-by-stage FName debug via /proc/pid/mem |
| Leaked ARC_Decryptor | (analyzed, not stored) | sig+Zydis+QuickDecrypt-emu architecture reference |
| Leaked Theia source | `/home/frost/Downloads/bla.txt` | Epic's FName obfuscation (CityHash64WithSeed, FNameEntry layout) |

## Environment
- Wine module base: 0x140000000 (memfd)
- Find PID: `pgrep "GameThread"`, filter out CrashReportClient via `/proc/pid/cmdline`
- IDA instances: `oo5g` (current dump PioneerGame-e_dumped.exe), `3q7c` (CL-1195482)
- IDA binary base: 0 (not 0x140000000) — subtract 0x140000000 from live RVAs for IDA addresses
