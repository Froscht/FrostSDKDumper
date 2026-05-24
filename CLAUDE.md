# FrostSDKDumper — Consolidated Reference

## Project Overview
External SDK dumper for ARC Raiders (Unreal Engine 5, Theia-obfuscated). Reads game memory via `/dev/memreader` kernel module (or `process_vm_readv` fallback). Outputs `SDK_Output.txt` + per-class `.hpp` files. Runs on Linux against Wine-hosted game process.

Build: `g++ -std=c++17 -O2 -march=native -mavx2 -msse4.1 -o FrostDumper main.cpp build/Zydis.o -lcapstone -lunicorn -lm`
Run: `sudo ./build_and_run.sh [PID]`

## Current Patch: CL-1201801 (2026-05-19)
Last verified: 22.8s dump, 99.2% naming, ~204K properties, 4004 structs, 2878 enums.

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

**Hardcoded fallbacks (arc_decrypt.h, manual update if drift):**
- UObject/UStruct/FField/FProperty field offsets (layout shifts per patch)
- FName entry header bitmasks (HDR_LENGTH_LO_MASK, HDR_IS_WIDE_BIT, etc.)
- SHARD_HASH_ADD, FNV_ADD, SLOT_HASH_ADD constants
- FField NamePrivate SIMD pipeline (KEY1/KEY2/SHUF/ROL values)
- GUObjectArray NumElements offset (+0x30 or +0xFC depending on patch)

## Key Constants (CL-1201801 / v20260519)

### Globals (RVAs)
| Name | RVA | Purpose |
|------|-----|---------|
| GNamePool | 0xE0FAA80 | FName string pool base |
| GNamePool init guard | 0xE0FAA78 | 1-byte init flag |
| SIMD constants block | 0xE0397F4 | FName decrypt SIMD tables |
| Keystream table | 0xE03989C | FName entry keystream (SIMD+0xA8) |
| UObj slot XOR mask (.rdata) | 0xB1F0B90 | PSHUFB mask for slot decrypt |
| GUObjectArray | 0xE4F8F60 | Object array base struct |
| GWorld | 0xE706C58 | Current UWorld pointer |
| PropertyType table | GNamePool+0x2540 | 703 FName handles for property types |

### Decrypt Constants
| Constant | Value | Used For |
|----------|-------|----------|
| UOBJ_SLOT_XOR_64 | 0xD22BC6399DD7BE75 | UObject name/class/outer slot PXOR |
| SLOT_HASH_ADD | 0x8F957A95 | FNV32 slot selector hash seed |
| SHARD_HASH_ADD | 0x4A3617A2 | FNamePool shard hash (decompiler shows wrong 0x4A3FAF42) |
| FNV_ADD | 0xBF571668EC20FA62 | FName entry FNV hash offset |
| FFIELD_NAME_KEY1 | 0xC88F612129941481 | FField NamePrivate XOR stage 1 |
| FFIELD_NAME_KEY2 | 0x018A6E394CF4AED0 | FField NamePrivate XOR stage 2 |
| FFIELD_NAME_SHUF | 0x1E | PSHUFLW imm for FField name |
| FFIELD_CLASS_NAME_KEY | 0x08EA69F63989FC99 | FFieldClass NamePrivate XOR |
| PropertyOffsetXor | 0xBAB939DB | bswap32(stored ^ key) = real offset |

### UObject Slot Decode Pipeline (CL-1201801)
```
NAME slot: PSHUFLW(0xB1) → XOR(0xD22BC6399DD7BE75) → ROL64(37)
CLASS/OUTER: ROL64(5) on direct pointer
Slot selector (NAME):  ((Lo8 ^ Hi8) & 3) ^ 2
Slot selector (CLASS):  t & 3
Slot selector (OUTER):  (((u8)v ^ byte2(v)) + 1) & 3
Hash: FNV32(prime=0x01000193, add=0x8F957A95), ROLs 17/19/17 + shift13
Base: obj + 0x20, stride 0x20 (4 slots)
```

### FField NamePrivate Decode (CL-1201801)
```
XOR(0xC88F612129941481) → ROL32(17) → PSHUFLW(0x1E) → XOR(0x018A6E394CF4AED0) → ROL64(32)
```

### FField/FProperty Layout (CL-1201801)
| Field | Offset | Notes |
|-------|--------|-------|
| FField::NamePrivate | +0x30 | Encrypted FName CI |
| FField::Next | +0x48 | Next FField in chain |
| FField::ClassPrivate | +0x50 | FFieldClass pointer |
| FField::Owner | +0x58 | Owner UStruct |
| FProperty::PropertyFlags | +0x88 | uint64 flags |
| FProperty::Offset_Internal | +0x94 | bswap(real ^ 0xBAB939DB) |
| FProperty::ArrayDim | +0xC0 | int32 |
| FProperty::ElementSize | +0xC8 | int32 |
| FStructProperty::Struct | +0xE8 | UScriptStruct* |
| FArrayProperty::Inner | +0xF8 | FProperty* |
| FMapProperty::KeyProp | +0xE8 | FProperty* |
| FMapProperty::ValueProp | +0xF0 | FProperty* |
| FEnumProperty::UnderlyingProp | +0xE8 | FProperty* (numeric) |
| FEnumProperty::Enum | +0xF0 | UEnum* |
| FBoolProperty specifics | +0xC0..+0xC4 | FieldSize/ByteOffset/ByteMask/FieldMask |

### UStruct/UClass/UEnum Layout
| Field | Offset | Notes |
|-------|--------|-------|
| UStruct::SuperStruct | +0xB0 | UStruct* parent |
| UStruct::ChildProperties | +0xB8 | FField* head (scan 0x80-0x140) |
| UStruct::PropertiesSize | +0x110 | int32 total struct size |
| UFunction::NativeFunc | +0x178 | void* native function pointer |
| UEnum::Names | +0xA8 or +0xB0 | TArray<TPair<FName,int64>> |

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
| Field | CL-1177146 | CL-1177678 | CL-1201801 |
|-------|-----------|-----------|-----------|
| FField::NamePrivate | +0x70 | +0x30 | +0x30 |
| FField::Next | +0x80 | +0x48 | +0x48 |
| FField::ClassPrivate | +0x90 | +0x50 | +0x50 |
| FProperty::Offset_Internal | +0xC4 | +0x88 | +0x94 |
| FStructProperty::Struct | +0x108 | +0xC8 | +0xE8 |
| FArrayProperty::Inner | +0xF0 | +0xC8 | +0xF8 |

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
