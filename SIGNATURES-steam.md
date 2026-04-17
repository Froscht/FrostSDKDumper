# ARC Raiders – Signatures & Xref Guide (Patch 20260402)

Module Base: `0x140000000`
Binary: `Arc_Raiders_Binary_20260402_180339.exe`
Last confirmed: 2026-04-03

On game update: scan signatures → follow LEA operands → extract new RVAs.

---

## 1. Key Functions

### FName_DecryptBlockAddr — Block header SIMD decrypt
- **RVA**: `0x231280` | **Size**: `0x231`
- **Sig**: `41 55 56 57 53 48 83 EC 38 0F 29 74 24 20 48 89 D3 41 0F B6 00 88 01 41 0F B6 40 01`
- **ONLY function** that references `BLOCK_HDR_AND/ANDNOT/SHUF/XOR`
- **Xrefs out**: 4 LEA instructions to block header tables
- **Update**: Find this func → extract all 4 LEA targets. CIDX tables are ~0x300 bytes before in .rdata.

### FName_ToString — CIdx decode entry
- **RVA**: `0x22A740` | **Size**: `0x17A`
- **Sig**: `41 57 41 56 56 57 53 48 81 EC 70 08 00 00 49 89 D6 49 89 CF`
- **Xrefs out**: `CIDX_SHUF` (pshufb), `CIDX_XOR1` (pxor), `CIDX_XOR2` (pxor)
- **Update**: Extract 3 LEA targets at func+0x3C, +0x45, +0x4D

### FName_ResolveCIdx — CIdx → block/offset
- **RVA**: `0x22C0EE` | **Size**: `0xFE`
- **Sig**: `33 C0 41 57 41 56 56 57 53 48 81 EC 80 00 00 00 49 89 D6 49 89 CF`

### FName_GetBlockPtr — Pool slot + block address
- **RVA**: `0x2280A0` | **Size**: `0x125`
- **Sig**: `41 56 41 55 56 57 53 48 81 EC 80 00 00 00 48 8B 05`
- **Contains**: LEA to `GNAMES_BASE` (FNamePool global in .data)

### UObj_SlotAccess — UObject encrypted slot decrypt (FName/Class/Outer)
- **RVA**: `0x4C5600` | **Size**: `0xF6E`
- **Sig**: `41 57 41 56 41 55 41 54 56 57 55 53 48 81 EC 88 00 00 00 48 89 CE`
- **Contains all slot decrypt constants inline**:
  - FName XOR sentinel: `48 BB 58 3F 5A 08 A1 61 4A CB` → `0xCB4A61A1085A3F58`
  - Ptr XOR sentinel: `48 B8 82 B3 EC D4 4B 78 C3 07` → `0x07C3784BD4ECB382`
  - FName ROL: `C1 C3 2F` → `rol rbx, 0x2F` (47)
  - Ptr ROL: `49 C1 C4 0F` / `48 C1 C0 0F` → `rol, 0x0F` (15)
  - PSHUFLW IMM: `F3 0F 70 ?? ?? 93` → 0x93
  - FNV prime: `69 C9 93 01 00 01` → `imul ecx, 0x01000193`
  - FNV addend: `81 C1 F9 27 67 78` → `add ecx, 0x786727F9`
  - Slot base: `[rsi+rax+20h]` → offset 0x20
  - Slot stride: `C1 E0 05` → `shl eax, 5` (×32)
  - FName slot: `83 F0 02` → `xor eax, 2`
  - Class slot: `41 83 E7 03` → `and r15d, 3`
  - Outer slot: `FF C7 83 E7 03` → `inc edi; and edi, 3`
- **Xrefs out**: `SLOT_MASK_PANDN`, `SLOT_MASK_PAND` (LEA at func+0x97, +0x9F)

### UObj_FNVHash — Address hash for slot selection
- **RVA**: `0x4E2130`
- **Sig**: `41 57 41 56 56 57 53 48 81 EC 70 02 00 00 48 89 CE`
- **Contains**: `mov rdi, 0x07C3784BD4ECB382` inline + FNV constants

### GObj_Decrypt — GUObjectArray SIMD decrypt
- **RVA**: `0x49AD` | **Size**: `0x148`
- **Sig**: `41 55 55 56 57 48 83 EC 28 B9 01 00 00 00 31 C0 F0 0F B1 0D`
- **Xrefs out**: `SIMD_OBJARRAY_SHUF`, `SIMD_OBJARRAY_XOR`
- **Nearby**: `GOBJECT_ARRAY_BASE` reference

---

## 2. SIMD Data Tables

Found via LEA xrefs from functions above. On update: find the functions first, then extract new LEA targets.

| Name | RVA | Bytes (16) | Found via |
|------|-----|------------|-----------|
| `SIMD_OBJARRAY_SHUF` | `0xABE2BD0` | `03 02 01 07 06 04 05 00 00 00 00 00 00 00 00 00` | GObj_Decrypt |
| `SIMD_OBJARRAY_XOR`  | `0xABE2BE0` | `9F 47 E1 8B 5C 95 C6 FE 9F 47 E1 8B 5C 95 C6 FE` | GObj_Decrypt |
| `CIDX_SHUF`          | `0xAC1BB10` | `04 07 05 00 06 03 01 02 04 07 05 00 06 03 01 02` | FName_ToString |
| `CIDX_XOR1`          | `0xAC1BB60` | `60 93 85 E5 54 84 FB 40 60 93 85 E5 54 84 FB 40` | FName_ToString |
| `CIDX_XOR2`          | `0xAC1BA50` | `04 F1 D5 27 49 EE 9D 5E 04 F1 D5 27 49 EE 9D 5E` | FName_ToString, FName_GetBlockPtr |
| `BLOCK_HDR_AND`      | `0xAC1BE50` | `E6 E6 E6 E6 E6 E6 E6 E6 E6 E6 E6 E6 E6 E6 E6 E6` | FName_DecryptBlockAddr |
| `BLOCK_HDR_ANDNOT`   | `0xAC1BE40` | `19 19 19 19 19 19 19 19 19 19 19 19 19 19 19 19` | FName_DecryptBlockAddr |
| `BLOCK_HDR_SHUF`     | `0xAC1BE60` | `03 06 07 05 00 00 00 00 00 00 00 00 00 00 00 00` | FName_DecryptBlockAddr |
| `BLOCK_HDR_XOR`      | `0xAC1BE70` | `3E 84 47 F7 00 00 00 00 00 00 00 00 00 00 00 00` | FName_DecryptBlockAddr |
| `SLOT_MASK_PANDN`    | `0xAC73D70` | `DA 8C B6 DC EA 19 89 CC DA 8C B6 DC EA 19 89 CC` | UObj_SlotAccess |
| `SLOT_MASK_PAND`     | `0xAC73D80` | `25 73 49 23 15 E6 76 33 25 73 49 23 15 E6 76 33` | UObj_SlotAccess |

---

## 3. Global Addresses

| Name | RVA | How to find |
|------|-----|-------------|
| `GNAMES_BASE` | `0xDA26E00` | LEA in FName_GetBlockPtr → .data section pointer |
| `FNAME_KEY_TABLE` | `0xD96B7F4` | FName key decrypt refs; 64× uint16 at `+0x78` = `0xD96B86C` |
| `GOBJECT_ARRAY_BASE` | `0xDCE2440` | LEA near GObj_Decrypt; read uint32 count + SIMD decrypt chunk ptr |

---

## 4. Inline Constants

| Constant | Value | Scan pattern |
|----------|-------|-------------|
| FName XOR (raw, pre-bitselect) | `0xCB4A61A1085A3F58` | `48 BB 58 3F 5A 08 A1 61 4A CB` |
| Ptr XOR / effective sentinel | `0x07C3784BD4ECB382` | `48 B8 82 B3 EC D4 4B 78 C3 07` |
| FNV prime | `0x01000193` | `69 C9 93 01 00 01` (imul ecx) |
| FNV addend | `0x786727F9` | `81 C1 F9 27 67 78` (add ecx) |
| FName ROL | 47 | `C1 C3 2F` (rol rbx, 0x2F) |
| Ptr ROL | 15 | `C1 C4 0F` / `C1 C0 0F` (rol, 0x0F) |
| PSHUFLW IMM | 0x93 | `F3 0F 70 ?? ?? 93` |
| UProp Offset XOR | `0xC43565C9` | In DecryptUPropertyOffset bswap^XOR |
| CIdx ROL32 amount | 23 | In ResolveNamePtrFull, `ROL32(ci, 23)` |

---

## 5. Struct Offsets

### UObject (with encrypted slots)
| Field | Offset | Notes |
|-------|--------|-------|
| VTable | +0x00 | |
| Slot 0 | +0x20 | 16 bytes encrypted |
| Gap 0 (UField::Next) | +0x30 | Plain pointer |
| Slot 1 | +0x40 | 16 bytes encrypted |
| Slot 2 | +0x60 | 16 bytes encrypted |
| Slot 3 | +0x80 | 16 bytes encrypted |
| Post-slot gap | +0x90 | Pool index for FField; other data for UObject |

### UStruct
| Field | Offset | Notes |
|-------|--------|-------|
| SuperStruct | +0xB0 | Plain pointer to parent UStruct |
| Children | +0xD0 | Old UProperty chain (UField::Next at +0x30) |
| ChildProperties | +0xD8 | Function descriptor chain (NOT FProperty!) |
| PropertiesSize | +0xE0 | uint32 sizeof(struct) |

### UEnum
| Field | Offset | Notes |
|-------|--------|-------|
| Names | +0xB0 | TArray: ptr at +0xB0, count at +0xB8 |
| Entry stride | 16 | int32 CI at +0, int64 value at +8 |

### UFunction
| Field | Offset | Notes |
|-------|--------|-------|
| Children (params) | +0xD0 | Old UProperty chain (function parameters) |
| FunctionFlags | +0x128 | uint32 bitmask |
| NativeFunc | +0x1C8 | Code pointer (0 if BP-only) |
| **Found via**: GObjects scan where ClassPrivate = "Function" metaclass | | Grouped by OuterPrivate |

### Old UProperty (UObject subclass)
| Field | Offset | Notes |
|-------|--------|-------|
| UField::Next | +0x30 | Chain walk pointer |
| FName | +0x50 | Custom PSHUFB+ROR32+XOR decrypt (GetUPropertyCompIndex) |
| Offset_Internal | +0x64 | `bswap32(val) ^ 0xC43565C9` |
| ElementSize | +0x68 | Plain uint32 |
| ArrayDim | +0x6C | Plain uint32 |

### FField (heap-allocated, NOT in GObjects)
| Field | Offset | Notes |
|-------|--------|-------|
| VTable | +0x00 | All FProperties share 1 vtable |
| **NamePrivate** | **encrypted slot** | Same PSHUFLW→XOR→ROL64(47) as UObject slots! Use `GetCompIndex(ff_addr)` |
| Pool index | +0x90 | NOT the FName CI — just the allocator index |
| Next | +0x98 | Plain pointer to next FField |
| ClassPrivate | +0xC8 | FFieldClass* pointer |
| Offset_Internal | +0xD8 | Plain uint32 (for FProperty) |
| ArrayDim | +0xC0 | uint32 |

### FFieldClass
| Field | Offset | Notes |
|-------|--------|-------|
| ElementSize | +0x70 | uint32 |

---

## 6. Xref Instruction Patterns

```asm
; CIdx tables (in FName_ToString, FName_ResolveCIdx):
66 0F 38 00 05 ?? ?? ?? ??   ; pshufb xmm0, [rip+CIDX_SHUF]
66 0F EF 05 ?? ?? ?? ??      ; pxor   xmm0, [rip+CIDX_XOR1]
66 0F EF 05 ?? ?? ?? ??      ; pxor   xmm0, [rip+CIDX_XOR2]

; Block header tables (in FName_DecryptBlockAddr):
66 0F DB 35 ?? ?? ?? ??      ; pand   xmm6, [rip+BH_AND]
66 0F DF 35 ?? ?? ?? ??      ; pandn  xmm6, [rip+BH_ANDNOT]
66 0F 38 00 35 ?? ?? ?? ??   ; pshufb xmm6, [rip+BH_SHUF]
66 0F EF 35 ?? ?? ?? ??      ; pxor   xmm6, [rip+BH_XOR]

; Slot decrypt (in UObj_SlotAccess):
66 0F DF 0D ?? ?? ?? ??      ; pandn  xmm1, [rip+SLOT_PANDN]
66 0F DB 05 ?? ?? ?? ??      ; pand   xmm0, [rip+SLOT_PAND]

; Sentinel immediates:
48 BB ?? ?? ?? ?? ?? ?? ?? ?? ; mov rbx, FName_XOR_sentinel
48 B8 ?? ?? ?? ?? ?? ?? ?? ?? ; mov rax, Ptr_XOR_sentinel
```

---

## 7. Update Procedure (Step by Step)

1. **Scan** for `FName_DecryptBlockAddr` sig → get 4 `BLOCK_HDR_*` LEA targets
2. **Scan** for `FName_ToString` sig → get 3 `CIDX_*` LEA targets
3. **Scan** for `FName_GetBlockPtr` sig → get `GNAMES_BASE` LEA target
4. **Scan** for `UObj_SlotAccess` sig → extract all inline constants:
   - 2× `mov reg, imm64` → sentinels
   - `rol` immediates → ROL amounts
   - `pshuflw` immediate → shuffle control
   - 2× LEA → `SLOT_MASK_*` addresses
   - `imul`/`add` constants → FNV prime/addend
5. **Scan** for `GObj_Decrypt` sig → get `SIMD_OBJARRAY_*` LEA targets + `GOBJECT_ARRAY_BASE`
6. **Verify offsets**: read a known UClass, check Children/Properties/PropertiesSize make sense
7. **Find FNAME_KEY_TABLE**: search .data for the 64 uint16 key entries near GNames
