# ARC Raiders – Signatures & Xref Guide (Patch 20260409)

> **Lesson learned from 20260402→20260409**: Pure opcode-pattern signatures broke 100%.
> What survived: **string references** (`UObjectHash.cpp`), **FNV prime immediate** (`0x01000193`),
> and **structural patterns** (byte-copy loops, SIMD pipeline shapes).
> This guide prioritizes **resilient anchors** over fragile byte sequences.

---

## Strategy: How to Find Everything After a Patch

### Tier 1 — Anchors (survive across patches)

| Anchor | How to find | What it gives you |
|--------|------------|-------------------|
| `UObjectHash.cpp` string | `find_regex("UObjectHash")` | Xrefs land in **UObj_SlotAccess** — extract FNV, sentinel, slot pipeline |
| FNV prime `0x01000193` | `find(type="immediate", targets=[16777619])` | All FNV hash call sites — slot hash, FName block hash |
| 16× `movzx+mov` byte-copy | `41 0F B6 40 01 88 41 01 41 0F B6 40 02 88 41 02` | **FName_DecryptBlockAddr** — the block resolution function |
| `FNamePool` init guard | `find(type="data_ref", targets=[pool_base_rva])` | FNamePool base address |
| `GetTransientPackage` string | `find_regex("GetTransientPackage")` | Leads to GWorld/GEngine area |

### Tier 2 — Structural patterns (usually survive)

| Pattern | Description |
|---------|-------------|
| `PSHUFB + ROL32 + PSHUFLW` near a `.data` xmmword load | GObjectArray base decrypt |
| `PSHUFLW + ROL64 + PXOR` triple chain (3 levels) | CIdx decode pipeline |
| `AND/ANDNOT blend + PSHUFB + PXOR` | Block header decode |
| `SHLD + IMUL 0x01000193 + ADD + ROL` repeated 4× | FNV-32 slot hash |
| `IMUL 0x100000001B3 + ADD + ROL` repeated 2× | FNV-64 entry chain |
| `ROL64 + PSHUFLW + XOR(sentinel) + CMP(sentinel)` | UObject slot decrypt |

### Tier 3 — Exact signatures (patch-specific, break on update)

See sections below.

---

## 1. UObj_SlotAccess — UObject encrypted slot decrypt
**RVA**: `0x4E8610` (patch 20260409) | Size: `0x825`

**How to find**: Search for xrefs to the `UObjectHash.cpp` string. All 5 xrefs land here.

### Pipeline (patch 20260409 — REVERSED from 20260402):
```
load 16B from obj + 0x20 + slot*32
  → ROL64(45):  PSLLQ(0x2D) | PSRLQ(0x13)
  → PSHUFLW(0x1E)
  → extract lo64
  → XOR(sentinel)
  → result: pointer (class/outer) or ROL64(32) for FName CI
```

Old pipeline was: `PSHUFLW(0x93) → XOR → ROL64(15/47)`. If it changes again, look for
the sentinel comparison (`cmp reg, sentinel; jz null_path`) — that's the anchor.

### Sig: Function prologue + sentinel load (wildcarded)
```
41 57 41 56 56 57 53 48 81 EC ? ? ? ? 48 89 CE 48 8B 05 ? ? ? ? 48 31 E0 48 89 84 24 ? ? ? ? 48 BF ? ? ? ? ? ? ? ?
```
**After match**: bytes at `+0x21..+0x28` (after `48 BF`) = little-endian **sentinel** value.

### FNV Hash (inside this function)
```asm
rol     ecx, 18h          ; ROL32(lo, 24)
imul    ecx, 1000193h     ; * FNV_PRIME
add     ecx, 295812B1h    ; + FNV_ADD
```
**Extraction**: `imul ?, 01000193h` → FNV_PRIME (stable); `add ?, ????????h` → FNV_ADD (changes per patch).
**ROL amounts**: scan for `C1 ?? 18` (ROL 24) and `C1 ?? 0E` (ROL 14) near the IMUL.

### Slot index
```asm
and     ebx, 3            ; class_slot = base_idx & 3
shl     ebx, 5            ; stride = 32
```
`xor edx, 2` = FName slot; `inc r8d; and r8d, 3` = Outer slot.

### Constants (patch 20260409)

| Constant | Value | Extraction |
|----------|-------|------------|
| FNV Prime | `0x01000193` | `69 ?? 93 01 00 01` (unchanged across patches) |
| FNV Add | `0x295812B1` | 32-bit imm after IMUL in hash function |
| Sentinel | `0x0B982F16865A5F21` | `48 BF` or `48 B8` movabs in slot decrypt |
| Slot ROL64 | 45 (0x2D) | PSLLQ immediate |
| Slot PSHUFLW | 0x1E | byte after `F2 0F 70` or `pshuflw` |
| FName final ROL | 32 (0x20) | `rol rax, 20h` after XOR sentinel |

---

## 2. GObj_Decrypt — GUObjectArray SIMD decrypt
**RVA**: `0x2D0784` (first xref to encrypted xmmword)

**How to find**: The encrypted GObjectArray xmmword is in `.data`. Search for
`movdqa xmm0, cs:[.data_addr]` followed by `pshufb xmm0, cs:[.rdata_addr]`.
The `.data` address changes; the `.rdata` PSHUFB table is stable within a patch.

### Pipeline (patch 20260409 — NO PXOR step):
```
PSHUFB(shuf_table)  →  ROL32(9): PSLLD(9)|PSRLD(23)  →  PSHUFLW(0x4B)  →  lo64 = base_ptr
```

### Sig: GObj decrypt inline (wildcarded)
```
66 0F 6F 05 ? ? ? ? 66 0F 38 00 05 ? ? ? ? 66 0F 6F C8 66 0F 72 D1 ? 66 0F 72 F0 ? 66 0F EB C1 F2 0F 70 C0 ? 66 48 0F 7E C0
```
**After match**:
- `+4..+7` = RIP-offset → encrypted xmmword (`.data` global)
- `+13..+16` = RIP-offset → PSHUFB table
- `+24` = PSRLD amount (23 = 32 - ROL)
- `+29` = PSLLD amount (9 = ROL)
- `+35` = PSHUFLW immediate (0x4B)

### Element count (at decrypted_base + 0x50)
```
PSHUFB(cnt_table) → PSLLQ(15) → pextrd dword[1]
```
Sig (inline after GObj decrypt):
```
66 0F 38 00 05 ? ? ? ? 66 0F 73 F0 ? 66 0F 3A 16 ? ?
```

### Chunk table (vtable[5] at decrypted_base + 0x80)
The chunk decrypt uses PEB:
```asm
movq    xmm0, [rdx]           ; load from base+0xB0
mov     eax, IMM32             ; PEB addend
add     rax, gs:[60h]          ; + PEB
pshuflw xmm1, xmm0, IMM8      ; shuffle
pxor    xmm1, [rip+off]        ; XOR table
ROL64(IMM) via psllq|psrlq
mov     rcx, IMM64             ; PEB XOR key
xor     rcx, rax               ; XOR with PEB-derived value
```
**Constants** (patch 20260409):
- PEB addend: `0x0D7DC434`
- PEB XOR key: `0xB2DA4299DB155ED3`
- PSHUFLW: `0x8D`
- ROL64: 46

### Constants (patch 20260409)

| Constant | Value | Location |
|----------|-------|----------|
| GObj struct RVA | `0xDD0B5A0` | `.data` section |
| Encrypted xmmword | struct + `0x30` | |
| PSHUFB table RVA | `0xAC2BC00` | `.rdata` |
| Count PSHUFB RVA | `0xAC7E9D0` | `.rdata` |
| ROL32 amount | 9 | PSLLD imm |
| PSHUFLW imm | `0x4B` | |

---

## 3. FName_ToString — CIdx 3-level decode → entry
**RVA**: `0x23D410` (patch 20260409)

**How to find**: Search for `pshufb xmm0, [rip+off]` followed immediately by `pxor xmm0, [rip+off]`
then `psrlq`/`psllq`/`por` (ROL64) then `pshuflw`. This pattern is the Level-1 CIdx decode.

### Pipeline: 3 levels of SIMD → pool lookup → FNV → entry

**Level 1** (in FName_ToString):
```
CI → cvtsi32_si128 → PSHUFB(cidxShuf) → PXOR(cidxXor1) → ROL64(13) → PSHUFLW(0x93)
```

**Level 2** (in FName_ResolveCIdx / sub_14023C150):
```
L1.lo64 → PSHUFLW(57) → ROL64(51) → PSHUFD(0x44) → PXOR(cidxXor3) → PXOR(cidxXor1) → ROL64(13) → PSHUFLW(0x93)
```

**Level 3 / Block Header** (in FName_DecryptBlockAddr / sub_140237CD0):
```
L2.lo64 → PSHUFLW(0x39) → ROL64(51) → AND(0x1E)/ANDNOT(0xE1) → PSHUFB(hdrShuf) → PXOR(hdrXor)
→ extract u32 = raw_hdr
pool_off = (raw_hdr >> 8) & 0xFFFF00
word_off = (uint16)raw_hdr
```

**NOTE**: For this patch, the 3-level decode produces **identity** (raw_hdr = CI).
This may change in future patches.

### Sig: FName_ToString prologue
```
41 56 41 55 56 57 53 48 83 EC ? 49 89 CE 48 8B 05 ? ? ? ? 48 31 E0 48 89 44 24 ? 66 0F 6E 01 66 0F 38 00 05 ? ? ? ?
```
**After match**: `+33..+36` = RIP-offset to CIdx PSHUFB table.

### Sig: FName_DecryptBlockAddr (16× byte-copy, survives across patches)
```
41 0F B6 40 01 88 41 01 41 0F B6 40 02 88 41 02 41 0F B6 40 03 88 41 03
```

---

## 4. FName Block Slot + FNV → Entry Pointer

### FNV-32 Slot Hash (in FName_DecryptBlockAddr)
```asm
; hash_addr = pool + pool_off + 0x90
; SHLD(16, hash_lo, 27) → IMUL(P) → ADD(K) → ROL(19) → IMUL(P) → +hi → +K → ROL(27) → IMUL(P) → +K → SHR(13) → IMUL(P) → +K
; slot_idx = (lo8 ^ byte2) & 7
```

### Slot Data Decrypt
```
load 8B from pool + pool_off + 0xA0 + 32*slot
  → PSHUFB(slotShuf)
  → ROL32(26): PSLLD(0x1A) | PSRLD(6)
  → XOR(0x1DB6DE4B85F51BC2) = v11
```

### FNV-64 Chain → Entry Pointer
```
fnv1  = P64 * ROL64(v11, 31) + ADD64
fnv2  = P64 * ROL64(fnv1, 44) + ADD64
raw   = v11 + (fnv2 ^ second_slot_decrypted) + 2*word_off

; Three-layer unwinding:
inner = bswap64(raw ^ 0x021DCE2C)
mid   = inner ^ 0x3040EF0C00000000
entry = bswap64(mid ^ 0x1C8EF20E00000000)
```

### Constants (patch 20260409)

| Constant | Value | How to extract |
|----------|-------|---------------|
| FNV-32 Prime | `0x01000193` | `69 ?? 93 01 00 01` |
| FNV-32 K | `0x8FD97DFC` | `ADD` imm32 after `IMUL P` in block hash |
| FNV-32 hash offset | `+0x90` | `add rdx, 90h` in DecryptBlockAddr |
| FNV-32 slot offset | `+0xA0` | `movdqa [rdx+rax+0A0h]` |
| FNV-64 Prime | `0x100000001B3` | `mov r10, imm64` near `imul r8, r10` |
| FNV-64 Add | `0xB6379560F2A0707C` | `mov r11, imm64` near `add r8, r11` |
| Slot PSHUFB | `{04,00,06,01,05,03,07,02}` | 8B at RIP target of `pshufb` in slot decrypt |
| Slot ROL32 | 26 (0x1A) | PSLLD immediate |
| Slot XOR key | `0x1DB6DE4B85F51BC2` | `mov r9, imm64` before `xor rdx, r9` |
| FNV-64 ROL1 | 31 (0x1F) | `rol r8, 1Fh` |
| FNV-64 ROL2 | 44 (0x2C) | `rol r8, 2Ch` |
| Final XOR | `0x021DCE2C` | `xor rax, imm32` before `bswap` |
| Entry XOR2 | `0x3040EF0C00000000` | In sub_14023C150: `xor result, imm64` |
| Entry XOR1 | `0x1C8EF20E00000000` | In FName_ToString: `mov rcx, imm64; xor rcx, [rsp+...]` |

---

## 5. FName String Decrypt

### Entry format
```
uint16 header   — length = ROL16(hdr, 2) & 0x3FF;  wide = (hdr & 0x100)
byte[] string   — encrypted with key table
```

### Key schedule (narrow)
```
key = (uint32)(4*header + (header >> 14) + 11)
byte[i]   ^= keyTable[(key & 0x3F) + 36] >> 3
byte[i+1] ^= keyTable[((key+7) & 0x3F) + 36] >> 3
key += 14   (per pair)
```

### Key schedule (wide)
```
key = length + 62731
word[i]   ^= keyTable[(key & 0x3F) + 36]
word[i+1] ^= keyTable[((key+7) & 0x3F) + 36]
key += 14
```

### Constants

| Constant | Value |
|----------|-------|
| Key table RVA | `0xD9947F4` |
| Key table offset | `+36` (was +60) |
| Key step | `+7` per char |
| Narrow key init | `4*hdr + (hdr>>14) + 11` |
| Wide key init | `length + 62731` |
| Header ROL | 2 (was 3) |

---

## 6. SIMD Data Tables (patch 20260409)

| Name | RVA | Bytes | Used by |
|------|-----|-------|---------|
| `CIDX_SHUF` | `0xAC64930` | `00 00 00 00 01 00 02 03 00 00 00 00 01 00 02 03` | CIdx Level 1 |
| `CIDX_XOR1` | `0xAC64940` | `4F A4 AE 9A 5B 21 A9 EB 4F A4 AE 9A 5B 21 A9 EB` | CIdx Level 1+2 |
| `CIDX_XOR3` | `0xAC64CE0` | `00 A4 00 00 5B 00 A9 EB 00 A4 00 00 5B 00 A9 EB` | CIdx Level 2 |
| `BLK_HDR_AND` | `0xAC64AE0` | `1E` × 16 | Block header |
| `BLK_HDR_ANDNOT` | `0xAC64AD0` | `E1` × 16 | Block header |
| `BLK_HDR_SHUF` | `0xAC64AF0` | `01 04 06 07 00 00 00 00 00 00 00 00 00 00 00 00` | Block header |
| `BLK_HDR_XOR` | `0xAC64B00` | `45 BA 48 0A 00 00 00 00 00 00 00 00 00 00 00 00` | Block header |
| `BLK_SLOT_SHUF` | `0xAC64950` | `04 00 06 01 05 03 07 02 00 00 00 00 00 00 00 00` | Slot decrypt |
| `GOBJ_SHUF` | `0xAC2BC00` | `04 05 03 06 07 01 00 02 00 00 00 00 00 00 00 00` | GObj base |
| `GOBJ_CNT_SHUF` | `0xAC7E9D0` | `00 00 05 01 07 04 03 00 00 00 00 00 00 00 00 00` | Element count |
| `CHUNK_XOR` | `0xACB8690` | `60 18 3E C6 37 76 A0 D2 37 76 60 18 A0 D2 3E C6` | Chunk decrypt |

---

## 7. Global Addresses (patch 20260409)

| Name | RVA | Purpose |
|------|-----|---------|
| `GNAMES_BASE` | `0xDA4FE00` | FNamePool (block count at +0x88) |
| `FNAME_KEY_TABLE` | `0xD9947F4` | uint16[256] XOR key table |
| `GOBJECT_ARRAY` | `0xDD0B5A0` | GUObjectArray struct (encrypted xmm at +0x30) |

---

## 8. Struct Offsets (patch 20260409)

| Struct | Field | Offset | Notes |
|--------|-------|--------|-------|
| **UObject** | VTable | +0x00 | |
| | InternalIndex | +0x0C | **plain uint32** (was +0x90 encrypted) |
| | Slot 0..3 | +0x20, stride 0x20 | 16B encrypted, 4 slots |
| **UStruct** | SuperStruct | +0xB0 | plain ptr |
| | Children (UProperty) | +0xD0 | legacy chain |
| | ChildProperties (FField) | +0xD8 | new system chain |
| | PropertiesSize | +0xE0 | uint32 |
| **FField** | VTable | +0x00 | |
| | NamePrivate (CI) | +0x90 | plain uint32 |
| | Next | +0x98 | plain FField* |
| | ClassPrivate | +0xC8 | FFieldClass* |
| | Offset_Internal | +0xD8 | plain uint32 |
| | ArrayDim | +0xDC | uint32 |
| **UProperty** | Next | +0x30 | UField::Next |
| | FName | +0x50 | PSHUFB+ROR32+XOR decrypt |
| | Offset_Internal | +0x64 | bswap32 ^ 0xC43565C9 |
| **FFieldClass** | ElementSize | +0x70 | uint32 |

---

## 9. Update Procedure (resilient)

1. **Find UObjectHash.cpp string** → xrefs give UObj_SlotAccess function
2. **Extract from UObj_SlotAccess**: sentinel (`mov r??, imm64`), FNV constants (`imul + add`), ROL amounts, PSHUFLW imm, slot stride
3. **Find GObj encrypted xmmword**: search for `movdqa xmm0, cs:[.data]` + `pshufb` pattern. Extract PSHUFB table RVA, ROL amount, PSHUFLW imm
4. **Find 16× byte-copy** (`41 0F B6 40 01 88 41 01`) → FName_DecryptBlockAddr. Extract FNV-32 K, FNV-64 prime/add/ROL amounts, slot PSHUFB, XOR keys
5. **Walk callers** of DecryptBlockAddr → find FName_ToString. Extract CIdx tables, entry XOR constants
6. **Find GNAMES_BASE**: `lea r??, unk_????` in DecryptBlockAddr → pool RVA
7. **Find FNAME_KEY_TABLE**: nearby `lea` in string decrypt function → key table RVA
8. **Verify struct offsets**: read a known UClass, check Children/PropertiesSize make sense
9. **Verify GWorld** (optional): scan `.data` near old RVA for heap ptrs with valid vtables
