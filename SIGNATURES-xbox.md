# ARC Raiders – Xbox Build Signatures & Constants (Patch 20260409)

Binary: `PioneerGame28_xbox_inMatch.exe`

> Found using the same Tier 1 anchors as Steam: `UObjectHash.cpp` string xrefs + callgraph walking.
> The encryption is **completely different** from the Steam build — different pipeline order,
> different operations (ROR vs ROL, SUB vs ADD), different constants.

---

## Key Functions

| Function | Address | Found via |
|----------|---------|-----------|
| `UObj_SlotAccess` | `0x7FF640AFCBB0` | UObjectHash.cpp xrefs |
| `FName_ToString` | `0x7FF640891EA0` | UObj_SlotAccess callees → UObject_GetPathName → BuildPathName callees |
| `FName_ResolveCIdx_Level2` | `0x7FF640890D10` | FName_ToString callee |
| `FName_DecryptBlockAddr` | `0x7FF640890B20` | FName_ResolveCIdx_Level2 callee (has 8x byte-copy pattern) |
| `FName_DecryptString` | `0x7FF640891B80` | FName_ToString callee |
| `FName_BoundsCheck` | `0x7FF6408968D0` | UObj_SlotAccess callee (`HIWORD(ci) < block_count+1`) |
| `GObj_ValidateInArray` | `0x7FF640AC3CB0` | UObj_SlotAccess callee |
| `UObject_GetPathName` | `0x7FF640AF4810` | UObj_SlotAccess callee |
| `UObject_BuildPathName` | `0x7FF640AF48E0` | UObject_GetPathName callee |
| `UE_Assert` | `0x7FF64081A0B0` | error string xrefs |

---

## 1. UObject Slot Decrypt

### Pipeline (Xbox — DIFFERENT from Steam)
```
XOR(sentinel) → PSHUFLW(0xB1) → ROL32(20) → PSHUFB(table) → result
```

Compare Steam: `ROL64(45) → PSHUFLW(0x1E) → XOR(sentinel) → result`

### Slot addressing
```
slot_data = *(uint64*)(obj + 0x10 + slot_index * 16)
```
- Base offset: `+0x10` (Steam uses `+0x20`)
- Stride: `16 bytes` (Steam uses `32 bytes`)
- Slot index: `(hash >> 16) ^ hash) & 3`, same formula as Steam

### Constants

| Constant | Value | Notes |
|----------|-------|-------|
| Sentinel | `D7 38 D1 B4 74 14 70 0C` (repeated) | at `0x7FF6483CECD0` |
| PSHUFLW imm | `0xB1` (177) | Steam uses `0x1E` |
| ROL32 amount | 20 | via PSLLD(20)\|PSRLD(12), using XOR not OR |
| PSHUFB table | `07 04 06 01 00 02 03 05` (repeated) | at `0x7FF6483CECB0` |
| Null check | `test rax, rax; jz null_path` | after PSHUFB extract |

### FNV Hash (Xbox — uses ROR not ROL, uses SUB not ADD)
```asm
ror     eax, 0Ah          ; ROR32(lo, 10) — Steam uses ROL32(24)
imul    ecx, eax, 1000193h
sub     ecx, 5E86F13Fh    ; = add 0xA1790EC1
ror     ecx, 13h           ; ROR32(19) — Steam uses ROL32(14)
imul    ecx, 1000193h
add     edx, 0A1790EC1h    ; hi + K1
add     edx, ecx
ror     edx, 0Ah           ; ROR32(10)
sub     edx, 212CCD25h     ; = add 0xDED332DB (different K2!)
imul    eax, edx, 1000193h
ror     eax, 13h           ; ROR32(19)
sub     eax, 212CCD25h     ; K2
imul    eax, 1000193h
```

| Constant | Value | Notes |
|----------|-------|-------|
| FNV Prime | `0x01000193` | unchanged across all builds |
| K1 (add) | `0xA1790EC1` | = -(0x5E86F13F) as uint32 |
| K2 (add) | `0xDED332DB` | = -(0x212CCD25) as uint32 |
| ROR amounts | 10, 19, 10, 19 | Steam uses ROL 24, 14, 24, 14 |

---

## 2. GObject Array

### Global addresses
| Name | Address | Notes |
|------|---------|-------|
| GObj struct | `0x7FF64B7463F0` | GUObjectArray global |
| GObj encrypted xmmword | struct + `0x80` | at `0x7FF64B746470` |

### GObj base pointer decrypt
```
PSHUFLW(0x93) → ROL32(27): PSLLD(0x1B)|PSRLD(5) → PSHUFB(table)
```
- PSHUFB table at `0x7FF648378C20`: `{07 05 00 02 06 04 01 03}`

Compare Steam: `PSHUFB → ROL32(9) → PSHUFLW(0x4B)`

### Element count decrypt
```
load [base+0x60] → ROL64(5): PSLLQ(5)|PSRLQ(59) → PSHUFLW(0x39) → ROL16(1): PSLLW(1)|PSRLW(15) → extract lo32
```

Compare Steam: `PSHUFB(table) → PSLLQ(15) → pextrd[1]`

---

## 3. FName Resolution

### CIdx Level 1 (in FName_ToString)
```
CI → PSHUFLW(0x8D) → XOR(xmmword_7FF6483B6A90) → PSHUFLW(0x8D) → ROL32(20)
```
- XOR table: `A9 9B 34 82 71 4B 31 4B` (repeated)
- PSHUFLW: `0x8D` (141)
- ROL32: 20 (same as slot decrypt)

Compare Steam: `PSHUFB → PXOR → ROL64(13) → PSHUFLW(0x93)`

### FName_DecryptBlockAddr (block resolution)
```
Decompiled from sub_7FF640890B20:

Pool base:       0x7FF64B58BC40 (unk, with init guard at byte_7FF64B58B9D7)
Block count:     dword_7FF64B58BC88
Block stride:    128 bytes (= HIWORD(decoded) * 128)
Word offset:     LOWORD(decoded)

FNV-32 hash (for slot selection):
  Input:         block_base + 80 (= +0x50)
  Prime:         0x01000193
  K:             -807133223 = 0xCFD3A4E9 (uint32)
  K2:            -858723229 = 0xCCD24063 (uint32)
  ROR amount:    5 (all 4 rounds use ROR 5)
  Slot mask:     & 7 (8 slots)
  Slot stride:   16 bytes
  Slot base:     block_base + 80

Slot decrypt:
  ROL64(43):     (x << 43) ^ (x >> 21)  — using XOR not OR
  XOR key:       0xB32D7D9362698C27

FNV-64 chain:
  Prime:         0x100000001B3 (same as Steam)
  Add:           0xD0EC645C0701AC39 (= -0x2F139BA3F8FE53C7)
  ROR1:          27
  ROR2:          31

Entry pointer:
  result ^ 0xF6CDE314 → movbe (bswap) → entry address
```

Compare Steam:
- Block stride 0x10000 (page-aligned), Xbox uses 128
- Slot stride 32, Xbox uses 16
- FNV-32 all use ROL, Xbox uses ROR(5) for all rounds
- FNV-64 ROL(31,44), Xbox uses ROR(27,31)

### FName_ToString entry XOR layers
```
Layer 1 (DecryptBlockAddr):  movbe(result ^ 0xF6CDE314)
Layer 2 (ResolveCIdx_Level2): result ^ ??? (follow sub_7FF640890D10)
Layer 3 (ToString):          movbe(result ^ 0x2945EB14)
```

---

## 4. FNamePool

| Name | Address |
|------|---------|
| FNamePool base | `0x7FF64B58BC40` |
| Block count | `0x7FF64B58BC88` (+0x48 from pool) |
| Init guard | `byte_7FF64B58B9D7` |

---

## 5. Steam vs Xbox Comparison

| Feature | Steam (20260409) | Xbox (20260409) |
|---------|-------------------|-----------------|
| **Slot pipeline** | ROL64→PSHUFLW→XOR | XOR→PSHUFLW→ROL32→PSHUFB |
| **Slot stride** | 32 bytes at obj+0x20 | 16 bytes at obj+0x10 |
| **Sentinel** | `0x0B982F16865A5F21` | `0x0C701474B4D138D7` |
| **PSHUFLW slot** | 0x1E | 0xB1 |
| **FNV operation** | ROL + ADD | ROR + SUB |
| **FNV K** | 0x295812B1 | K1=0xA1790EC1, K2=0xDED332DB |
| **FNV rotations** | 24, 14, 24, 14 | 10, 19, 10, 19 |
| **GObj pipeline** | PSHUFB→ROL32(9)→PSHUFLW(0x4B) | PSHUFLW(0x93)→ROL32(27)→PSHUFB |
| **GObj enc offset** | struct+0x30 | struct+0x80 |
| **CIdx Level 1** | PSHUFB→PXOR→ROL64(13)→PSHUFLW(0x93) | PSHUFLW(0x8D)→XOR→PSHUFLW(0x8D)→ROL32(20) |
| **FNV-32 slot ROR** | ROL(19,27), shr 13 | ROR(5) all rounds |
| **Block stride** | page-aligned (>>8 & 0xFFFF00) | 128 bytes |
| **Slot data stride** | 32 bytes | 16 bytes |
| **Slot XOR key** | 0x1DB6DE4B85F51BC2 | 0xB32D7D9362698C27 |
| **FNV-64 Add** | 0xB6379560F2A0707C | 0xD0EC645C0701AC39 |
| **FNV-64 ROLs** | 31, 44 | ROR 27, 31 |
| **Entry XOR** | 0x021DCE2C (3 layers) | 0xF6CDE314 + 0x2945EB14 (3 layers) |

---

## 6. Update Procedure (Xbox)

Same Tier 1 anchors work:

1. `find_regex("UObjectHash")` → xrefs → **UObj_SlotAccess**
2. Extract sentinel (`xorps xmm1, [addr]`), PSHUFLW imm, ROL amounts, FNV constants
3. Follow callgraph: UObj_SlotAccess → callees → find **UObject_GetPathName** (largest callee with sub-calls)
4. GetPathName → BuildPathName → callees → find **FName_ToString** (takes FName*, returns string)
5. FName_ToString → callees → **FName_ResolveCIdx_Level2** and **FName_DecryptString**
6. ResolveCIdx_Level2 → callee → **FName_DecryptBlockAddr** (has 8x byte-copy pattern)
7. Extract all FNV-32, FNV-64, slot, and entry constants from DecryptBlockAddr
8. **FName_BoundsCheck**: smallest callee of UObj_SlotAccess (`HIWORD(ci) < block_count+1`) → gives FNamePool block count address
9. **GObj struct**: `lea rcx, [addr]` before call to GObj_ValidateInArray → gives GUObjectArray global

All functions found and renamed successfully using only string references + callgraph traversal.
