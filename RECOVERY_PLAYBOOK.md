# ARC Raiders Patch Recovery Playbook

Reference: patch **20260428** (Steam build `ARC_RAIDERS_UNKNOWN_20260428_111248_D3D694C7_77PagesDecrypted.exe`, module base 0x140000000, IDB rebased to 0).

This file documents every load-bearing anchor the dumper depends on, with **multiple recovery paths** so when the next patch shifts RVAs, the layout, or the algorithm, the dumper can be re-anchored without redoing the full RE pass.

For every anchor below: prefer recovery methods in the order listed (1 → fastest, N → slowest). String anchors survive layout churn; xref-graph patterns survive RVA shifts; algorithmic / structural fingerprints survive both.

---

## 0. Big picture (what the encryption is)

Every UObject FName access since 1.26.x requires:
1. Hash → slot index (4 slots @ obj+0x20/+0x40/+0x60/+0x80, stride 0x20)
2. SIMD decrypt of slot (PSHUFB + ROL32 + XOR + optional ROL64)
3. Lo32 of result is `CompIndex` (FNamePool slot)
4. CompIndex → entry pointer via second SIMD pass + FNV-64 fold
5. Entry → string via per-char keytable XOR

Pre-1.26: `*(FName*)(obj+0x18)` was a single load. Now: 6-stage pipeline. Everything below revolves around finding the constants/functions that drive this.

---

## 1. FNamePool resolver constants

### `GNamePool_Base` — RVA `0xDB5BE80`
Base of the FNamePool chunk array. Every chunk-relative entry pointer is `GNamePool_Base + chunk_offset`.

Recovery (in order):
1. **xref count** ≈ 0 (data, only used inside the resolver)
2. **String anchor**: search for `"NamePoolChunkBase"` in IDA — typically only 1 match in a getter.
3. **Structural**: find any function that does `lea rXX, [rip+disp32]; <stuff>; mov reg, [rax + 0x6580]` — the lea target is `GNamePool_Base`. The +0x6580 offset (chunk header → keytable region) is the tell.
4. **Live probe**: after PE load, find any module-range data pointer at offset +0xC8 of an FName-decode result; that's GNamePool_Base.

### `FName_KeyTable` — RVA `0xDAA07F4`
256 × uint16 table. Used in the per-char XOR loop in `decrypt_name_string`: `byte ^= table[idx] >> 3`.

Recovery:
1. **String anchor**: `"FName_KeyTable"` (sometimes `"NamePoolKey"`) typically present.
2. **Xref count** ≈ 66 — every site that calls into the entry-decode loop.
3. **Byte pattern**: a 512-byte region of mostly-nonzero u16 values, sequential indexing patterns nearby.
4. **Live probe**: read 512 bytes; verify ≥64 nonzero u16s.

### `FName_SlotShufMask` — RVA `0xAD63080`
16-byte PSHUFB mask used in slot decrypt.

Recovery:
1. **Xref count** ≈ 16,837 — extremely high. The mask is referenced from every UObject FName decrypt site.
2. **Byte pattern**: known bytes `01 06 00 04 07 03 02 05 ...` (per C# reference; verify on patch).
3. **Sibling-data**: lives in a `.rdata` cluster with `FName_CIdxShuf1` (+0x80), `FName_SlotXorKey` (+0x90), `FName_BlockShufMask` (+0xB0), `FName_BlockHashShuf` (+0xC0), `FName_BlockHashXor` (+0xD0). Find one, the rest are at known offsets.

### `FName_SlotXorKey` — RVA `0xAD49110`
XOR key applied during slot decrypt (16 bytes; lo64 = `0x4834C6DEA02581C7`).

Recovery:
1. **Xref count** ≈ 20 — much lower than ShufMask, but specific.
2. **Byte pattern**: `C7 81 25 A0 DE C6 34 48 ...` (lo64 little-endian).
3. **Sibling cluster** (see ShufMask).

### `FName_CIdxShuf1` / `FName_BlockShufMask` / `FName_BlockHashShuf` / `FName_BlockHashXor`
RVAs `0xAD49100` / `0xAD49130` / `0xAD49140` / `0xAD49150`.

Recovery: sibling-cluster from `FName_SlotXorKey` (16-byte stride, all in the same `.rdata` block). Fingerprint via the xor cluster start.

---

## 2. UObject slot decrypt pipeline

### Slot picker hash constants (UObjSlot20260428)
- `HASH_PRIME = 0x01000193` (FNV-32 prime, **constant across patches**)
- `HASH_ADD = 0x114F3D53` (290405715 dec; verified against the C# reference)
- `HASH_ROL1 = 25, HASH_ROL2 = 27, HASH_SHR1 = 7, HASH_SHR2 = 5`
- Final mask: `(uint8(h) ^ uint8(h>>16)) & 3 ^ 2` → 4-slot picker (NOT 8-slot)

Recovery:
1. **String anchor**: search the binary for `"FNV"` strings or string-table refs near slot decrypt functions (rare).
2. **Algorithmic**: find any function that reads `[obj+0x10]`, then computes `P*h + ADD` chains, then ANDs `& 3` and XORs `^ 2`. The hardcoded `& 3 ^ 2` is the fingerprint.
3. **Empirically**: pre-1.26-style `*(FName*)(obj+0x18)` no longer works; if it does, the decrypt may have been removed.

### Slot decrypt SIMD pipeline (per slot)
Stages: load 16B → `PSHUFFLELO(0x1E or other imm)` → `ROL32(15-17)` → `PSHUFB(SlotShufMask)` → `PXOR(SlotXorKey)` → extract64 → `ROL64(32)` (FName slots) or skip ROL64 (pointer slots like ClassPrivate).

Recovery:
1. Find any function with `pshuflw`/`pshufb`+`pxor` sequence reading from `obj+0x20+slot*0x20`.
2. Check the IDA-decompiled slot decrypt (see `UFunction_Destructor_20260428` at 0x3411E0 — uses slot decrypt for its name in the destructor error path).

---

## 3. UStruct / FField / FProperty layout (20260428)

| Struct | Field | Offset | Notes |
|---|---|---:|---|
| UObject | InternalIndex | 0x0C | plain u32 |
| UObject | EncryptedSlots[4] | 0x20 + i*0x20 | slot decrypt input |
| UStruct | SuperStruct | 0xA8 | (was 0xB0 in earlier RE pass — wrong) |
| UStruct | ChildProperties | 0xD0 | FField chain head; mirrored at +0xE8/+0xF0 |
| UStruct | PropertiesSize | 0x118 | u32 |
| FField | VTable | 0x00 | module-range |
| FField | ClassPrivate | 0x20 | FFieldClass* |
| FField | Next | 0x48 | next FField in chain |
| FField | Owner | 0x50 | parent UStruct \| 1 (low-bit tag) |
| FField | NamePrivate | 0x70 | 16B SIMD slot |
| FField | SaltSentinel | 0x78 | constant `0x893BCE4393840650` |
| FField | per-type ptr | 0x88 | FProperty type discriminator (replaces ClassPrivate-keyed map) |
| FProperty | PropertyFlags | 0x98 | u64 |
| FProperty | ElementSize | 0xA0 | u32 |
| FProperty | Offset_Internal | 0xB4 | encrypted; `real = bswap32(stored) ^ 0x34605D14` |
| FProperty | ArrayDim | 0xE0 | u32 |
| FStructProperty | Struct | 0x108 | UScriptStruct* |
| FObjectProperty | PropertyClass | 0x108 | UClass* |
| FInterfaceProperty | InterfaceClass | 0x108 | UClass* |
| FArrayProperty | Inner | 0x110 | FField* |
| FMapProperty | KeyProp | 0x108 | FField* |
| FMapProperty | ValueProp | 0x110 | FField* |
| FSetProperty | ElementProp | 0x108 | FField* |
| FEnumProperty | UnderlyingProp | 0x108 | FField* |
| FEnumProperty | Enum | 0x110 | UEnum* |
| UEnum | Names | 0xA8 | TArray<TPair<FName, int64>> |
| UFunction | NumParms | 0xB0 | u8 |
| UFunction | NextPtr | 0x98 | UField next |
| UFunction | ChildProperties | 0xD0 | param FField chain |
| UFunction | FunctionFlags | 0x120 | u32 |
| UFunction | NativeFunc | 0x148 | void* (x64 prologue) |
| UClass | FuncMap.Pairs.Data | 0x268 | TPair<FName, UFunction*> array |
| UClass | FuncMap.Pairs.Num | 0x270 | u32 |

### Recovering these on a new patch

1. **FField salt sentinel** at +0x78 = `0x893BCE4393840650` is a unique tell. Find any FField in memory; the qword at +0x78 should be this value. Use it to verify FField-shape.
2. **FStructProperty.Struct** at +0x108: live-probe by finding any struct with a known `FVector` field, then read +0x108 on its FField — should resolve to the FVector UScriptStruct.
3. **`FStructProperty_DefaultCtor_20260428`** at 0x45D2D7 has `*(_QWORD *)(v4 + 264) = 0;` — 264 = 0x108 — that's the dead-give-away anchor for the Struct field.
4. **FBoolProperty error string** `"Unsupported FBoolProperty %s size %d."` — the function holding it (`FBoolProperty_UnsupportedSizeError_20260428`) decompiles cleanly to show the FField NamePrivate decrypt pipeline.
5. **FProperty Offset_Internal sentinel**: known-zero offsets store as `0x145D6034` (= `bswap32(0x34605D14)`). Use as ghost-FField guard / offset-XOR-key fingerprint.

---

## 4. Property-type discriminator table (FField+0x88)

Patch 20260428 stores 38 FProperty type globals at fixed RVAs. The discriminator is at `FField+0x88` (was at `+0x20 ClassPrivate` in earlier patches).

```
DE0CF70 FEnumProperty       DE0D050 FField                DE0D0C0 FFieldPathProperty
DE14C30 FProperty           DE14CA0 FArrayProperty        DE14D10 FObjectPropertyBase
DE14D80 FBoolProperty       DE14DF0 FByteProperty         DE14E60 FClassProperty
DE14ED0 FClassPtrProperty   DE14F40 FDelegateProperty     DE14FC0 FInterfaceProperty
DE15030 FLazyObjectProperty DE150A0 FMapProperty          DE15120 FMulticastDelegateProperty
DE15190 FMulticastInlineDelegateProperty                  DE15200 FMulticastSparseDelegateProperty
DE15270 FNameProperty       DE152E0 FNumericProperty      DE15350 FInt8Property
DE153C0 FInt16Property      DE15430 FIntProperty          DE154A0 FInt64Property
DE15510 FUInt16Property     DE15580 FUInt32Property       DE155F0 FUInt64Property
DE15660 FFloatProperty      DE156D0 FDoubleProperty       DE15740 FObjectProperty
DE157C0 FObjectProperty(2)  DE15830 FOptionalProperty     DE15C40 FSetProperty
DE15CB0 FSoftClassProperty  DE15D20 FSoftObjectProperty   DE15DE0 FStrProperty
DE15E50 FStructProperty     DE15ED0 FWeakObjectProperty   DE17200 FTextProperty
```

### Recovering this table on a new patch

The anchor function is `FProperty_RegisterTypeGlobal_20260428` (sub_3E3010 in earlier RE) — its 78 callers each do:
```
lea rcx, <global>      ; the type global pointer
lea rdx, &<wstring>    ; the type name as wide string
call sub_3E3010
```

Recovery steps:
1. Find the registration function: search for any function with 78+ callers, each pattern-matching `lea rcx; lea rdx; call`.
2. Walk those 78 callers; extract the (global_addr, name_wstring) pairs.
3. Output: 38 unique pairs (some functions register in pairs).

---

## 5. GUObjectArray + chunks_manager

### `GUObjectArray` — RVA `0xDE173A0`
The encrypted FUObjectArray global.

Recovery:
1. **Cross-patch signature** (verified in `feedback_signatures.md`):
   ```
   48 8D 0D ? ? ? ? E8 ? ? ? ? C6 05 ? ? ? ? 00 80 3D ? ? ? ? 00 75 ? 80 3D ? ? ? ? 01 0F 85 ? ? 00 00
   ```
   Match site is the first `LEA rcx, [rip+disp]`; target = `ea + 7 + sign_extend(disp32)`.
2. **Xref count** ≈ 113.
3. **Layout fingerprint**: at +0x38 stores `NumActive` plain (u32); at +0x68 stores duplicate; at +0xB0 stores encrypted chunks_manager pointer.

### NumElements (real total)
At `chunks_manager + 0x14`, encrypted. Decrypt: `ROL32(*(u32) ^ 0xC88F6121, 17) ^ 0x4CF4AED0`.

Note: `GUObjectArray + 0x38` only has the *partial* count (~70K-90K active), not the real total (~280K-540K).

### chunks_manager pointer decrypt (Step 1)
```
blob = read 16B from GUObjectArray + 0xB0
shuffled = PSHUFLW(blob, 0x1E)                    // swap w0↔w1, w2↔w3 in low 8B
xored    = shuffled[0..7] XOR qword[0xAD0FE50]    // = 0xC8727080CA112779
chunks_manager = ROL16(xored, 1) per uint16-lane
```

The XOR key at `0xAD0FE50` is the **same** keystream constant used by the FField NamePrivate decrypt — find one, you have the other.

### chunk_table base (Step 2: `ChunkTable_DecryptSIMD_PEB_20260428` @ 0x49AC60)
`vtable[5]` of `*(qword*)(chunks_manager + 0x80)` → returns chunk_table base. The function inlines a SIMD pipeline:
```
ROL16(13) → PSHUFLW(0x8D) → ROL32(10) → XOR(broadcast(PEB + peb_add_const))
```

`peb_add_const` is **read live** from the binary at `RVA_CHUNK_TABLE_DECRYPT_FN + 5` (= `mov eax, imm32` after function entry). On 20260428 the value is `0x647A6348`. **This rotates per binary** — never hardcode.

PEB candidate addresses (Wine): sweep `0x7FF00000..0x7FFE0000` step `0x10000`, then `0x00010000..0x00200000`. Validate each by reading slot[0] of chunk[0] and confirming UObject vtable in module range.

### Chunk layout
- Chunk array stride: **8 bytes** (one qword per chunk)
- Each entry points 8 bytes INTO a chunk's heap allocation (the 8B header at `chunk_ptr - 8` holds capacity = 0x10000 = 65536)
- FUObjectItem stride: **20 bytes** at chunk_ptr + 0
- FUObjectItem layout: `Object @ +0` (qword), `SerialNumber @ +8` (dword), `Flags @ +0xC` (dword)

### Recovery on new patch

1. **GC anchor**: `GC_GatherUnreachable_20260428` (sub_398180) inlines the entire IndexToObject pipeline. Find it via the `0xC8727080CA112779` keystream constant xref, then the SIMD pipeline pattern around it.
2. **String anchor**: search for `"GarbageCollection"` / `"GatherUnreachable"` strings (often present as log strings).
3. **PEB-add const drift**: every patch shifts the immediate at `chunkTableDecryptFn + 5`. Read it live, never bake.
4. **PEB-free fallback**: see `gobjects.h::ProbeChunkTableNoPEB` — sweeps rw heap regions for an array of N consecutive chunk-shaped pointers. Works without solving the SIMD pipeline.

---

## 6. Metaclass vtables

These are the type-singleton vtables that ScanByVtable sweeps the heap for. **All 11 are in this patch's `.rdata` cluster `0xAD6CB80..0xAD8AE70`** — find one, the rest are nearby.

| Kind | RVA | Stride | Heap count (this session) |
|---|---:|---:|---:|
| UScriptStruct | 0xAD6CB80 | 0x130 | ~5779 |
| UClass (native) | 0xAD6D440 | 0x300 | ~4222 |
| UFunction | 0xAD6D980 | 0x200 | ~21802 |
| UEnum | 0xAD6FF30 | 0x130 | ~855 |
| UPackage | 0xAD8AE70 | 0x100 | ~468 |
| UBlueprintGeneratedClass | 0xB527FC0 | 0x490 | ~747 |
| UWidgetBlueprintGeneratedClass | 0xB322870 | 0x5D0 | ~16 |
| USMBlueprintGeneratedClass | 0xC0092B0 | 0x490 | ~31 |
| UAnimBlueprintGeneratedClass | 0xB4D5CC0 | 0x7F0 | ~6 |
| UAngelscriptClass | 0xB8A9180 | 0x340 | ~5713 |
| UAngelscriptStruct | 0xB8B2420 | 0x150 | ~2078 |

### AngelScript function subclasses (24 vtables, all stride 0x200)
Cluster: `0xB8A9A60..0xB8B17A0`. ASFunction has 23 subclasses (per-signature JIT specializations: `_NotThreadSafe`, `_NoParams`, `_FloatExtToDouble`, `_ByteArg`, `_ReferenceArg`, `_ObjectReturn`, `_ByteReturn`, `_JIT`, plus `_JIT` variants of each). All inherit UFunction.

### Recovery on new patch

1. **Cluster anchor**: find any one vtable (e.g. UPackage via the path-leading-`/` decode), then walk the `.rdata` cluster to find siblings. Distinguish by:
   - Number of vtable slots before the next vtable header (vtable size = stride distance / 8 with destructor at slot 0)
   - Constructor pattern at vtable[1] (allocates+initializes the specific Kind struct size)
2. **Live count anchor**: any patch will have hundreds of UClasses, thousands of UScriptStructs, many UFunctions. The Kind with the highest heap-occurrence count is usually UFunction.
3. **String anchor**: per-Kind constructor (e.g. `UClass::UClass`, `UFunction::UFunction`) sometimes has a string for type-name-as-wstring nearby.

---

## 7. UClass FuncMap (TMap<FName, UFunction*>)

| Offset | Field |
|---:|---|
| UClass+0x268 | Pairs.Data (heap ptr) |
| UClass+0x270 | Num (u32) |
| UClass+0x274 | Max (u32) |
| TPair stride | 24 bytes |
| TPair+0x00 | FName (key) |
| TPair+0x08 | UFunction* (value) |
| TPair+0x10 | HashNextId (i32) |
| TPair+0x14 | HashIndex (i32) |

Anchors:
- `UClass_AddFunctions_DecryptName_TMap_20260428` (sub_35E730) — primary writer
- `UClass_Destructor_FreeMaps_20260428` (sub_3665FC) — frees the 3 TMaps

Recovery: find any UClass instance live, read +0x268: should be a heap pointer. Read +0x270: should be ≤ a few hundred (small u32). Read pairs at stride 24; values at +8 should be UFunction* (vtable in module range).

---

## 8. Algorithmic invariants (these survive even when EVERYTHING shifts)

These are facts about the encryption that don't depend on RVAs. If the binary's symbol table is gone and every offset has changed, you can still recover by:

1. **The slot table is ALWAYS at obj+0x20, stride 0x20, 4 slots**. This stayed constant 1.26.x → 20260428.
2. **The slot decrypt pipeline ALWAYS uses PSHUFB + ROL32 + XOR + optional ROL64**. Specific masks/ROL counts/XOR keys vary; the SHAPE doesn't.
3. **CompIndex is ALWAYS lo32 of the final 64-bit decrypted slot value**.
4. **FNamePool entries ALWAYS have a 16-bit length-encoded header** (different bit layouts across patches).
5. **FNV-32 and FNV-64 primes are CONSTANTS** (`0x01000193`, `0x100000001B3`).
6. **FUObjectItem is ALWAYS 20 bytes** (`Object @ +0, SerialNumber @ +8, Flags @ +0xC`).
7. **Module base on Wine memfd is ALWAYS `0x140000000`** (PE convention; Wine respects it).

---

## 9. Patch-day playbook (when 20260428 → 20260XYZ breaks the dumper)

In order:

1. **Run the dumper. Read the FIRST error.**
   - "GUObjectArray decrypt failed" → §5 chunks_manager pipeline / xor key drift
   - "FName decode 0% success" → §1 GNamePool_Base or §2 slot decrypt drift
   - "FField salt mismatch" → §3 sentinel drift (rare; usually means pipeline shift, not just RVA)
   - "Pass-N classification 0%" → §6 metaclass vtables shifted

2. **Verify the salt sentinel is alive**: `0x893BCE4393840650` xref count > 0 in the binary. If zero, the salt rotated and §3 needs full re-RE.

3. **Re-anchor the FField NamePrivate XOR const**: search the binary for `0xC8727080CA112779` byte sequence. Every site that uses it = NamePrivate decrypt. This is **the same constant used by chunks_manager pipeline**. Find one, fix both at once.

4. **Walk RVA shifts via xref-count fingerprints**:
   - `FName_SlotShufMask` should have ~16K xrefs (highest-xref data in the binary)
   - `GUObjectArray` should have ~113 xrefs
   - `FName_KeyTable` should have ~66 xrefs
   - If xref counts roughly match expected, the role hasn't changed; just record the new RVA.

5. **Cross-validate against C# reference** at `REFERENCE_FName_20260428.h` — the user-provided ground-truth pipeline for FName decrypt.

6. **For the chunks_manager peb-add const drift**: the 4-byte immediate at `<chunk_table_decrypt_fn> + 5` is **always a `mov eax, imm32`**. Read it live; don't hardcode.

7. **Confirm `m_knownTypeVtables` in `gobjects.h::InitPatch20260428` still resolves**: if any vtable RVA returns 0 hits, find the new RVA via the cluster anchor (§6).

---

## 10. Primary references

| File | Purpose |
|---|---|
| `arc_decrypt.h` | All offsets + scalar constants for current patch |
| `fname_decrypt.h` | Slot decrypt + FNamePool resolver (full pipeline) |
| `gobjects.h` | GUObjectArray walker + chunks_manager + ScanByVtable |
| `sdk_generator.h` | Classification (Path A/B/C, Pass 1-5) + emit |
| `REFERENCE_FName_20260428.h` | C# ground-truth FName pipeline (cross-validation) |
| `tools/fname_pipeline.py` | Pure-Python live decoder (faster iteration than C++ rebuild cycle) |
| `tools/memreader.py` | Live `/dev/memreader` bindings |
| `tools/upackage_scan.py` | Heap-wide UPackage scanner |
| `tools/uss_pool_hits_20260428.txt` | Test fixture: 6013 UScriptStruct addresses (golden output) |
| Memory: `feedback_20260428_layouts.md` | Latest patch state + all live findings |

---

## 11. IDA renames committed to instance `msmz` (binary 20260428)

Functions: 19 renamed (chunks_manager pipeline, FStructProperty ctors, UClass FuncMap helpers, ASFunction ctors, etc.)
Vtables: 11 metaclass vtables + 24 ASFunction subclass vtables = 35 renamed
Constants: 13 RVA constants renamed (XOR keys, shuffle masks, GNamePool base, KeyTable, etc.)

**Total: 67 renames, all suffixed `_20260428` so future patches can carry forward without colliding.** Re-apply via `mcp__ida-multi-mcp__rename` batch — full rename list available in chat history (last batch was applied 2026-04-29).
