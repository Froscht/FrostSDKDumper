# FrostSDKDumper — Master Reverse-Engineering Reference (Steam / Wine)

> **Scope:** Arc Raiders **Steam** build only. The historical Xbox notes have been dropped — no recent work touched that binary.
> **Current target patch:** `20260421` (binary: `Arc_Raiders_Binary_20260421_213315.exe`).
> **Previous patch covered:** `20260409` (see §14 for the legacy table).
>
> This file consolidates every MD note, memory entry, and signature set produced for this project. It is organized so that after a future patch you can
>   1. Run the dumper; if it fails, follow §2 (Post-Patch Recovery Playbook).
>   2. Use §3-§10 to match/update each pipeline.
>   3. Lift fresh signatures from §11 via the anchor strings / structural patterns even if exact bytes move.

---

## Table of Contents

1. [Quick Orientation](#1-quick-orientation)
2. [Post-Patch Recovery Playbook](#2-post-patch-recovery-playbook)
3. [Module / Process Layout (Wine)](#3-module--process-layout-wine)
4. [GNamePool — FName Entry Resolution](#4-gnamepool--fname-entry-resolution)
5. [GObjectArray — Canonical Enumeration via vtable[7]](#5-gobjectarray--canonical-enumeration-via-vtable7)
6. [UObject — Slot Decrypt & Hash-Based Slot Selection](#6-uobject--slot-decrypt--hash-based-slot-selection)
7. [UStruct / UClass / UEnum Layout](#7-ustruct--uclass--uenum-layout)
8. [FField / FProperty Chain & Subclass Accessors](#8-ffield--fproperty-chain--subclass-accessors)
9. [FFieldClass Pointer → Type-Name Table](#9-ffieldclass-pointer--type-name-table)
10. [SDK Generator — Heuristics & Dedup Strategy](#10-sdk-generator--heuristics--dedup-strategy)
11. [Signatures (Patch 20260421)](#11-signatures-patch-20260421)
12. [Investigation Methodology — How the Chains Were Found](#12-investigation-methodology--how-the-chains-were-found)
13. [Hard-Won Lessons](#13-hard-won-lessons)
14. [Appendix — Legacy Patch 20260409 Reference](#14-appendix--legacy-patch-20260409-reference)

---

## 1. Quick Orientation

**Tooling**
- **IDA MCP** (instance `6jc0` = MERGED.exe for 20260421).
- **Unicorn Engine** — emulates vtable[7] (GObjectArray chunks getter) with a fake TEB/PEB so we can read the canonical chunk array without matching its SIMD by hand.
- **`libc.process_vm_readv`** — primary live-memory read path (no kernel module required; the optional kernel module in `build_and_run.sh` is skipped when the path contains spaces — Linux Kbuild can't handle them).
- **Target PID finder** — `pgrep -a` for "GameThread", then filters out `CrashReportClient.exe` by scanning `/proc/<pid>/cmdline`. CrashReportClient inherits the GameThread name when the game crashes.

**Current stats (20260421, post-refactor)**
```
Classes: ~14,300+   Structs: ~8,200+   Enums: ~2,700+
Functions: ~36,800  Properties: ~212,000+
Named ratio: ~99%+  Namespace collisions: 0 (final-name dedup)
```

**Key files**
| Path | Role |
|------|------|
| `arc_decrypt.h` | Per-patch constants, struct offsets, Patch20260421 namespace |
| `fname_decrypt.h` | CI → entry → string pipeline |
| `gobjects.h` | GObjectArray discovery + chunk enumeration |
| `sdk_generator.h` | UObject walk, metaclass logic, FField chain, emit |
| `main.cpp` | Unicorn emulation of vtable[7], PID/module discovery |
| `sig_scan.h` | Signature scanning (RVA auto-recovery — Phase 1) |

---

## 2. Post-Patch Recovery Playbook

**Rule of thumb:** on a patch, the *anchors* survive. The *RVAs* and *XOR keys* rotate. Start from anchors, recover RVAs, recompute keys.

### 2.1 Phase-0 (5 minutes, no IDA needed)
1. Update `Arc_Raiders_Binary_<DATE>.exe` filename in CLAUDE.md / dumper args.
2. Run `./build_and_run.sh --sdk`. If it prints *any* metaclass counts, 90% of the plumbing still works — skip to step 2.3 (key rotation).
3. If it prints 0 classes, likely the FName pipeline broke — go to §4.

### 2.2 Phase-1 (IDA, ~30 min) — Recover RVAs from strings
Open the new binary in IDA (create a new instance, not the old one). Then:

| Anchor string | Function it lands in | What it gives you |
|---------------|----------------------|-------------------|
| `.\Runtime/CoreUObject/Private/UObject/Class.cpp` | `UStruct_Link` (~0x33E480 in 20260421) | UStruct layout, property-linking code |
| `.\Runtime/CoreUObject/Private/UObject/Obj.cpp` | UObject ctors / static init | Everything involving a raw UObject ptr |
| `UObjectHash.cpp` | `UObj_SlotAccess` (legacy name) | Sentinel, FNV, slot-pipeline constants |
| `GetTransientPackage` | GWorld/GEngine statics area | Good starting point for package globals |
| `BoolProperty`, `StructProperty`, `ObjectProperty`, `LazyObjectProperty`, `SoftObjectProperty`, `AssetObjectProperty` | `GNamePool_InitPropertyTypeNames` call graph | FFieldClass ptr map extraction (§9) |

**From `UStruct_Link`:** you see every UProperty/FField offset referenced — verify Children (+0xD0), ChildProperties (+0xE0), PropertiesSize (+0x118).

### 2.3 Phase-2 (IDA, ~1h) — Rotate keys
Follow §4 (FName pipeline), §6 (UObject slot), §8 (FField decrypt), extracting each constant from its identifying instruction pattern (see individual sections). The pipeline *shape* rarely changes between patches — only constants and offsets rotate.

### 2.4 Phase-3 (~30 min) — FFieldClass pointer map rebuild
When FFieldClass pointers rotate, the 36 hard-coded entries in `SeedHardcodedFClassMap_20260421` break. Rebuild:
1. Find `GNamePool_InitPropertyTypeNames` (20260421: RVA 0x230440) via the `BoolProperty` / `ObjectProperty` string xrefs.
2. The function does 36 `GetPropertyTypeFNameHandle` calls followed by `FField_RegisterClass`. Each call resolves a name and stores a FFieldClass pointer. Dump that list.

### 2.5 Phase-4 — Validate
Run `./build_and_run.sh --sdk --only NameTest,ClassTest,FewSamples` (if you add such a flag; otherwise run full and look at early output). Expect:
- ≥ 500k UObjects discovered (canonical chunks — matches live process).
- ≥ 14k classes. If closer to 2k → Pass-B scan-gap was over-tightened; see §13.
- Named ratio ≥ 99%. If closer to 89% → `DecryptFFieldNameCI` broke; see §13.

---

## 3. Module / Process Layout (Wine)

- **Module base on Wine** = `0x140000000` (all Proton builds, since the PE loads via `memfd_create`).
- **Fake TEB for Unicorn** = `0x7FFFFFFE0000`.
- **Fake PEB** = `0x7FFD0000` (pointed to by TEB+0x60).
- **PID finder:**
  ```c
  pgrep -a "GameThread" | filter by cmdline contains "Arc_Raiders"
  // Drop PIDs whose cmdline contains "CrashReportClient.exe"
  ```
  Without the CrashReportClient filter, the dumper will attach to the crash reporter after a game crash and read garbage.

---

## 4. GNamePool — FName Entry Resolution

### 4.1 FName handle (patch 20260421)
FName is a 64-bit encrypted handle stored in UObject/FField name slots:
```
decoded = bswap64(handle ^ 0x59B07C3D00000000)
entry_ptr = decoded  (points directly to FNameEntry, no CI lookup needed)
```

> This replaces the 20260409 flow where FName was a 32-bit *CompIndex* (CI) that had to be fed through a 3-level SIMD decode, then FNV-32 slot, then FNV-64 chain walk. **For 20260421, prefer the handle path when available.** The 3-level CI path still exists for some callers (see 4.3).

### 4.2 GNamePool structure (verified 20260414+)
```
GNamePool_Base        = RVA 0xDB0FE00
+0xC8   chunks_array  (stride 0x40, each element contains):
  +0xD0  heap-mapped encrypted chunk ptr
  +0xD8  module-cached chunk ptr  ← use this; partially valid but usable
```
Don't try to read `+0xD0` directly — it's SIMD-encrypted. `+0xD8` is the module cache which the game itself populates in plaintext; it's partial but good enough for dump purposes.

### 4.3 CI → Entry (legacy path, still present)
If a future patch removes the 64-bit handle path, fall back to `ResolveNamePtrFull_Core_CIToEntry` (RVA 0x242FC0 in 20260421). This is the 3-level SIMD decode + FNV-32 slot + FNV-64 chain. Full pipeline in §14.

### 4.4 Entry → String (20260421)
```
struct FNameEntry {
    uint16 header;       // length encoding, see below
    union {
      uchar  ansi[];     // (header & 0x100) == 0
      ushort wide[];     // (header & 0x100) == 1
    };
};

// Length (20260421):
length = (hdr & 3) | ((hdr >> 5) & 0x3FC);

// Key schedule (narrow, 20260421):
key = length + ??? (TBD — matches narrow-key init in prior patch shape)
str_offset_in_table = 52 + (key & 0x3F)    // +52, was +36 in 20260409
key_step = +7 per char, key_bias = -17564  (per pair: +14 -> per bias)
```
Key table at RVA `0xDA547F4` (uint16[256]).

### 4.5 FField name slot — "FFieldName" pipeline (patch 20260421)
FField's NamePrivate at `+0x60` is decrypted via `DecryptFFieldNameCI`:
```
load 8B from FField+0x60
  → PSHUFLW(0x1E)
  → XOR(m_fFieldXorConst)     ; xmmword @ RVA 0xAD15750
  → ROL16(1)
  → ROL64(32)
  → extract lo32 = CI          ; feeds Entry pipeline
```
The `m_fFieldXorConst` first 8 bytes are `38 BA 6F 75 E8 89 57 36`.

---

## 5. GObjectArray — Canonical Enumeration via vtable[7]

### 5.1 The discovery
Patch 20260414 moved the authoritative chunk array out of `GUObjectArray->Items` (encrypted xmmword at +0x30). Instead, the code dispatches through **vtable[7]** of a global "UObject store" object, which internally returns a pointer to a 65536-slot array of 20-byte UObject slots.

### 5.2 Implementation
- **Don't match the SIMD by hand.** `vtable[7]` is 24 inline SIMD instructions per variant with rotating PSHUFB/PXOR keys — an opcode signature breaks on every patch.
- **Use Unicorn Engine.** `SDKDumper::TryInitViaVtable7` (main.cpp) emulates the function:
  - Load the target vtable[7] function bytes (via `process_vm_readv`).
  - Set up fake TEB at `0x7FFFFFFE0000`, fake PEB at `0x7FFD0000`.
  - Initialize `rcx` with the global UObject-store pointer (first arg).
  - Emulate until `ret`.
  - Read `xmm0.lo64` — that's the canonical `chunks_array` base.
- **Chunk layout:** each chunk = 65536 entries, each entry = 20 bytes (stride 0x14). Pointer at `chunk+0` = UObject*.

### 5.3 Fallback (structural scan)
If Unicorn emulation fails (e.g., hit an instruction not in the whitelist), fall back to `StructuralScanFUObjectItems` — two-pass:
1. **Pass A:** tight (MIN_RUN=500, MAX_GAP=0) — finds the main chunk cleanly.
2. **Pass B:** loose (MIN_RUN=32, MAX_GAP=64) — catches fragmented regions. **Critical:** keep MAX_GAP=64 in Pass B; setting it to 0 drops discovery to zero.
3. **Revalidate vtables in the emission loop**, not just during scan — prevents noise from fragmented regions.

### 5.4 Key constants (20260421)
| Symbol | Value |
|--------|-------|
| `RVA_GOBJECT_ARRAY_BASE` | `0xDDCB420` |
| vtable[7] slot offset | `+0x38` from vtable base |
| Chunk stride | `0x14` (20 bytes per slot) |
| Chunk size | `65536` items |

---

## 6. UObject — Slot Decrypt & Hash-Based Slot Selection

### 6.1 Layout (patch 20260421)
```
UObject {
  +0x00  VTable
  +0x0C  InternalIndex     (plain uint32)
  +0x20  Slot[0..3]        (16 bytes each, encrypted)
  +0x40  …
}
```
Four 16-byte slots hold: Name (FName handle), Class (UClass*), Outer (UObject*), (and a fourth used for miscellany).

### 6.2 Slot decrypt pipeline
```
load 16B from UObject + 0x20 + slot*16
  → PSHUFB(xmmword_AD128C0)     ; {05 03 01 04 02 07 00 06 ...}
  → ROL32(32-bit, NOT 64-bit!)  ; PSLLD/PSRLD — this is the recurring pitfall
  → XOR(xmmword_AD128D0)         ; {09 43 BD C8 4B 4B BC FF ...}
  → PSHUFLW(imm)
  → extract lo64
```
> **DO NOT use PSLLQ/PSRLQ.** The slot rotate is 32-bit. Using 64-bit ROL gives plausible-looking garbage.

### 6.3 Hash-based slot selection (Agent α finding — discovered but not yet wired in)
The game chooses *which* slot holds Name/Class/Outer via a hash of the UObject vtable pointer:
```
hash  = FNV32(bytes_of(obj_vtable_ptr), prime=0x01000193, init=k_add)
name_slot  = (hash & 3) ^ 2
outer_slot = (hash + 1) & 3
class_slot = (hash & 3)              // inferred
```
**Current dumper** uses a 3-tier heuristic `GetCompIndex` that ranks plausibility. This recovers most objects but leaves ~969 `Class_0x...` fallbacks. **TODO:** wire the hash formula into `GetCompIndex` / `GetClassPrivate` / `GetOuterPtr` to eliminate the remaining fallbacks.

### 6.4 Slot-decrypt constants (20260421)
| Constant | Value / Location |
|----------|------------------|
| Slot PSHUFB mask | `xmmword_AD128C0`: `05 03 01 04 02 07 00 06 ...` |
| Slot XOR const | `xmmword_AD128D0`: `09 43 BD C8 4B 4B BC FF ...` |
| FNV32 Prime | `0x01000193` (universal) |
| FNV32 K (20260421) | `0xCA3F9BE2` (NOT `0xCA3F5962` — mind the hex conversion of negative int literals) |

---

## 7. UStruct / UClass / UEnum Layout

### 7.1 UStruct (patch 20260421)
| Field | Offset | Notes |
|-------|--------|-------|
| SuperStruct | `+0xB0` | plain UStruct* |
| Children (UField chain) | `+0xD0` | legacy UProperty chain |
| ChildProperties (FField chain) | `+0xE0` | **new FField chain — primary source** |
| PropertiesSize | `+0x118` | uint32 |

### 7.2 UEnum (verified live on 3 enums)
| Field | Offset | Notes |
|-------|--------|-------|
| CppType | `+0xA0` | `FString` (TArray<wchar_t>) — e.g. `"EPixelFormat"` |
| Names | `+0xB0` | `TArray<TPair<FName,int64>>` (16-byte entries) |

### 7.3 UEnum metaclass whitelist (verified — live process)
`Enum` (1524) + `UserDefinedEnum` (617) cover **all** UEnum instances in the live process. No other strings ending in "Enum" correspond to real UEnum metaclasses. The entries `VerseEnum` / `AngelscriptEnum` / `ASEnum` previously kept in the whitelist are dead code — safe to remove, harmless to keep.

> **Bug flagged** (not yet patched): `sdk_generator.h:1374` uses `names_cnt == names_max` — UE's TArray over-allocates (a UDE can have Num=5, Max=24). Should be `names_cnt <= names_max`. Only affects the heuristic-enum fallback path.

---

## 8. FField / FProperty Chain & Subclass Accessors

### 8.1 FField base layout (patch 20260421)
| Field | Offset | Notes |
|-------|--------|-------|
| VTable | `+0x00` | → FFieldClass* via FFieldClass-of-FField lookup table |
| ClassPrivate | `+0x30` | FFieldClass* (plain) |
| Next | `+0x40` | FField* (chain — walk ChildProperties → Next) |
| NamePrivate | `+0x60` | encrypted (see §4.5) |
| ArrayDim | `+0xA8` | uint32 |
| ElementSize | `+0xAC` | uint32 |
| Offset_Internal | `+0xC0` | **encrypted: `bswap32(stored) ^ 0x59B8C401`** |

> **CRITICAL:** the decrypt order is `bswap32(stored) XOR key`, NOT `bswap32(stored XOR key)`. Early runs applied XOR first and got all offsets looking like `0x1484552xxx`.

### 8.2 Subclass sub-property offsets (patch 20260421 — verified live, 2026-04-22)
**All moved from +0x130/+0x138 (old) to +0xE8/+0xF0 (new).** The FProperty base shrank 0x48 bytes, so every subclass field shifted:

| FProperty subclass | Field | Offset | Type |
|---|---|---|---|
| `FArrayProperty` | Inner | `+0xF0` | FField* |
| `FMapProperty` | KeyProp | `+0xE8` | FField* |
| `FMapProperty` | ValueProp | `+0xF0` | FField* |
| `FSetProperty` | ElementProp | `+0xE8` | FField* |
| `FStructProperty` | Struct | `+0xE8` | UStruct* |
| `FObjectProperty` | PropertyClass | `+0xE8` | UClass* |
| `FEnumProperty` | UnderlyingProp | `+0xE8` | FField* |
| `FEnumProperty` | Enum | `+0xF0` | UEnum* |
| `FByteProperty` | Enum | `+0xE8` | UEnum* |
| `FInterfaceProperty` | InterfaceClass | `+0xE8` | (inferred) |
| `FWeakObjectProperty` | PropertyClass | `+0xE8` | UClass* |
| `FSoftObjectProperty` | PropertyClass | `+0xE8` | UClass* |
| `FDelegateProperty` | SignatureFunction | `+0xE8` | UFunction* |
| `FClassProperty` | MetaClass | **unconfirmed** | probably `+0xF0` — probe live |
| `FSoftClassProperty` | MetaClass | **unconfirmed** | probe live |

**Discovery method:** decompiled each subclass's `LinkInternal` (at vtable[+0xA8], index 21) in IDA, read the member accesses (`a1+232` / `a1+240`), cross-validated with `AddReferencedObjects` and `CopyFrom`.

### 8.3 FField chain scanning — "all offsets" rule
**Don't assume the FField chain head is at a single fixed offset on the parent struct.** Probe **all** offsets 0x80-0x140 on UStruct for plausible FField chain heads. Validate by `ClassPrivate != NULL`, `Next sane or NULL`, `NamePrivate looks encrypted`.

### 8.4 Ghost-FField filter (in `sdk_generator.h`)
Break chain walk when any of:
- `ClassPrivate == NULL` or points outside the module
- Slot is zero AND Offset_Internal is sentinel
- `chunk_off > 0x6A0000` (out of plausible chunk range)

This removed ~10k `Prop_CI<n>` fallback names in 20260421.

---

## 9. FFieldClass Pointer → Type-Name Table

`SeedHardcodedFClassMap_20260421` in `sdk_generator.h` hard-codes 36 FFieldClass pointer values. These come from `GNamePool_InitPropertyTypeNames` (RVA `0x230440` in 20260421) which registers all property types in one go.

**If these pointers rotate on a patch:**
1. Locate `GNamePool_InitPropertyTypeNames` via the signature in §11.1 (`mov eax, 0x10B8; call __alloca_probe`).
2. In the decompilation, each `GetPropertyTypeFNameHandle(..., "TypeName")` call is followed by a write to a FFieldClass global.
3. Dump the 36 `(ptr, name)` pairs and update the hardcoded map.

**Names registered (as a sanity check):** `BoolProperty`, `ObjectProperty`, `StructProperty`, `LazyObjectProperty`, `SoftObjectProperty`, `AssetObjectProperty`, and ~30 more spanning `Int`, `Float`, `Array`, `Map`, `Set`, `Byte`, `Enum`, `Delegate`, `MulticastInlineDelegate`, `MulticastSparseDelegate`, `Text`, `Str`, `Name`, `WeakObject`, `Interface`, `Class`, `SoftClass`, `Optional`, etc.

---

## 10. SDK Generator — Heuristics & Dedup Strategy

### 10.1 Metaclass detection
- **Collect ALL metaclass names**, not just the first-seen. Some UObjects share metaclass names — filtering to first-only dropped detection of 14k+ real types in early runs.
- **Whitelists** (kClassMetaNames, kStructMetaNames, kEnumMetaNames) include the game's Angelscript-tagged variants (e.g., `ASClass`, `ASStruct` when present).
- **CDO-based recovery:** when a class's own name slot fails to decrypt, check for its `Default__<ClassName>` CDO (Class Default Object). The CDO preserves the original class name in its own name slot and recovers the mapping.

### 10.2 Property dedup
**Key on `p.ff_addr`, NOT `p.offset`.** Early runs keyed on offset, but Offset_Internal decrypted to garbage (`0xD63FB02A`) before the bswap-order fix; that made every property dedup to one entry.

### 10.3 Namespace collision dedup
- First attempt keyed `c++` on bare type name → second-order collisions (pre-existing `UpdateScript_1` in the live process collided with a freshly-renamed one).
- **Final approach:** track every *final assigned* name via `unordered_set<string>`. Increment the suffix until the candidate is unused. Robust against any pre-existing names.

---

## 11. Signatures (Patch 20260421)

RVAs assume base-rebase to `0x0`. All signatures verified unique (1 hit) over `.text` `0x1000 – 0xACB4000`, unless a twin case is noted.

### 11.1 FName / FField / FProperty chain (Sig Agent 1)

| Function | RVA | Signature (IDA format) | Notes |
|---|---|---|---|
| `FName_ToString` | `0x24C8130` | `56 57 53 48 81 EC 70 01 00 00 48 89 D7 48 89 CE 48 8B 05 ? ? ? ? 48 31 E0 48 89 84 24 68 01 00 00 49 8B 50 08 49 39 10` | 4-byte wildcard = `__security_cookie` RIP-rel |
| `FNameEntry_AppendNameToString` | `0x22EC20` | `41 56 56 57 53 48 83 EC 28 48 89 D6 48 89 CF 0F B7 19 89 D8 83 E0 03 C1 EB 05 81 E3 FC 03 00 00 09 C3` | Narrow path, header-bit extract |
| `FNameEntry_AppendNameToString_WithNumber` | `0x245880` | `41 57 41 56 56 57 53 48 83 EC 20 48 89 D6 48 89 CF 0F B7 19 89 D8 83 E0 03 C1 EB 05 81 E3 FC 03 00 00 09 C3` | Same extractor, extra `41 57` push |
| `FName_Init` | `0x2480E0` | `41 57 41 56 41 55 41 54 56 57 55 53 48 81 EC 88 08 00 00 48 8B 05 ? ? ? ? 48 31 E0 48 89 84 24 80 08 00 00 8B 72 08 48 8B 02 80 7A 0C 01` | 0x888 stack + `cmp byte ptr [rdx+0Ch], 1` tail |
| `FNameEntry_GetPlainNameString` | `0x22AA30` | `56 57 48 83 EC 28 48 89 D6 48 89 CF 0F B7 09 89 CA 83 E2 03 89 C8 C1 E8 05 25 FC 03 00 00 09 D0 44 0F B7 C0 66 85 C9 78 63` | 2 hits — 2nd is wide-char twin at `0x22C600` |
| `GetPropertyTypeFNameHandle` | `0x243A90` | `56 57 48 83 EC 28 89 D7 48 89 CE 80 3D ? ? ? ? 00 75 13 48 8D 0D ? ? ? ? E8 ? ? ? ? C6 05 ? ? ? ? 01 89 F8 48 8D 0D` | Wildcards: init-flag refs, g_GNamePool lea, call rel32 |
| `GNamePool_InitPropertyTypeNames` | `0x230440` | `41 57 41 56 41 55 41 54 56 57 55 53 B8 B8 10 00 00 E8 ? ? ? ? 48 29 C4 0F 29 B4 24 A0 10 00 00 48 89 CE 48 8B 05` | `mov eax,0x10B8; call __alloca_probe` — key anchor |
| `ResolveNamePtrFull_Core_CIToEntry` | `0x242FC0` | `41 56 56 57 53 48 83 EC 38 0F 29 74 24 20 49 89 D6 41 0F B6 00 88 01 41 0F B6 40 01 88 41 01 41 0F B6 40 02 88 41 02` | Byte-by-byte 8-byte copy loop |
| `FField_GetFName_AppendChain` | `0x3DBE00` | `41 57 41 56 41 54 56 57 53 48 81 EC E8 00 00 00 66 0F 7F BC 24 D0 00 00 00 66 0F 7F B4 24 C0 00 00 00 4C 89 C6 48 89 CF 48 8B 05` | Double XMM spill |
| `FProperty_GetNameCPP` | `0x3AFE70` | `41 56 56 57 53 48 81 EC 58 02 00 00 48 89 CF 48 8B 05 ? ? ? ? 48 31 E0 48 89 84 24 50 02 00 00 48 8B 41 30 F2 0F 70 40 20 4B` | `pshuflw xmm0, [rax+0x20], 0x4B` = FName-handle decoder tell |
| `FMapProperty_LinkInternal` | `0x456A40` | `41 56 56 57 53 48 83 EC 28 48 89 D7 48 89 CE 48 8B 99 E8 00 00 00 48 8B 03 48 89 D9 FF 90 A8 00 00 00 4C 8D 73 38` | `[rcx+0xE8]` + vtable `[rax+0xA8]` + `lea r14, [rbx+0x38]` |
| `FProperty_SetupOffset_case2` | `0x440700` | `56 57 48 83 EC 28 48 89 CE 48 8D 79 38 E8 ? ? ? ? 48 89 F9 48 89 C2 E8 ? ? ? ? 48 8B 7E 38 48 83 E7 FE 0F 95 C1 20 C1 80 F9 01` | `lea rdi, [rcx+0x38]` body |
| `FProperty_SetupOffset_case1` | `0x428210` | `56 57 53 48 83 EC 20 48 89 CF 48 8B B1 F0 00 00 00 48 8B 06 48 89 F1 FF 90 A8 00 00 00 48 8D 5E 38` | Uses `[rcx+0xF0]` (case2 uses +0xE8) |
| `FStructProperty_LinkInternal` | `0x3E584A` | `41 56 48 83 EC 60 56 57 48 83 EC 28 48 89 CE 48 8B B9 E8 00 00 00 48 8B 07 48 89 F9 FF 90 A8 00 00 00 48 89 F9 E8 ? ? ? ? 48 8B 86 E8 00 00 00` | 2-stage stack alloc (`sub rsp,0x60` then `sub rsp,0x28`) |
| `FBoolProperty_LinkInternal` | `0x447120` | `41 57 41 56 56 57 55 53 48 83 EC 38 4C 89 C7 48 89 CE 48 8B 05 ? ? ? ? 48 31 E0 48 89 44 24 30 45 85 C9 74 27 48 8D 05` | `test r9d, r9d; jz` — bit-field tell |
| `UStruct_Link` | `0x33E480` | `41 57 41 56 41 55 41 54 56 57 55 53 48 81 EC 98 00 00 00 66 44 0F 7F 84 24 80 00 00 00 66 0F 7F 7C 24 70 66 0F 7F 74 24 60 48 89 D7 48 89 CE 48 8B 05` | Triple XMM6/7/8 spill |
| `FName_CityHash64` | `0xC1960` | `41 57 41 56 41 55 41 54 56 57 55 53 50 49 89 D5 83 FA 20 77 5C 48 B8 4F 40 90 2F 3B 6A E1 9A 41 83 FD 10 0F 87` | `mov rax, 0x9AE16A3B2F90404F` (CityHash kmul) |

**FField subclass `LinkInternal` RVAs (from Agent β):**
| Function | RVA | Inner offset |
|---|---|---|
| `FArrayProperty_LinkInternal` | `0x428210` | Inner at `+0xF0` |
| `FMapProperty_LinkInternal` | `0x456A40` | KeyProp `+0xE8`, ValueProp `+0xF0` |
| `FSetProperty_LinkInternal` | `0x46B880` | ElementProp `+0xE8` |
| `FStructProperty_LinkInternal_Real` | `0x45C6C0` | Struct `+0xE8` |
| `FObjectProperty_LinkInternal` | `0x4417E0` | (trivial; +0xE8 via ctor/ARO) |
| `FEnumProperty_LinkInternal` | `0x3E5850` | UnderlyingProp `+0xE8` |
| `FByteProperty_LinkInternal` | `0x47B4C0` | Enum `+0xE8` |
| `FInterfaceProperty_LinkInternal_Size16` | `0x47B4A0` | |
| `FObjectPropertyBase_LinkInternal_Size8` | `0x45B040` | Weak/Lazy/Name parent |
| `FDelegateProperty_LinkInternal_Size40` | `0x45CC90` | |
| `FObjectProperty_AddReferencedObjects` | `0x4250F0` | Proves PropertyClass `+0xE8` |
| `FEnumProperty_CopyFrom` | `0x367730` | Proves Enum `+0xF0` |

**CPP-type format thunks (useful for type-name resolution):**
| Function | RVA | Formats as |
|---|---|---|
| `FWeakObjectProperty_GetCPPType` | `0x497CE0` | `TWeakObjectPtr<...>` |
| `FSoftObjectProperty_GetCPPType` | `0x47E710` | `TSoftObjectPtr<...>` |
| `FOptionalProperty_GetCPPType` | `0x47EDE0` | `TOptional<...>` |
| `FNameProperty_GetCPPType` | `0x467470` | `FName` |
| `FSoftClassProperty_GetCPPType` | `0x494250` | `TSoftObjectPtr<UObject>` |

### 11.2 UObject / UStruct / GObjectArray chain (Sig Agent 2)

| Function | RVA | Signature | Bytes | Matches |
|---|---|---|---|---|
| `UObject_GetOuter` | `0x23F6690` | `48 8D 41 10 48 89 C2 48 C1 EA 20 C1 C0 13 69 C0 93 01 00 01 05 48 40 A3 48 C1 C0 16 69 C0 93 01 00 01 01 D0 05 48 40 A3 48 C1 C0 13 69 C0 93 01 00 01 05 48 40 A3 48 C1 E8 0A 69 C0 93 01 00 01 8D 90 48 40 03 00 C1 EA 10 31 C2 FF C2 83 E2 03 C1 E2 05 F2 0F 70 44 11 20 B1 66 0F 6F C8 66 0F 72 D1 11 66 0F 72 F0 0F 66 0F EB C1 66 0F 38 00 05 ?? ?? ?? ?? 66 0F EF 05 ?? ?? ?? ?? 66 48 0F 7E C0 C3` | 131 | 2 (1 junk) |
| `UObject_GetFName` | `0x353CD0` | `48 8D 41 10 49 89 C0 49 C1 E8 20 C1 C0 13 69 C0 93 01 00 01 05 48 40 A3 48 C1 C0 16 69 C0 93 01 00 01 44 01 C0 05 48 40 A3 48 C1 C0 13 69 C0 93 01 00 01 05 48 40 A3 48 C1 E8 0A 69 C0 93 01 00 01 44 8D 80 48 40 03 00 41 C1 E8 10 41 31 C0 41 83 E0 03 41 83 F0 02 41 C1 E0 05 F2 42 0F 70 44 01 20 B1` | 99 | 3 (1 canonical + 2 junk/inlined) |
| `UObject_GetFullName` | `0x4225EF0` | `56 48 83 EC 20 48 89 CE 48 89 D1 48 89 F2 45 31 C9 E8 ?? ?? ?? ?? 48 89 F0 48 83 C4 20 5E C3` | 31 | 1 |
| `UObject_GetWorld` | `0x424D460` | `48 8B 01 48 8B 80 E0 01 00 00 48 FF E0 41 57 57 56 48 83 EC 50 4C 89 C6` | 24 | 1 |
| `UObject_GetPathName` | `0x4F3DF0` | `56 57 48 81 EC 48 02 00 00 48 89 D6 48 8B 05 ?? ?? ?? ?? 48 31 E0 48 89 84 24 40 02 00 00 0F 57 C0 0F 11 02` | 36 | 1 |
| `UObject_GetPackage` | `0x4F6EA0` | `56 57 53 48 81 EC B0 00 00 00 44 0F 29 9C 24 A0 00 00 00 44 0F 29 94 24 90 00 00 00 44 0F 29 8C 24 80 00 00 00` | 37 | 1 |
| `UObject_GetPathNameHelper` | `0x513EE0` | `41 57 41 56 41 54 56 57 53 48 83 EC 38 4C 89 C6 48 8B 05 ?? ?? ?? ?? 48 31 E0 48 89 44 24 30 48 39 D1` | 34 | 1 |
| `UObject_GetOutermost` | `0x52C010` | `56 57 53 48 81 EC 80 00 00 00 44 0F 29 44 24 70 0F 29 7C 24 60 0F 29 74 24 50 48 89 CE 48 8B 05 ?? ?? ?? ?? 48 31 E0 48 89 44 24 48 F3 0F 7E 35 ?? ?? ?? ?? F3 0F 7E 3D ?? ?? ?? ?? 45 0F 57 C0 48 8D 7C 24 20 EB 41` | 71 | 1 |
| `UObject_GetFullNameInternal` | `0x529E80` | `41 57 41 56 56 57 53 48 81 EC 50 02 00 00 44 89 CF 4C 89 C3 48 89 D6 49 89 CE 48 8B 05 ?? ?? ?? ??` | 33 | 1 |
| `FChunkedFixedUObjectArray_Init` | `0x4A08F0` | `41 57 41 56 41 55 41 54 56 57 53 48 81 EC B0 00 00 00 66 44 0F 7F 84 24 A0 00 00 00 66 0F 7F BC 24 90 00 00 00 0F 29 B4 24 80 00 00 00 44 89 C3 48 89 CE 48 8B 05 ?? ?? ?? ?? 48 31 E0 8D 8A FF FF 00 00` | 67 | 1 |
| `FChunkedFixedUObjectArray_Decrypt_vt7_varA` | `0x4AF300` | `F3 0F 7E 02 B8 9E A1 25 AD 65 48 03 04 25 60 00 00 00 F2 0F 70 C8 B1 66 0F EF 0D ?? ?? ?? ?? 66 0F 6F C1 66 0F 73 D0 3B 66 0F 73 F1 05 66 0F EB C8` | 49 | 1 |
| `FUObjectArray_FreeUObjectIndex` | `0x4ABBE0` | `41 56 56 57 53 48 81 EC 98 00 00 00 0F 29 B4 24 80 00 00 00 48 89 D7 48 89 CE 48 8B 05 ?? ?? ?? ?? 48 31 E0 48 89 44 24 78 44 8B B2 90 00 00 00 66 0F 6F 81 40 01 00 00 66 0F 6F C8 66 0F 72 D1` | 64 | 1 |
| `FUObjectArray_ShutdownUObjectArray` | `0x4ACD90` | `56 57 53 48 83 EC 20 48 89 CE 48 8D 79 30 48 89 F9 E8 ?? ?? ?? ?? 48 63 5E 08 48 85 DB 7E ?? 48 FF C3` | 34 | 1 |
| `FUObjectArray_AllocateUObjectIndex` | `0x4ADCC0` | `41 57 41 56 41 55 41 54 56 57 55 53 48 81 EC D8 00 00 00 66 44 0F 7F 9C 24 C0 00 00 00 66 44 0F 7F 94 24 B0 00 00 00 66 44 0F 7F 8C 24 A0 00 00 00 66 44 0F 7F 84 24 90 00 00 00` | 59 | 1 |
| `FUObjectArray_AllocateSerialNumber` | `0x4B0D00` | `56 57 53 48 83 EC 70 48 89 CE 48 8B 05 ?? ?? ?? ?? 48 31 E0 48 89 44 24 68 66 0F 6F 81 40 01 00 00 66 0F 6F C8 66 0F 72 D1 09 66 0F 72 F0 17 66 0F EB C1 66 0F 38 00 05` | 56 | 1 |
| `FUObjectArray_AllocateSerialNumberInObjectPtr` | `0x4B1BF0` | `56 57 55 53 48 83 EC 68 48 89 CE 48 8B 05 ?? ?? ?? ?? 48 31 E0 48 89 44 24 60 66 0F 6F 05 ?? ?? ?? ?? 66 0F 6F C8 66 0F 72 D1 09 66 0F 72 F0 17 66 0F EB C1` | 52 | 1 |
| `FUObjectArray__AddUObject` | `0x4B4940` | `41 57 41 56 41 55 41 54 56 57 55 53 48 81 EC 28 01 00 00 66 44 0F 7F 9C 24 10 01 00 00 66 44 0F 7F 94 24 00 01 00 00 66 44 0F 7F 8C 24 F0 00 00 00` | 49 | 1 |
| `Angelscript_RegisterUObject` | `0x425CC30` | `41 56 56 57 53 48 81 EC 48 01 00 00 0F 29 B4 24 30 01 00 00 48 8B 05 ?? ?? ?? ?? 48 31 E0 48 89 84 24 28 01 00 00 0F 57 F6 0F 29 74 24 30 C6 44 24 40 00 0F 11 74 24 48 C6 44 24 58 00 48 8D 05 ?? ?? ?? ?? 48 89 44 24 60 48 8D 74 24 70` | 78 | 1 |

**Globals resolved from these functions (20260421):**

| Name | RVA | Source anchor |
|---|---|---|
| `GChunksManagerEncryptedPtr` | `0xDDCB420` | `movdqa xmm0, cs:...` at 0x4B1C0A inside `AllocateSerialNumberInObjectPtr` |
| `FNV_XorPad_A` (pshufb mask) | `0xAD128C0` | `pshufb xmm1, [rip+disp]` tail of `UObject_GetOuter`/`GetFName` |
| `FNV_XorPad_B` (pxor key) | `0xAD128D0` | `pxor xmm0, [rip+disp]` tail of same |
| String `"UObject"` | `0xB8C1727` | `lea rax, ...` at 0x425CC6D inside `Angelscript_RegisterUObject` |
| `loc_3FDDB50` | `0x3FDDB50` | `call` target — Angelscript `RegisterObjectMethod` thunk |
| `loc_3FC3E30` | `0x3FC3E30` | first `call` in RegisterUObject — Angelscript class-start thunk |

**Highest-leverage anchor: `Angelscript_RegisterUObject` (0x425CC30).** After stack setup it loads literal `"UObject"` and walks a table of `(method_ptr, signature_string)` tuples, each ~52 bytes:
```
lea rdi, <MethodThunk>          ; e.g. AddToRoot
mov [rsp+var_78], rdi
lea rax, aSignatureString       ; e.g. "void AddToRoot()"
mov [rsp+var_88], rax
call loc_3FDDB50                ; RegisterObjectMethod
```
Walk this table once to recover ~20 UObject method names: `AddToRoot`, `RemoveFromRoot`, `GetClass`, `IsA`, `GetFName`, `GetName`, `GetPathName`, `GetFullName`, `GetPackage`, `GetOuter`, `GetOutermost`, `MarkPackageDirty`, `GetWorld`, `IsValid`, …

**Structural fingerprints for next-patch recovery:**
- **Shared FNV1a+pshufb slot-decrypt pipeline:** bytes `69 C0 93 01 00 01 05 48 40 A3 48` appear in every UObject property/outer getter. Slot selectors distinguish: `01 D0` (add edx) = Outer; `44 01 C0` / `41 83 F0 02` = FName.
- **FChunkedFixedUObjectArray vtable decrypt stubs:** each begins `F3 0F 7E 02` (movq xmm0,[rdx]) + unique 32-bit immediate (e.g. `0AD25A19Eh` for vt7_varA). The stride-0x40 table of 37 variants in `.rdata` can be located by scanning 8-byte pointers whose targets match `F3 0F 7E 02 B8 ?? ?? ?? ?? 65 48 03 04 25 60 00 00 00`.
- **GetOuter vs GetFName near-duplicate:** differ only at the mov-arg3 instruction (`48 89 C2` vs `49 89 C0`) and the hash-slot XOR step (none vs `83 F0 02`).

### 11.3 Anchor strings (cross-patch stable)

| String | Addr (20260421) | xrefs | Use |
|---|---|---|---|
| `.\Runtime/CoreUObject/Private/UObject/Class.cpp` | `0xAD1C09E` | 7 (→ UStruct_Link, candidates) | UStruct code recovery |
| `.\Runtime/CoreUObject/Private/UObject/Obj.cpp` | `0xAD390FA` | 8 | UObject ctors, statics |
| `BoolProperty` | `0xACFAC74` | | FFieldClass map anchor |
| `ObjectProperty` | `0xACFAC8F` | | " |
| `StructProperty` | `0xACFACD9` | | " |
| `LazyObjectProperty` | `0xACFAD4C` | | " |
| `SoftObjectProperty` | `0xACFAD5F` | | " |
| `AssetObjectProperty` | `0xAD440F4` | | " |
| `UObjectHash.cpp` | (search) | (legacy) | Still works for UObj_SlotAccess |
| `GetTransientPackage` | (search) | | GWorld/GEngine area |

> **Note:** `FFieldClass: %s` and `FField.cpp` strings are **absent** from 20260421 — logging got stripped/inlined. Class.cpp / Obj.cpp path-strings are now the most reliable anchors.

### 11.4 Data-table anchors (20260421)

| Symbol | RVA | First 8 bytes | Purpose |
|---|---|---|---|
| UObject slot PSHUFB mask | `0xAD128C0` | `05 03 01 04 02 07 00 06` | §6.2 |
| UObject slot XOR const | `0xAD128D0` | `09 43 BD C8 4B 4B BC FF` | §6.2 |
| FField NamePrivate XOR const | `0xAD15750` | `38 BA 6F 75 E8 89 57 36` | §4.5 |
| FFieldClass name XOR const | `0xACF8900` | `9D AF 12 36 28 A6 FC 6D` | §9 |

**Cross-patch trick:** search for each 8-byte XMM half independently. The pair `05 03 01 04 02 07 00 06 ?? ?? ?? ?? ?? ?? ?? ?? 09 43 BD C8 4B 4B BC FF` is a very strong structural fingerprint for the UObject slot pipeline.

### 11.5 Cross-binary signatures (verified 20260421 + 20260428)

These signatures were lifted by diffing the same function's body across `Arc_Raiders_Binary_20260421_213315.exe` (instance `zqxp`) and `pioneer_steam_1.26.x-CL-1169740_2026_04_29__23_00_83pct.exe` (instance `qf91`), then choosing an interior anchor that survived patch-day shape changes. Each one returns exactly one match on each binary.

| Function | 20260421 RVA | 20260428 RVA | Cross-binary signature | Anchor type / notes |
|---|---|---|---|---|
| `GNamePool_InitPropertyTypeNames` | `0x230440` | `0x241D20` | `41 57 41 56 41 55 41 54 56 57 55 53 B8 ?? 10 00 00 E8 ?? ?? ?? ?? 48 29 C4 0F 29 B4 24 ?? ?? 00 00 48 89 CE 48 8B 05` | Function start. Wildcards: stack-alloc size byte (0x10B8 → 0x1088), alloca-call rel32, XMM save offset (0xA0 → 0x70). Replaces the brittle `mov eax,0x10B8` anchor in §11.1. |
| `FName_CityHash64` | `0xC1960` (sig hits +21) | `0xf1540` (sig hits +25) | `48 B8 4F 40 90 2F 3B 6A E1 9A 41 83 FD 10 0F 87` | Body anchor — the CityHash kmul `mov rax, 0x9AE16A3B2F90404F` immediately followed by `cmp r13d, 0x10; ja near` size check. Caller must walk back to nearest preceding `41 57 41 56 41 55 41 54` 12-push prologue to find function start. |
| `FStructProperty_LinkInternal_Real` | `0x45C6C0` (sig hits +38) | `0x495415` (sig hits +49) | `4C 8B 02 48 89 D1 48 89 C2 41 FF 90 98 01 00 00` | Body anchor — `mov r8, [rdx]; mov rcx, rdx; mov rdx, rax; call qword [r8+0x198]` vtable dispatch. Walk back to function start. **20260428 reads `[rcx+0x108]` instead of `[rcx+0xE8]` for `Struct` field — see `feedback_fstruct_offset_20260428.md`.** |

**Functions where the original §11 sig dies on 20260428 and no cross-binary byte-sig is feasible** (shape change too large — needs xref-from-string anchor or RE work):
- `FNameEntry_AppendNameToString` / `_WithNumber` / `GetPlainNameString` — header decrypt is now LCG-stateful (per `feedback_20260428_breakdown.md`); the `(hdr & 3) | ((hdr >> 5) & 0x3FC)` extractor pattern is gone.
- `FProperty_GetNameCPP` — anchor `pshuflw xmm0, [rax+0x20], 0x4B` doesn't exist; new slot decrypt uses mask `01 06 00 04 07 03 02 05 → ROL32(17)`.
- `FProperty_SetupOffset_case1` / `case2`, `FBoolProperty_LinkInternal`, `FMapProperty_LinkInternal` — struct-field offsets and vtable indices rotated together.
- `ResolveNamePtrFull_Core_CIToEntry` — resolver was rewritten as LCG; no equivalent standalone function.
- All `FUObjectArray_*` and `FChunkedFixedUObjectArray_*` — internal struct offsets `+0xD8`/`+0xDC`/`+0xE0` rotated; vt7 magic constant is per-variant. `F3 0F 7E 02 B8 ?? ?? ?? ?? 65 48 03 04 25 60 00 00 00` still hits 90+ vt7 variants — Unicorn emulation in `main.cpp` is the right answer here, not a byte sig.
- `UObject_GetOuter` / `GetFName` / `GetWorld` / `GetPackage` / `GetPathNameHelper` — FNV+PSHUFB pipelines reshaped; vtable indices moved.
- `FName_Init`, `UStruct_Link` — calling convention / arg count changed (`UStruct_Link` now takes 4 args via 4 register saves where 20260421 took 2).

**Dumper relevance:** none of the §11.5 functions are read at runtime by the dumper today (`grep` shows `RVA_FNAME_CITYHASH64` is defined in `arc_decrypt.h` but never read). They're RE-time anchors used to recover other constants and offsets when patches break the pipeline. Keeping them patch-resilient saves ~1h of IDA pivoting per patch.

---

## 12. Investigation Methodology — How the Chains Were Found

A walkthrough of how each pipeline was reverse-engineered. Use this as a template when a future patch breaks something.

### 12.1 FName handle (20260421) — "bswap64 XOR" was a hunch that verified
**Symptom after patch:** every name slot produced obviously-wrong CIs outside the valid pool range, but the top byte looked like `0x3D 7C B0 59` — looked byteswapped.
**Method:**
1. Read a few live UObject name slots alongside known names (GNamePool walks).
2. Tried `bswap64(slot)` → still garbage.
3. Tried `bswap64(slot ^ CONSTANT)` for common sentinels → `0x59B07C3D00000000` produced valid entry pointers on every sample.
4. Verified against 20 distinct UObjects whose names were independently known.

**Lesson:** when a decrypted value's MSBs look like a known sentinel, XOR with sentinel-shifted-left before bswap is the first thing to try.

### 12.2 vtable[7] is NOT VMProtected
**Symptom:** the bytes at vtable[7] start with `65 48 03 04 25 60 00 00 00` — which at first glance looked like VMProtect dispatch.
**Actually:** that's a *single* `add rax, gs:[0x60]` — a normal PEB load. Reading the whole function reveals 24 inline SIMD instructions per variant. We solved this by emulating with Unicorn (see §5.2) rather than matching bytes.

**Lesson:** don't pattern-match the first 9 bytes and call it VMP. Decompile first, even briefly.

### 12.3 Finding FField offsets +0xE8/+0xF0 (patch 20260421)
**Symptom after patch:** `FArrayProperty::Inner` at the old +0x130 gave NULL or junk pointers.
**Method (Agent β):**
1. In IDA, locate `FArrayProperty_LinkInternal` by virtue of vtable[+0xA8] (LinkInternal is always at vtable index 21 across FProperty subclasses).
2. Decompile — the function reads `a1+240` into a FField*. 240 = `0xF0`.
3. Cross-check with `AddReferencedObjects` (reads the same offset, since it has to walk the sub-property for GC).
4. Cross-check with `CopyFrom` on `FEnumProperty` (reads both +0xE8 and +0xF0).
5. Live-verify: read `FField vtable [0xAD1C570+0xA8]` on the running process — matches IDA byte-for-byte.

**Lesson:** **vtable indices are stable across patches even when offsets rotate.** When offsets move, vtable[+0xA8] still points to LinkInternal, and decompiling that recovers the new offsets.

### 12.4 Hash-based slot selection (Agent α finding)
**Symptom:** 3-tier heuristic recovered most objects but failed on ~969 (showed as `Class_0x...`).
**Method:**
1. Pick a known-failing object (user showed `BP_SocketContainer`).
2. Read its 4 slots raw.
3. Brute-force: which slot permutation, if fed to the decrypt pipeline, produces a pointer into a known UClass region?
4. Observation: the "correct" slot index correlated with the UObject's vtable pointer low bits.
5. Hypothesis: `hash = FNV32(vtable_ptr)`; `name_slot = (hash & 3) ^ 2`; `outer_slot = (hash + 1) & 3`.
6. Tested on 50 more objects → 100% match.

**Status:** discovered but not yet wired in. Current heuristic is close enough that the dumper still emits 212k+ properties, so this is "nice-to-have" cleanup.

### 12.5 Offset_Internal decrypt order
**Symptom:** all properties appeared at offsets like `0x1484552xxx` — absurd.
**Method:**
1. Expected offsets are small (0x10, 0x20, 0x100, 0x200 range).
2. `bswap32(stored_value)` alone → reasonable-looking small numbers but still wrong.
3. Tried applying XOR *before* bswap vs *after* bswap → "after" (`bswap32(stored) ^ key`) gave valid offsets matching known structs.

**Lesson:** XOR-vs-bswap order matters. Always try both.

### 12.6 FFieldClass pointer → type-name map
**Method:**
1. Find `GNamePool_InitPropertyTypeNames` via the `mov eax, 0x10B8; call __alloca_probe` fingerprint.
2. Decompile — it's a sequence of `RegisterFieldClass(name_hash, &g_FFieldClass_XYZ)` calls.
3. Extract 36 `(ptr, name)` pairs.
4. Validated against live FField->ClassPrivate reads on a few properties of each type.

**Cross-patch strategy:** the *count* (36) is stable but pointer addresses rotate. Re-dump from `GNamePool_InitPropertyTypeNames` each patch.

---

## 13. Hard-Won Lessons

**Lesson 1: Opcode signatures break on every patch.** Use string refs + structural patterns (prologue shape, stack size, constant immediates, FNV prime) — these survive.

**Lesson 2: vtable[4] slot decrypt uses PSRLD/PSLLD, NOT PSRLQ/PSLLQ.** 32-bit rotate, not 64-bit. Getting this wrong produces plausible-looking-garbage results.

**Lesson 3: Scan ALL offsets 0x80-0x140 for FField chain heads.** Early versions hard-coded a single offset and missed ~half the properties.

**Lesson 4: Collect ALL metaclass names, not just first-seen.** Multiple UObjects share metaclass names; first-only filtering dropped 14k+ types.

**Lesson 5: Keep MAX_GAP=64 in Pass B of the structural scan.** Setting it to 0 drops class discovery to zero. Re-validate vtables in the emission loop to filter noise, not in the scan.

**Lesson 6: Dedup properties by `ff_addr`, NOT `offset`.** When Offset_Internal decrypt is broken (or before it's verified), every property has the same garbage offset and gets collapsed to one.

**Lesson 7: Namespace collision dedup must track FINAL names.** Pre-existing names in the game's own class list cause second-order collisions if you dedup by bare-name counter.

**Lesson 8: GNAMES chunks at +0xD8 (module cache), NOT +0xD0 (encrypted heap).** The +0xD8 cache is partial but plaintext and good enough for dumping.

**Lesson 9: Emulator must accept ANY GP-reg memory form as input_data.** Early Unicorn whitelist only accepted `[rdx]` — led to a constant-output bug when the compiler scheduled the load through `[rcx]` instead.

**Lesson 10: CrashReportClient.exe inherits the "GameThread" thread name** and has `PioneerGame` in its cmdline, so `pgrep GameThread` can match it when the game crashes. Always filter by `/proc/<pid>/cmdline`.

**Lesson 11: Negative int-literal hex conversion is easy to get wrong.** `-901800990` as u32 is `0xCA3F9BE2`, **not** `0xCA3F5962` (arithmetic slip). Always verify via `hex((-N) & 0xFFFFFFFF)` in Python.

**Lesson 12: Chain probing must re-probe per-session.** vtable[5] chunk-ptr emulation bytes can shift within a patch if the loader relocates; don't cache across runs.

**Lesson 13: FFieldClass ptr map must re-bake after every patch.** The 36 pointers rotate 100%; recover from `GNamePool_InitPropertyTypeNames`.

**Lesson 14: CDO (`Default__X`) preserves the class name** when the class's own name slot fails. Use it as a recovery hint for "Class_0x..." entries.

---

## 14. Appendix — Legacy Patch 20260409 Reference

These sections describe the *previous* patch's pipelines. Kept here because many structural patterns persist, and a diff between 20260409 and 20260421 is instructive.

### 14.1 UObj_SlotAccess (20260409)
- RVA: `0x4E8610`, size `0x825`
- Pipeline: `ROL64(45) → PSHUFLW(0x1E) → extract lo64 → XOR(sentinel) → ROL64(32)`
- Sentinel: `0x0B982F16865A5F21`
- FNV Add: `0x295812B1`

### 14.2 GObj Decrypt (20260409)
- RVA: `0x2D0784`
- Pipeline (NO PXOR step): `PSHUFB → ROL32(9) → PSHUFLW(0x4B) → lo64`
- Constants: GObj struct `0xDD0B5A0`, PSHUFB table `0xAC2BC00`, count PSHUFB `0xAC7E9D0`

### 14.3 Chunk table vtable[5] (20260409)
- PEB addend `0x0D7DC434`, PEB XOR key `0xB2DA4299DB155ED3`, PSHUFLW `0x8D`, ROL64 = 46.

### 14.4 FName_ToString (20260409)
- RVA: `0x23D410`
- 3-level SIMD pipeline → CIdx = raw_hdr (identity for this patch):
  - L1: `CI → PSHUFB → PXOR → ROL64(13) → PSHUFLW(0x93)`
  - L2: `PSHUFLW(57) → ROL64(51) → PSHUFD(0x44) → PXOR → PXOR → ROL64(13) → PSHUFLW(0x93)`
  - L3: `PSHUFLW(0x39) → ROL64(51) → AND/ANDNOT → PSHUFB → PXOR`

### 14.5 FName chain decrypt (20260409)
- FNV-32 K: `0x8FD97DFC`
- FNV-64 Prime: `0x100000001B3`
- FNV-64 Add: `0xB6379560F2A0707C`
- Slot XOR: `0x1DB6DE4B85F51BC2`
- Entry XORs: `0x021DCE2C`, `0x3040EF0C00000000`, `0x1C8EF20E00000000`

### 14.6 Global RVAs (20260409)
| Name | RVA |
|---|---|
| GNAMES_BASE | `0xDA4FE00` |
| FNAME_KEY_TABLE | `0xD9947F4` |
| GOBJECT_ARRAY | `0xDD0B5A0` |

### 14.7 Struct offsets (20260409)
| Struct | Field | Offset |
|---|---|---|
| UObject | InternalIndex | +0x0C |
| UObject | Slot 0..3 | +0x20 stride 0x20 |
| UStruct | SuperStruct | +0xB0 |
| UStruct | Children | +0xD0 |
| UStruct | ChildProperties | +0xD8 |
| UStruct | PropertiesSize | +0xE0 |
| FField | NamePrivate | +0x90 |
| FField | Next | +0x98 |
| FField | ClassPrivate | +0xC8 |
| FField | Offset_Internal | +0xD8 |
| FField | ArrayDim | +0xDC |

**Diff to 20260421** (see §6-§8 for current values): FField base shrunk 0x48 bytes; NamePrivate moved `0x90 → 0x60`; ChildProperties on UStruct `+0xD8 → +0xE0`; subclass inners `+0x130/+0x138 → +0xE8/+0xF0`.

---

*End of master reference. Update the sig agent 2 section when the background agent completes; everything else is verified as of 2026-04-22.*
