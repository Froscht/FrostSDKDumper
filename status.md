# FrostSDKDumper — CL-1177678 Status

Build: 2026-05-06 (post Theia-leak session)
Game build: ARC Raiders pioneer_steam CL-1177678 (2026-05-05)

---

## 1 · Current dumper output

| Metric | Value |
|---|---|
| Classes | 18,797 |
| Structs | 10,872 |
| Enums | 0 (regression — see §6) |
| Functions | 43,806 |
| Properties total | 88,095 (struct fields) + 59,949 (function params) = **148,044** |
| Properties **named** | 85,532 / 88,095 = **97.1%** |
| Placeholders | 2,563 (3%) |

Inheritance walk verified working: `Pawn → Actor → Object`, sizes correct
(0x430 / 0x3A0 / 0x90).

---

## 2 · Spot-check: ground-truth offsets vs live SDK

| Class | Field | Offset | Type |
|---|---|---|---|
| Actor | Tags | 0x250 | FArrayProperty |
| Actor | Owner | 0x1B8 | FObjectProperty |
| Actor | ReplicatedMovement | 0x148 | FStructProperty |
| Actor | OnDestroyed | 0x2A0 | FMulticastSparseDelegateProperty |
| Actor | BlueprintCreatedComponents | 0x388 | FArrayProperty |
| Pawn | Controller | 0x3D8 | FObjectProperty |
| Pawn | PlayerState | 0x3C0 | FObjectProperty |
| Pawn | LastControlInputVector | 0x408 | FStructProperty |
| Pawn | AIControllerClass | 0x3B8 | TSubclassOf<Class> |
| ARFilter | PackageNames | 0x0 | TArray |
| ARFilter | ClassPaths | 0x40 | TArray |

---

## 3 · CL-1177678 layout fixes shipped this session

### 3.1 UStruct offsets (`arc_decrypt.h::Offsets::UStruct`)

| Field | CL-1177146 | **CL-1177678** | Verified by |
|---|---|---|---|
| SuperStruct | 0x0B0 | **0x0A8** | Pawn.Super=Actor (0x2A5A9700), Actor.Super=Object (0x2A5A1300), Object.Super=0 |
| Children | 0x100 | **0x0B8** | UField/UFunction list head |
| ChildProperties | 0x100 | **0x0B0** | FField head: Actor +0xB0=0xBEECD000 (FField, Owner=Actor\|1), Pawn +0xB0=0xC1165B00 (FField, Owner=Pawn\|1), ARFilter +0xB0=FField |
| PropertiesSize | 0x0D8 | **0x110** | Actor=0x3A0, Pawn=0x430, ARFilter=0x150, UObject_UClass=0x90 |

### 3.2 FField chain walker — kChainOffs (`sdk_generator.h:2710`)

Now: `{ 0xB0, 0x100, 0xB8, 0xC8, 0xD8, 0x108, 0x118, 0x138, 0x190 }`

Added 0xB0 first (real CL-1177678 ChildProperties). +0xB8 retained for legacy
fallback / UScriptStruct alt-heads. The tightened ghost-FField guard rejects
walks that land on UField (UFunction) lists masquerading as FFields.

### 3.3 Ghost-FField guard tightening (`sdk_generator.h:1303-1334`)

Old: `if (name_zero && any_offset_sentinel) break;` — required BOTH conditions,
so UField objects with non-zero garbage at +0x88 slipped through.

New: dual-offset NamePrivate check. Reads 16 bytes at the auto-discovered
`FField::NameEncrypted` offset AND at hardcoded +0x30. Breaks only if BOTH
are all-zero. Real FFields always have a populated NamePrivate slot at +0x30
(the obfuscation pipeline produces non-zero bytes even for FName::None).

### 3.4 NamePrivate auto-disc pinning (`auto_offsets.h::ProbeFFieldNamePrivate`)

The probe was moving NamePrivate from 0x30 → 0xE0 because `CollectFFields`
returns UScriptStruct's UField list (not the FField chain head) on CL-1177678.
Those UField objects have a session-constant 64-bit value at +0xE0 (likely a
flag/version block) producing a 70-hit signal that out-voted the real
+0x30 slot.

Fix: hard-pin to the compile-time +0x30. Logs "pinned to 0x30 (slot=N,
best=0xE0@70 hits)" so we can tell when CollectFFields gets fixed and the
auto-disc is ready to be re-enabled.

### 3.5 Type-pool vtables added for CL-1177678 (`gobjects.h:266-289, 1313-1335`)

8 new compile-time vtable entries appended to existing CL-1177146 list:

| Kind | CL-1177678 RVA | Stride |
|---|---|---|
| UScriptStruct | 0xADF4820 | 0x130 |
| UClass (native) | 0xB63A840 | 0x300 |
| UFunction | 0xB940DC0 | 0x200 |
| UEnum | 0xADF7AC0 | 0x130 |
| UPackage | 0xAE13030 | — |
| UBlueprintGeneratedClass | 0xB583B90 | 0x490 |
| UWidgetBlueprintGeneratedClass | 0xB3AF490 | 0x5D0 |
| UAnimBlueprintGeneratedClass | 0xBECF7F0 | 0x7F0 |

---

## 4 · FField NamePrivate decoder (CL-1177678) — solved

Found via xref to `"PropertyBool.cpp"` string (`module + 0xAE148DC`); the third
xref lands inside `sub_44E3DC` = `FBoolProperty::GetCPPType_CL1177678`.

```c
slot = load16(FField + 0x30)
si = ROL64(slot, 55) per qword            ; PSLLQ 0x37 | PSRLQ 9
si = PSHUFB(si, [06 05 03 01 02 07 00 04 00 00 00 00 00 00 00 00])
si = PXOR  (si, lo64=0x4882C8C849A43F3B)
res = ROL64(si.lo64, 32)
ci = res.lo32, num = res.hi32
```

Constants verified live (RVAs and bytes match IDA xmmword consts at 0xADEDB90
and 0xADEDBA0). Different shape than CL-1177146 (which used per-uint32-lane
ROL32(13) + scalar ROL64(7)).

Code lives in `fname_decrypt.h::DecryptFFieldNameSlot` Tier-A.

---

## 5 · Theia obfuscation source — leaked, partially actionable

Diff at `/home/frost/Downloads/bla.txt` (3,209 lines, 30+ files) implements
Epic's "Theia" FName/FProperty obfuscation system. This is the exact mechanism
ARC Raiders uses for the ~3% of properties that still resolve to placeholders.

### 5.1 Confirmed structure

```c
struct FNameEntry {           // shipping build (no WITH_CASE_PRESERVING_NAME)
    uint64 HashLower;          // +0  CityHash64WithSeed of lowercase name
    uint16 Header;             // +8  bIsWide:1 + Len:15
    bool   bIsOpaque;          // +10
    char/wchar Name[];         // +12 onward (variable, aligned)
};
```

### 5.2 Hash algorithm

`HashLower = CityHash64WithSeed(lowercase_bytes, len_bytes, TH_OPAQUE_HASH_SEED)`

Default seed in the source: **4919** (= 0x1337).
Epic's comment: *"Changing it from its default value is strongly recommended,
changing it every so often (or even per-build) past that is also recommended."*

### 5.3 String placeholder format (per leak)

```
^<flags-char><4 len chars><16 lower-hash chars>[<16 exact-hash chars>]
```

Each char ∈ 'a'..'p' (= 'a' + nibble_value). Total length 22 chars (shipping)
or 38 chars (editor).

**ARC stripped this format.** Wide-scan of 3 GB of mapped game memory found
only 2 strings matching the pattern. ARC modified `FNamePool::CreateOpaque`
to NOT write the placeholder string into entries — keeping just `HashLower +
Header + bIsOpaque`.

### 5.4 Seed extraction status

| Method | Result |
|---|---|
| Search binary for CityHash64 mixing constants (k0/k1/k2/k3) | **0 hits** — likely VMProtect-encrypted code page or `mov r8, imm64` not visible to immediate-search |
| Wide-scan game memory for `^[a-p]{21,37}` | 2 hits — ARC stripped placeholders |
| Live IDA trace via uprobe on FNameHash::GenerateHash | Not yet attempted — needs game running, FName lookup-by-string trigger |

### 5.5 What the leak tells us about our remaining placeholders

The decoder produces a 32-bit CI from the FField slot. For plaintext entries,
that CI maps to a real chunk in FNamePool → resolves to name. For opaque
entries, the "CI" is the low 32 bits of a 64-bit hash → maps to an unmapped
chunk → resolver returns empty.

This perfectly matches our placeholder pattern: ~1,460 entries with valid-
looking CIs in the 9.9M..16.7M range that don't resolve.

---

## 6 · Known regressions / open issues

### 6.1 Enums dropped to 0 in current run

Previous run: 2,878 enums. Current: 0. The pre-pass walked only 562 known
structs (vs 0 previously) but found 0 enums. Suspect: UEnum::Names offset
moved AGAIN on this game session, or the enum vtable scan broke.

### 6.2 ~2,563 properties still show placeholders

- ~1,100 with `Prop_CI0_Off0xXXX` — decoder returned CI=0. Likely garbage
  chain entries the ghost guard didn't filter.
- ~1,460 with `Prop_CIxxxx_0xYYYY` — opaque Theia entries (need seed
  extraction). Top CIs: 22529 (×25), 36866 (×17), 9980968 (×15), 9981034
  (×12), 9982678 (×11). The high-CI cluster around 0x983XXX matches an
  unmapped FNamePool chunk — consistent with Theia 64-bit hash being
  truncated to 32 bits.

### 6.3 Field offset minor skew vs refSDK

Live shows Tags @ 0x250 (refSDK CL-1177146 has 0x260). 0x10-byte shift on
a few fields. May be intentional CL-1177678 layout change OR an Offset_Internal
broad-scan picking the wrong sentinel position. Low priority — fields are
named and types are resolved.

---

## 7 · Three viable next moves

| Path | Effort | Payoff |
|---|---|---|
| **(A) Live IDA trace via uprobe on FNameHash::GenerateHash** | Medium — needs game state + trigger point | Reveals `TH_OPAQUE_HASH_SEED` directly. Once we have the seed, dictionary-attack opaque entries with refSDK + UE engine name lists. |
| **(B) Pool-entry layout RE** | Higher | Find FNamePool's chunk layout in live memory, read each entry's `HashLower` field per leaked layout, brute-force seed by computing `CityHash64WithSeed("None", 4, S) == known_hash_for_None`. |
| **(C) Accept the 97% gap** | None | Opaque Theia names are designed to resist exactly this. The remaining 3% are gameplay-internal fields the SDK doesn't strictly need. |

---

## 8 · Files modified this session

| File | Change |
|---|---|
| `arc_decrypt.h` | UStruct offsets shifted (SuperStruct +0xA8, Children +0xB8, ChildProperties +0xB0, PropertiesSize +0x110) |
| `sdk_generator.h` | kChainOffs prepended +0xB0; ghost-FField guard tightened to dual-offset NamePrivate check |
| `auto_offsets.h` | NamePrivate probe range extended to start at +0x20 with weighted lo==hi scoring; final apply hard-pinned to compile-time 0x30 until CollectFFields is fixed |
| `gobjects.h` | 8 CL-1177678 type-pool vtables added to compile-time fallback list |

---

## 9 · Memory / reference notes saved

- `reference_theia_leaked_source.md` — full pointer to the leaked Theia diff
  + extracted FNameEntry layout, hash algorithm, opaque format, and the
  three attack paths for seed extraction. Auto-loaded next session.
- `discovery_cl1177678_ffield_decoder_solved.md` — the SIMD decoder algo
  + constants + how to rediscover via "PropertyBool.cpp" xref.
