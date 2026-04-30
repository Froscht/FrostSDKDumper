# FrostSDKDumper — CL-1177146 reference

Project-specific reference. Loaded automatically by Claude when working in
this directory. Consolidates everything the dumper needs to know about the
ARC Raiders **CL-1177146 (build 2026-04-30)** patch.

Game binary: `pioneer_steam_1.26.x-CL-1177146_2026_04_30__11_29_82pct.exe`
Module base on Wine: `0x140000000` (memfd, find PID by "GameThread")
IDA project: `/media/frost/Coding Stuf/Linux/EasyDump/<same>.exe` (instance `nb1g`)

---

## 1 · Patch-day playbook (when stats regress)

Run order, fastest signal first:

1. **`[stats] struct_props=0`** ⇒ chain walker FAIL-STOP gates (`array_dim>1024`, `elem_size>0x10000`) tripping on stale offsets. See §3 — re-verify `FProperty::ArrayDim/ElementSize/Offset_Internal`.
2. **`[ffield] auto-calibrated NamePrivate offset = +0x118`** (or any non-`0x70`) ⇒ NamePrivate pipeline drift. See §4.
3. **`[p28] ScanByVtable(...): +0 hits` (across the board)** ⇒ engine type-pool vtables relocated. See §5.
4. **`/Script/Package.X` mass-bucketing** ⇒ stale `UPACKAGE_VT_RVA` in `fname_decrypt.h`. See §5.
5. **`Empty-body namespaces` very high** ⇒ BPGC chain-head offset moved (try fallback list) AND/OR offset broad-scan signature too narrow (byte 2 sensitivity). See §3.

Triage: probe live data on a known-rich struct (PostProcessSettings, RigidBodyState) before patching `arc_decrypt.h`. The chain walker validity gates are FAIL-STOP not skip — wrong offsets here annihilate the entire dump. Read 256 bytes at the first FField and:

- find `48 74 ?? ??` pattern in `+0xB0..+0xCB` → that's the encrypted offset position
- find heap-pointer in `+0x80..+0xA0` → that's `Next` / `Owner`
- the small `01 00 00 00` u32 pair in `+0xF0..+0xFF` is `ArrayDim` / `ElementSize`

---

## 2 · FName subsystem map (resolver chain → name string)

Verified 2026-04-30 via 10 parallel IDA agents tracing xrefs from the verified FName resolver chain. Patch CL-1177146 binary.

The FName subsystem is the single largest patch-day breakage point. Mapping the full chain (resolver → entry decrypt → intern → hash table → public API) lets us anchor on multiple stable points so a single moved RVA doesn't lose the whole pipeline. Use the "universal SIMD prologue" sigscan (item below) to rediscover all 14 ToString overloads in one shot.

### Resolver chain (CI → name string)
- `0x240390` `FName_Resolve_Outer` — entry. CI stage1+3 SIMD transform (ROL32(22)+shufflelo(0x72)+ROL16(3)), then calls Stage2.
- `0x240040` `FName_Resolve_Stage2_XOR` — `XOR 0x18E0021000000000` middle stage. **Has 14 entry points** — universal hub.
- `0x23A430` `FName_Resolve_Core_BlockFNV` — chunk hash + Block1/Block2 SIMD decrypt + FNV64 fold + final `XOR 0x9DD41EF0`.
- `0x2491D0` `FNameEntry_DecryptString` — header parse + key-table XOR over wide/ansi string body.

### ToString / AppendString family (14 overloads — all share the SIMD prologue)
Every overload starts with the IDENTICAL universal prologue:
```
_mm_cvtsi32_si128(*a1) → ROL32(22) → shufflelo(0x72) → ROL16(3)
```
…then calls Stage2_XOR. **Sigscan target this prologue (~40 bytes) and you get all of them.**
Notable: `0x247AD0 FNameEntry_AppendNameToString`, `0x245930 FName_AppendString_WithNumber`, `0x232110 FName_ToString_OutputBuffer`, `0x245B60 FName_AppendToString_Wide`, `0x2402B0 FName_ToString_Wide`.

### Equality (uprobe oracle gold)
- `0x2472C0` `FName_EqualsString_ANSI` — takes (FName, char*, len). **Uprobe to capture (handle, string) pairs live for ground-truth validation.**
- `0x24A19F` `FName_EqualsString_WIDE` — same for UTF-16.

### FNamePool / hash-table public API
- `0x22B1E0` `FNamePool_Repack` (was `FName_Intern`)
- `0x222400` `FNamePool_GetSnapshotMaybeRepack`
- `0x22B5A0` `FNamePool_Add`
- `0x2264B0` `FNamePool_Find` AKA `FName_FindOrAdd_FromShape16` — public API: takes (pool, OutFName, Shape16).
- `0x221470` `FNamePool_Remove`
- `0x21EFE0` `FNamePool_FilterFindBatch`
- `0x220220` `FNamePool_InitOnce`
- `0x227A00` `FNamePool_Shutdown`

### FName-from-string constructors
- `0x238A40` `FName_FromWideStr_FindOrAdd`
- `0x23CF50` `FName_FindByHandle_NoInsert` (read-only)
- `0x23D550` `FName_FindOrAddByHandle` — **50+ callsites in `sub_2334A0`**, almost certainly the EName table initializer.
- **`sub_2334A0`** — initializes UE5's hard-coded EName table (`Pawn`, `None`, `Tick`, etc.). **Known-plaintext oracle for FName slot validation** — verify decoder against well-known names.

### Cryptographic constants (verified live)
- **Stage2 XOR** (entry-pointer obfuscation): `0x18E0021000000000`
- **Final ptr XOR** (after bswap chain): `0x9DD41EF0`
- **Entry handle XOR** (auto-detected by dumper): `0xE8FED68D00000000` — universal across all 14 overloads. New patch's equivalent of the old `0x59B07C3D00000000`.
- **Intern hash mixer** at `xmmword_AD48930`: 16 bytes of `0xFF` — so the intern hash is just `~ROL32(shufflelo(slot, 0x1B), 25)`.
- **Keystream table base**: `unk_DAF87F4` (= module+0xDAF87F4). The dumper's `RVA_FNAME_KEY_TABLE = 0xDAF88EC` is `0xDAF87F4 + 0xF8` (skipping a 248-byte header). 64-WORD ring used by ALL 5 entry decoders. Universal `+40429` (= -25107 mod 0xFFFF) ring offset.
- **FNamePool base**: `unk_DBB3F80` (renamed `GFNamePool`). Chunks-array starts inline (no `+0x3040` offset).
- **Block decrypt RVAs (intact across 20260428 → CL-1177146 byte values, just relocated):**
  - BLOCK1_XOR @ 0xAD79F00 = `12 09 73 66 C3 14 7D E8`
  - BLOCK2_AND @ 0xAD7A0D0 = `73 C7` ×8
  - BLOCK2_ANDNOT @ 0xAD7A0C0 = `8C 38` ×8
  - BLOCK2_XOR @ 0xAD7A0E0 = `9E 31 FF 5E 4F 2C F1 D0`

### Bug fixed 2026-04-30 (FName resolver)
The chunk hash chain produces `V8 = HASH_PRIME * H + ADD` AFTER the 4th `ROL32(17)` — that IS the Bidx1/Bidx2 input. Old code did an EXTRA `P*+ADD` before computing Bidx1/Bidx2, shifting both inputs forward one stage and producing wrong block indices. Fix at `fname_decrypt.h:532-543`.

---

## 3 · FField / FProperty layout (CL-1177146)

Cross-checked against IDA `FField_ChainWalker_verified_20260430` @ 0x353F40 and `FProperty_OffsetReader_verified_20260430` @ 0x353900, plus live reads of PostProcessSettings (3× FBoolProperty bool overrides) and RigidBodyState (FStructProperty + FFloatProperty fields).

### Offset table

| Field | 20260428 | **CL-1177146** | Notes |
|---|---|---|---|
| FField::vtable | +0x00 | +0x00 | unchanged |
| FField::vtable2 (FProperty subclass) | +0x08 | +0x08 | unchanged |
| FField::NamePrivate (16-byte SIMD slot) | +0x70 | **+0x70** | unchanged |
| FField::Next | +0x48 | **+0x80** | live-verified heap ptr |
| FField::ClassPrivate (FFieldClass\*, module ptr) | +0x20 | **+0x90** | live-verified module ptr |
| FField::Owner (UStruct\|1 tagged ptr) | +0x50 | **+0xA0** | live-verified |
| FProperty::PropertyFlags | +0x98 | +0x98 | unchanged (=0x45 on bools) |
| FProperty::Offset_Internal | +0xB4 | **+0xC4 or +0xC8** | varies by FProperty subclass — broad-scan |
| FProperty::ArrayDim | +0xE0 | **+0xF0** | =1 on bools |
| FProperty::ElementSize | +0xA0 | **+0xF8** | =1 on bools, 4 on float |
| UStruct::ChildProperties | +0xD0 | **+0x100** | native UClass / UScriptStruct |
| (BPGC PropertyLink fallback) | — | **+0xB8** | when +0x100 is null — see §3.2 |
| Salt sentinel | +0x78 (`0x893BCE...`) | (none / 0) | sentinel removed |

### 3.1 FProperty::Offset_Internal encoding

- **XOR key**: `0x40277448` (was `0x34605D14` on 20260428)
- **Sentinel for offset=0**: u32 = `0x40277448` (LE bytes `48 74 27 40`)
- **Decrypt formula**: `real = bswap32(stored ^ 0x40277448)` — IDA exact match. The `bswap32(stored) ^ key` form is **wrong** (key is not its own bswap; bswap32(0x40277448) = 0x48742740 ≠ 0x40277448).

The encoded byte 2 (the `0x27`) **flips for any offset > 0xFF**:
```
real     = 0x148  (e.g. first field of a BPGC)
bswap32  = 0x48010000
stored   = bswap32 XOR key = 0x08267448
LE bytes = 48 74 26 08      ← byte 2 = 0x26, NOT 0x27
```

So broad-scan must look for `48 74 ?? ??` (only fix bytes 0-1 — byte 2 changes with offset). The original `48 74 27 ??` pattern only matched offsets < 0x100 (the bool sentinels) and missed every real BPGC field. See `sdk_generator.h::ReadPropertyChain`.

### 3.2 ChildProperties chain-head fallback for BPGCs

Native UClass / UScriptStruct have ChildProperties at `+0x100`. **BPGCs and many engine-generated UClass subclasses store their FField chain at `+0xB8`** (likely PropertyLink, UE5's flattened own+inherited list). Live evidence on `BP_CinCam_HandHeldShake_Jitter_C` (BPGC vtable 0x14B5653C0):
- `+0x100` = 0 (empty)
- `+0xB8` = real FField, offset 0x148 (a child class field)
- `+0x118` = another FField head (likely RefLink)
- `+0x190` = another FField head (likely DestructorLink)

Fallback in `sdk_generator.h::BuildSDK`:
```cpp
static constexpr uint64_t kChainOffs[] = { 0x100, 0xB8, 0x118 };
for (uint64_t off : kChainOffs) {
    uint64_t head = Read<uint64_t>(obj_ptr + off);
    walk_chain(head);
    if (!best_at_ff.empty()) break;  // first non-empty wins
}
```

ff_addr dedup catches duplicates between PropertyLink (own + inherited) and ChildProperties (own only). Walking PropertyLink may include inherited fields — accepted trade-off; otherwise ~5K BPGCs emit empty bodies.

### 3.3 Ghost-FField guard

```cpp
// CL-1177146:
uint64_t vtbl = Read<uint64_t>(ff + 0x00);
if (vtbl < module_base+0x1000 || vtbl >= module_base+0xE9D0000) break;
uint64_t cls_ptr = Read<uint64_t>(ff + 0x90);  // ClassPrivate
if (cls_ptr != 0 && (cls_ptr < 0x100000 || cls_ptr >= 0x800000000000)) break;
// Probe BOTH +0xC4 AND +0xC8 for offset sentinel — position varies by subclass
uint32_t off_c4 = Read<uint32_t>(ff + 0xC4);
uint32_t off_c8 = Read<uint32_t>(ff + 0xC8);
bool name_zero = /* read +0x70, all zero? */;
bool any_offset_sentinel =
    (off_c4 == 0 || off_c4 == 0x40277448 || off_c4 == 0x145D6034) &&
    (off_c8 == 0 || off_c8 == 0x40277448 || off_c8 == 0x145D6034);
if (name_zero && any_offset_sentinel) break;
```

---

## 4 · FField NamePrivate decrypt pipeline (CL-1177146)

Found via IDA `sub_4544A0` — FBoolProperty's GetCPPType / "Unsupported FBoolProperty %s size %d." error path. It loads the FField NamePrivate slot and feeds it to FName_ToString_Wide, exposing the full pipeline:

```c
si128 = _mm_load_si128(FField + 0x70);
fname_u64 = ROL64(
    (PSLLD(si128, 13) | PSRLD(si128, 19)).lo64    // ROL32(13) per uint32-lane → take lo64
    ^ 0x9A492C85DDF6F193ULL,                       // XOR with new const
    7);                                             // ROL64 by 7
// fname_u64 = (Number << 32) | CI; CI in lo32.
```

**Smoking-gun validation**: the high 8 bytes of every encrypted +0x70 slot we sampled (`B7 EF 9E 8C 49 D2 2C 64`) are session-wide constant. ROL32(13) on those upper lanes produces exactly `0xDDF6F193 0x9A492C85` — which IS the XOR const itself. The hi64 cancels to 0 → Number=0 for every name. That cancellation confirms the right key.

| FField | +0x70 bytes | Decoded CI | Decoded Number | Real name (post-resolve) |
|---|---|---|---|---|
| PostProcessSettings #1 | `BFEF9E80 49522864 B7EF9E8C 49D22C64` | 0x80C048 | 0 | LPVIntensity etc. |
| PostProcessSettings #2 | `BFEF9E80 49022F64 B7EF9E8C 49D22C64` | 0x80C03D | 0 | (sibling LPV field) |
| RigidBodyState #1      | `B7EF9EAC 49F22B64 B7EF9E8C 49D22C64` | 0x20072  | 0 | Position |

**Cross-patch differences**: 20260428 used `ROL64(21) → XOR(0xC8727080CA112779) → ROL16(15) → ROL64(32)`. CL-1177146 dropped the per-lane uint16 step entirely and switched to per-lane uint32 ROL with a final scalar ROL64(7). XOR const fully rotated.

Implementation: `fname_decrypt.h::DecryptFFieldNameSlot` (helper) + short-circuit at top of `DecryptFFieldNameCI` before the legacy auto-cal fallback.

---

## 5 · Engine type-pool vtables (CL-1177146)

The 20260428 vtable RVAs all moved en masse with the patch CRT relocation. Without these, `ScanByVtable` returns +0 hits per kind and ~5-8K classes vanish (Actor, Pawn, World, etc.).

### Vtable map

| Kind | 20260428 RVA | **CL-1177146 RVA** | Probe targets used |
|---|---|---|---|
| UScriptStruct | `0xAD6CB80` | **`0xAD9DC20`** | PostProcessSettings, Vector, Rotator, RigidBodyState |
| UClass (native) | `0xAD6D440` | **`0xAD9E500`** | ABBHighCompressedVector\*, AIAlertness\* |
| UFunction | `0xAD6D980` | **`0xAD9EA70`** | ReceiveTick, ReceiveBeginPlay, GetActorLocation |
| UEnum | `0xAD6FF30` | **`0xADA1140`** | ETeleportType, EAttachmentRule, EAICombatPhase |
| UPackage | `0xAD8AE70` | **`0xADBC9A0`** | /Script/EngineMessages |
| UBlueprintGeneratedClass | `0xB527FC0` | **`0xB5653C0`** | BP_Placement_Deployable_SoundTrap_C |
| UWidgetBlueprintGeneratedClass | `0xB322870` | **`0xB35B400`** | WBP_VignetteContainer_C |
| UAnimBlueprintGeneratedClass | `0xB4D5CC0` | **`0xB512510`** | ABP_Master_C, ABP_MainLayer_C |
| USkeletalMeshBlueprintGeneratedClass | `0xC0092B0` | **`0xB7BBCF0`** | SK_WorkshopStation_RecycleStation_01_C |
| UAngelscriptClass | `0xB8A9180` | **`0xB8ED140`** | PowerComponent, AIBSMEncounterModifierTransition |
| UASStruct | `0xB8B2420` | **`0xB8F6920`** | LevelSequenceListEntry, MappedVisime |
| ASFunction subclass A (Tick-shape) | `0xB8AD..0xB8B17A0` | **`0xB8EDA70`** | MainMenuCarouselWidget_Quests::Tick |
| ASFunction subclass B (Destruct) | (same range) | **`0xB8EDEC0`** | MainMenuCarouselWidget_Quests::Destruct |

### Strides (likely unchanged but verify if class count regresses)

| Kind | Stride |
|---|---|
| UScriptStruct | 0x130 |
| UClass | 0x300 |
| UFunction | 0x200 |
| UEnum | 0x130 |
| UPackage | 0x130 |
| BPGC | 0x490 |
| WBPGC | 0x5D0 |
| SMBPGC | 0x490 |
| AnimBPGC | 0x7F0 |
| ASClass | 0x340 |
| ASStruct | 0x150 |
| ASFunction | 0x200 |

### Probe procedure (next patch day)

1. Pick 2-3 known-name objects per kind from `dump_objects.txt`:
   - UScriptStruct: `Vector|Rotator|Transform|Quat|PostProcessSettings`
   - UClass (native): `ABBHighCompressed*MixinLibrary`
   - UFunction: `ReceiveTick|ReceiveBeginPlay|GetActorLocation`
   - UEnum: `ETeleportType|EAttachmentRule|EBlendMode`
   - UPackage: grep `/Script/`-prefixed entries
   - BPGC: `_C$` suffix entries (instance, NOT `Default__BP_X_C` which is the CDO)
   - ASClass: already classified `ASClass` entries in `dump_classes.txt`
2. `mcp__memory-reader__read_u64` at each address (= UObject + 0x00 = vtable)
3. All instances of the same kind share the same vtable — confirms identification
4. Update `gobjects.h::InitPatch20260428` (yes — function name; it handles CL-1177146 too):
   - `m_knownTypeVtables` (set, used for neighbor check)
   - `vt_targets` (vector of `{vtable, neighbor_stride}` for active scans)

### UPackage vtable (separate fix — `/Script/Package` mass-mis-bucketing)

`fname_decrypt.h::GetPackagePtr` uses a constant `UPACKAGE_VT_RVA` to recognize when the outer-chain has reached a real UPackage. With a stale value, the chain falls through to "deepest non-package UObject" which lands on the **UPackage metaclass UClass** — whose own NamePrivate is literally the string `"Package"`. Net effect: ~10K classes mis-bucketed into `/Script/Package.X` (incl. Actor, Pawn, World).

**Fix** (one-liner): `static constexpr uint64_t UPACKAGE_VT_RVA = 0xADBC9A0ULL;` in `fname_decrypt.h`.

### FFieldClass type globals (separate from vtables)

The 38 hardcoded `FProperty type-global` RVAs from 20260428 (`0xDE0CF70..0xDE17200`) are GONE on CL-1177146. Live samples:
- FBoolProperty global: `0x14DE6CEB0` (RVA `0xDE6CEB0`)
- FStructProperty (or sibling): `0x14DE6E150` (RVA `0xDE6E150`)

The Tier-1 dynamic AutoDiscoverVTables walks `m_known_addrs` at runtime and finds 38-56 mappings live — the seeded hardcoded list is stale and contributes 0; the dynamic resolver carries the load.

---

## 6 · Stat progression on CL-1177146 (full RE)

| Stage | Classes | Structs | Enums | Funcs | Properties | Empty bodies |
|---|---|---|---|---|---|---|
| Initial (broken) | 10,078 | 10,389 | 2,809 | 46,447 | **1,411** | — |
| FProperty offsets fixed (round 1) | 13,176 | 10,390 | 2,805 | 40,523 | 97,285 | — |
| NamePrivate pipeline + names work | 13,176 | 10,390 | 2,805 | 40,523 | 99,753 | — |
| Engine vtables (round 2) | 16,273 | 10,459 | 2,802 | 49,002 | 143,172 | — |
| All BPGC vtables + UPackage vt | 16,241 | 10,459 | 2,805 | 49,037 | 143,470 | 10,422 |
| Offset broad-scan + chain fallback (round 3) | 15,294 | 9,115 | 973 | 76,862 | **204,060** | **4,893** |
| Reference target | 21,453 | 9,355 | 2,340 | 41,093 | 275,843 | — |

Notes:
- Functions over-shoot target (76K vs 41K) because PropertyLink walk inflates param chains. Acceptable trade-off; cosmetic.
- Enums dropped to 973 in round 3 due to a different game session — class/enum count varies by what's loaded.
- Of the remaining 4,893 empty bodies, many are *intentionally* empty in UE5 (SoundCues, sound triggers, abstract bases like `AIDataProvider`).

### Per-vtable scan results (round 2)

| Vtable | Hits | Comment |
|---|---|---|
| UClass-native (`0xAD9E500`) | **+3,567** | engine UClasses (heavy hitter) |
| BPGC (`0xB5653C0`) | **+1,135** | game blueprints |
| WBPGC (`0xB35B400`) | +106 | widgets |
| SMBPGC (`0xB7BBCF0`) | +22 | static meshes |
| AnimBPGC (`0xB512510`) | +2 | animation BPs |
| All others (already-found shapes) | +0 | structural scan covers them |
| **Total** | **+4,832 objects** | |

---

## 6.5 · GUObjectArray layout (CL-1177146)

CL-1177146 shipped a new GUObjectArray layout that bypasses the encrypted FChunkedFixedUObjectArray pipeline used in 20260428.

- `RVA_GOBJECT_ARRAY_BASE = 0xDE6F6E0` — confirmed via init-once-sled signature (sig in §1 list, matches at .text RVA 0x38D4BA, LEA target = 0xDE6F6E0)
- **NumElements is PLAIN at +0x30** (was +0x38 on 20260428, encrypted on 20260421)
- 16B blob at +0x10 contains static seed `52 1E 93 2F 33 F5 41 87` — matches the binary file, NEVER decrypted at runtime; this is NOT the chunks_manager pointer
- Chunks-manager encrypted-blob pipeline (PSHUFLW(0x1E)→XOR→ROL16(1)) is GONE; no `+0xB0` blob
- `+0x80` = some heap pointer (e.g. 0x196BD0000) holding 4-byte u32 entries (NOT FUObjectItem array)
- `+0xE0` holds a TArray<Listener> — encrypted-looking but plain after probe (`ptr + Num + Max`)
- Init flag at `+0xF0 = 1` (was at +0xF0 on 20260428 too)

**XOR const** `38 BA 6F 75 E8 89 57 36` is **unchanged** in CL-1177146, located at RVA `0xB7FF0E0` (was `0xAD0FE50` on 20260428 — that RVA is now zeroed). The bytes weren't relocated; they got duplicated at a new RVA.

**Dumper handling**: structural-scan-only path. Read `NumElements` from `+0x30` (fallback to `+0x38` for older patches). Skip the 20260428 canonical chunks-manager decrypt entirely when `+0x30` looks like a plain count (1000..2_000_000 with hi32==0).

Result: structural scan recovers ~70,848 UObject pointers from heap (NumElements=70,592 plain). Vtable scan adds ~5K more (see §5).

---

## 7 · Path format

SDK output now emits:
- `/Script/Engine.Actor` (engine classes — was previously stripped to basename + hardcoded `/Script/` prefix)
- `/Script/Angelscript.PowerComponent`
- `/Game/Pioneer/Effects/Systems/Weapons/Muzzleflashes/Generic/NS_Muzzleflash_HandCannon_3p.NS_Muzzleflash_HandCannon_3p`

Distribution after all fixes: 13,708 `/Script/*`, 2,513 `/Game/*`, 17 `/EmbarkScript/*`, 2 `/Engine/*`, 1 `/MediaPlate/*`.

`pkg_map` in `sdk_generator.h::BuildSDK` stores the **full path** (not basename); `DumpStruct` / `DumpEnum` emit `rec.package` directly when it starts with `/`, falling back to `/Script/` prefix only for legacy non-path entries.

---

## 8 · Quick verification samples

After all fixes, these should be present and non-empty:

| Class | Expected output |
|---|---|
| Actor | `/Script/Engine.Actor` with Tags, RootComponent, Layers, bIsEditorOnlyActor, bReplicates, bCanBeInCluster, ... at offsets 0x260, 0x228, 0x238, 0xDB |
| Pawn | `/Script/Engine.Pawn` extends Actor, OverrideInputComponentClass at 0x428, LastControlInputVector at 0x410 |
| PostProcessSettings (UScriptStruct) | LPVIntensity at 0x670, LPVSecondaryBounceIntensity at 0x680, ... up to size 0x6F0 |
| RigidBodyState | Position at 0x0, Quaternion at 0x20, LinVel at 0x40, AngVel at 0x58, Flags at 0x70 |

If any of these break, see §1 playbook.

---

## 9 · Reference: file mapping

| File | Purpose |
|---|---|
| `arc_decrypt.h` | All offsets, XOR keys, RVAs (single source of truth) |
| `fname_decrypt.h` | FName resolver, FField NamePrivate decrypt, GetPackagePtr |
| `gobjects.h` | GObjectArray walk, ScanByVtable, type-pool vtable list |
| `sdk_generator.h` | BuildSDK, ReadPropertyChain, DumpStruct, resolvePackage |
| `sig_scan.h` | Patch-resilient RVA discovery (overrides hardcoded values on drift) |
| `find_fname_func.h` | Auto-locates FName decrypt function via prologue sigscan |
| `pe_reader.h` | On-disk PE fallback for VMProtect-cold pages |
| `tools/fname_pipeline.py` | Pure-Python FName harness (fast iteration vs C++ rebuild) |

## 10 · Reference SDK location (ground truth for layouts)

`/home/frost/Downloads/5.3.1169740+pioneer_1.26.x-PioneerGame_[unknowncheats.me]_/`

- `CppSDK/SDK/*.hpp` — Dumper-7 format. 6172 files. Each class has fields with offset comments `// 0xXXXX(0xSIZE)(flags)`. Use as ground-truth for layout.
- `Mappings/*.usmap` — UE 5.3 binary mapping. **Uncompressed** (header byte 4 = 0). Pure-Python parser at `tools/usmap_dump.py`. 80,797 names, 2,894 enums, 22,147 structs. **No byte offsets** (only schema indices) — combine with the C++ SDK for offset truth.
- `.usmap` header for this build: 16 bytes `c4 30 03 00 00 00 00 00 cc 03 2d 00 cc 03 2d 00` = magic `0x30C4`, version 3, no compression, compSize=decompSize.
