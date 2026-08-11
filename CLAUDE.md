# FrostSDKDumper — Consolidated Reference

## Project Overview
External SDK dumper for ARC Raiders (Unreal Engine 5, Theia-obfuscated). Reads game memory via `/dev/memreader` kernel module (or `process_vm_readv` fallback). Outputs `SDK_Output.txt` + `generated_decrypt.h` + `dump_bones.txt`. Runs on Linux against Wine-hosted game process.

Build: `g++ -std=c++17 -O2 -march=native -mavx2 -msse4.1 -I KernelDriver/include -o FrostDumper main.cpp build/Zydis.o -lcapstone -lunicorn -lm`
Run: `sudo ./build_and_run.sh [PID]`

## Current Patch: Steam build 24653108 (2026-08-11)
Image size **0x117E9000**. Dump: `module_dump_0x140000000.bin`.
**FULLY REVERSED AND LIVE-VERIFIED 2026-08-11 vs PID 53906** — 9048 sampled
objects, 100.0% named, 0 "None", 5509 distinct names.

### Verified constant sheet
```
GNamePool          RVA 0xE38FA00      pool-init flag 0xE38F9F8
FName resolver     RVA 0x23EC40       narrow 0x2411CC, wide 0x24A2E0
GUObjectArray      RVA 0xE64B260      standalone encrypted 16B global (NO struct!)
UObject::GetFName  RVA 0x5027E0
keystream table    RVA 0xE2CE7F4      uint16[144], decrypt window at +0xA0

CI decode:  CI = lo32( PSHUFLW(enc ^ 0xCA5BCA5BCA5BCA5B, 0x8C) >> 18
                       ^ 0x0000063EEF1B0319 ) ^ 0xDB155ED3
CI encode:  enc = PSHUFLW( ROL64(CI ^ 0xB2DA4299DB155ED3, 18), 0x72 )
                  ^ 0xC63ED2A018607637
  NameOff = CI & 0xFFFF ; ChunkOff = (CI >> 8) & 0xFFFF00

Shard hash (P = 0x1000193, ADD = 0x6E149835), SeedAddr = ChunkAddr + 0x6550:
  H = (0x40000000 | (Lo >> 6)) * P + ADD        ; mov r8d,0x10 ; shld r8d,edx,0x1A
  H = ROL32(H, 0x15) * P                        ; NOTE: no +ADD on this step
  H = ROL32(H + Hi + ADD, 0x1A) * P + ADD
  H = (H >> 0x0B) * P + ADD
  S = H ^ (H >> 16) ; B1 = S & 7 ; B2 = (S + 1) & 7

Block decode (8 blocks at ChunkAddr + 0x6560, stride 32):
  D = ROL16( PSHUFB(raw, [01 04 06 00 03 07 02 05]), 2 ) ^ 0x01554577E835E9F4
FNV64 (P64 = 0x100000001B3, ADD64 = 0x323C186F5D5C1B15):
  Fv1 = ROL64(V13, 0x28) * P64 + ADD64
  Fv2 = ROL64(Fv1, 0x29) * P64 + ADD64
  EntryPtr = V13 + (V15 ^ Fv2) + 2*NameOff      <-- pointer chain is a NO-OP, see below

FNameEntry header (uint16 at EntryPtr, string at EntryPtr+2):
  length = ((h >> 6) & ~0x3F) | (h & 0x3F)      ; wide = (h & 0x800) != 0
String decrypt (single cyclic sequence, no LCG):
  K = length + 0x7216                            ; index (K + i) & 0x3F, +1 per element
  narrow: buf[i] ^= (uint8)(KS[(K+i) & 0x3F] >> 3)
  wide  : buf[i] ^= KS[(K+i) & 0x3F]             ; full uint16, NO >>3

UObject::GetFName (RVA 0x5027E0, P = 0x1000193, ADD = 0x21B21773):
  Seed = Obj + 0x10 (the ADDRESS), Lo = lo32, Hi = hi32
  H = ROL32(Lo, 0x18) * P + ADD
  H = (H >> 3) * P + Hi + ADD
  H = (H >> 8) * P + ADD
  H = (H >> 3) * P + ADD
  S = H ^ (H >> 16) ; Idx = (S & 3) ^ 2 ; Slot = Obj + 0x20 + Idx * 0x20
  V = ROL16( PSHUFB(*Slot, [01 04 06 00 03 07 02 05]), 2 ) ^ 0x01554577E835E9F4
  FName = ROL64(V, 32)   -> CompIndex = lo32, Number = hi32
  Class = S & 3 ; Outer = (S + 1) & 3
```

### GUObjectArray (verified: NumElements 281066, invariant 104/104)
There is **no GUObjectArray struct on this patch.** The chunks_manager is a
standalone encrypted 16-byte global, addressed rip-absolute at all 838 read
sites, with **zero writes and zero `lea`s**. Searching for a base pointer or an
xref-ranked `lea` finds nothing — anchor on the absolute RVA.
```
Mgr = lo64( PSHUFB( ROL32_perdword( PSHUFLW(xmmword[0xE64B260], 0x4B)
                                    ^ 0x8387081898D8D8DD, 5 ),
                    [06 02 00 07 05 01 03 04] ) )
  key mask @ 0xB3F4030, shuffle mask @ 0xB3F4040
NumElements = lo32( ROL16(PSHUFB(xmmword[Mgr+0x30], [01 04 06 00]), 2) )
              ^ 0xE835E9F4                       ; mask @ 0xB447380
vtable      = [Mgr + 0x60]        (offsets are -0x40 vs CL-1325322)
blob        = xmmword[Mgr + 0x90]
thunk       = vtable[6] = [vt + 0x30]            (was slot 3 on CL-1325322)
FUObjectItem stride 20, 65536/chunk; UObject::InternalIndex at +0x0C
```
PEB = 0x7FFD0000 (Wine). Gate PEB candidates on the InternalIndex invariant —
150 of 151 candidates that pass the Ldr/ProcessParameters/ProcessHeap triple
fail the invariant 104/104, the right one passes 104/104. Perfect separation.

### Layout (all live-verified)
```
UStruct::SuperStruct      +0xA8     UStruct::ChildProperties  +0x100
UStruct::Children         +0xF8     UStruct::PropertiesSize   +0x110
UStruct::MinAlignment     +0xD8     UField::Next              +0x90
UClass::ClassCastFlags    +0x1E8   UClass::ClassFlags        +0x158
UClass::ClassWithin       +0x150   UClass::ClassConfigName   +0x1F0
UClass::ClassConstructor  +0x1D8   UStruct::StructBaseChain  +0x98
UEnum::Names Data +0xA8, Num +0xB0, Max +0xB4; TPair stride 0x10 {FName@0,int64@8}
  (INTACT on this patch - was stripped by Theia on CL-1233465)
FField::NamePrivate       +0x70     FField::Next              +0x80
FField salt sentinel      +0x88     FField::FlagsPrivate      +0x98
FField::Owner             +0xA0     (tagged, bit0=1 => UObject)
FProperty sentinel        +0xA8     RepIndex                  +0xB0
PropertyFlags             +0xB8     Offset_Internal           +0xC4
RepNotifyFunc             +0xE0     ArrayDim                  +0xF0
BlueprintRepCondition     +0xF4     ElementSize               +0xF8
links                     +0x100..+0x118          sizeof(FProperty) = 0x120
FBoolProperty FieldSize/ByteOffset/ByteMask/FieldMask = +0x120..+0x123

Offset_Internal = bswap32(stored) ^ 0xEE0CA1CB
FField::NamePrivate is KEY-FREE: PSHUFLW(0x8D) -> ROL64(46) -> PSHUFLW(0x4B) -> ROL64(32)
Pointer idiom: PSHUFB( ROL32( PSHUFLW(E, 0x4B) ^ 0x8387081898D8D8DD, 5 ),
                       [06 02 00 07 05 01 03 04] )
```

### Traps specific to this patch
- **The keystream table must be read LIVE.** The module dump holds the
  at-rest form; runtime decrypts it in place. A static extraction of
  0xE2CE7F4 yields bytes that share not one value with the live table, and
  13 of 23 live bytes never occur in the static form at all. Same applies to
  `.text 0x4BD000-0x4BDFFF` (entropy 7.1 vs 4.4 in neighbours) and to
  `RVA 0x234000-0x239000`, which is 0xCC-filled in the dump.
- **The FName pointer chain is an algebraic no-op.** `bswap64(0x43231D85) ==
  0x851D234300000000`, so `EntryPtr == RawPtr`. It is split across two
  functions purely as obfuscation. Safe to drop from the hot path.
- **The CI blend `(E&A)|(~E&B)` collapses to `E ^ B`** because `B == ~A`
  (`A = 0x35A4...`, `B = 0xCA5B...`). Same for several thunks.
- `&` binds looser than `+` in **both Python and C++**. `(x*P)&M32 + Hi + ADD`
  silently parses as `(x*P) & (M32+Hi+ADD)`. This produced a hash with exactly
  zero correlation to the true slot (uniform 4x4 contingency table) while
  looking completely reasonable, and cost a full debugging cycle. Parenthesise
  the mask.

### chunks_manager thunk family (mapped 2026-08-11)
Not a loose set of variants: a table of **37 consecutive 0x40-byte vtables at
.rdata 0xB47FB80..0xB4804C0**, each holding an inverse encrypt/decrypt pair at
slots 5 and 6. **74 thunks, 73 structurally unique** — semantic normalisation
over the primitive alphabet yields 73 distinct shapes for 73 decodable thunks.
Runtime picks one via `hash % 37` (dispatcher at RVA 0x4AFE00, `movabs rdx,
0xDD67C8A60DD67C8B; mul; shr 5; lea *9; lea *4` then a 37-way switch).

**Pattern-matching a fixed op list cannot work. Interpretation is mandatory.**
The interpreter needs exactly 22 mnemonics; `paddw`/`paddd` appear only as
self-add (a 1-bit left shift) in 3 of 74 variants and are easy to miss.
Only `[rdx]` and `gs:[0x60]` are ever read; no branches, no calls, no writes.
All 105 rip constants sit in one block at `.rdata 0xB47C3C0..0xB47CB4F`.
`vt#24 slot6 (0x4BDEC0)` is encrypted at rest; reconstruct it by inverting its
partner `0x4B1150` rather than reading it.

### Anchors that survived this patch
The AngelScript binding signature strings and the CoreUObject source-path
assert strings both still work and remain the fastest route to any
script-visible native function. Use them first on the next patch.

## Previous Patch: CL-1325322 (2026-08-08)
Image size 0x11853000. IDA instance `qe3o` (`pioneer_steam_1.39.x-CL-1325322_2026_08_08__22_23_83pct.exe`), IDA base 0x140000000 (NOT 0 like older instances).

**FName pipeline: SOLVED and live-verified** 2026-08-08 vs PID 16430 — sequential pool walk decodes 60/60 engine names. See "CL-1325322 FName Pipeline" below.

**GObjectArray: SOLVED and live-verified** 2026-08-08 — 291388 objects enumerated, chunk array passes the InternalIndex invariant 256/256. GUObjectArray = RVA 0xE6ED190 (confirmed: object registration calls `sub_1404B0BF0(&unk_14E6ED190, Obj)`). Key facts from `sub_1404B0BF0`:
- chunks_manager blob at **GUObjectArray + 0x110**, decrypt = `PSHUFLW(ROL64(raw_lo64 ^ xmmword_14B48A020, 38), 0x39)`
- chunk-pointer array comes from **vtable[3]** (offset 24) on `mgr + 0xA0`, arg = 128-bit blob at `mgr + 0xD0`
- **FUObjectItem stride = 20** (not 24 — this is why prior scans failed), 65536 items/chunk
- `Chunk = ChunkArray[Index >> 16]`, `Item = Chunk + 20 * (Index & 0xFFFF)`, `Item + 16` = flags dword
- UObject InternalIndex at **+0x0C**

vtable[3] is a small PEB-salted thunk, but **Theia ships ~100 interchangeable
variants and picks a different one per process launch** — the vtable itself moves
too (0x14B51ADC0 in one run, 0x14B51ADA0 in the next). Two observed shapes:
```
0x1404C15F0:  PSHUFLW(blob,0x8D) -> pxor rip-const -> ROL64(46)
              -> xor (0xB2DA4299DB155ED3 ^ (0x4D56C2E0 + PEB))
0x1404B7A90:  (blob & A) | (~blob & B)  [pand/pandn/por, rip-consts]
              -> PSHUFLW(0x93) -> ROL16(12) [psllw/psrlw]
              -> xor (0x4802830B + PEB) broadcast   ... no movabs at all
```
Pattern-matching a fixed op list therefore breaks on the next launch. The dumper
now **interprets** the thunk instead (`EmulateChunkThunkV808`, a small SSE
subset interpreter covering movdqa/movq/pand/pandn/por/pxor/pshufd/pshuflw/
pshufb/psllw-q/psrlw-q plus `mov r,imm`, `add rax, gs:[0x60]`, `xor`, `rol`).
Unsupported opcode aborts rather than guessing.

No uprobe needed: the PEB is found by scanning writable memory for `PEB+0x10 ==
ImageBaseAddress (0x140000000)` with a valid Ldr / ProcessParameters /
ProcessHeap triple — Wine puts it at 0x7FFD0000.

**Do not gate this on structural plausibility — gate it on the InternalIndex invariant.** `*(u32*)(Obj + 0x0C) == ChunkIdx * 65536 + Slot` holds for every live FUObjectItem and for no unrelated heap region. Earlier heap sweeps accepted float arrays as object arrays because they only checked "pointer-shaped".

### Theia pointer decryption (CL-1325322, verified 2026-08-09)
This idiom appears at 112 sites and is **pointer** decryption, NOT name decoding —
the result is dereferenced directly (`mov qword ptr [rax+0x160], 0` at 0x1403ABD1B2,
`movzx ebp, byte ptr [rcx+0x21B]` at 0x1403ABEBC8):
```
Ptr = ROL32(PSHUFLW(enc, 0x39) ^ xmmword_14B4E02B0, 9) ^ 0x890EF320D7E2DC4C
      (ROL32 is per-dword: psrld 0x17 | pslld 9)
xmmword_14B4E02B0 lane0 = 0xD2966E6B7A701FF6
```
All 112 sites share the same constant pair. Sites read `[reg+0x60]` (105) and
`[reg+0x80]` (7). **Do not mistake this for the FName path** — a lot of time was
lost treating UObject +0x20/+0x40/+0x60/+0x80 as name slots when they are
encrypted pointers (Outer/Class/etc.), which is why only a handful of distinct
ciphertexts occur: many objects share the same class and outer.

Theia uses a **different constant pair per site**. Two other confirmed FName-shaped
decoders, both reading container elements rather than UObject fields:
```
0x1404D5341:  FName = ROL64(PSHUFLW(e,0x39) ^ 0xBF6D1474CC9622A5, 62) ^ 0xAB7645401DC01268
0x1404D4BC9:  ROL64(13) -> PSHUFB[rip] -> ROL64(10)
```
Consequence: brute-forcing transform families is hopeless. Find the exact site.

**UObject::GetFName: SOLVED and live-verified** 2026-08-09 — 290063/290063 objects
named, 141694 distinct. See `ArcDecrypt::v20260808::UOBJ_NAME_*`. The decisive
anchor was the **AngelScript binding signature strings** in .rdata: the string
`"FName GetName() const"` (0x14C084885) is referenced by a registration site that
loads the native function pointer immediately before it (`lea rax, [rip-...]`
at 0x14422B053 → RVA 0x343950). That function is UObject::GetFName in full.

Two properties made this impossible to guess and cost most of the search time:
the slot is **hash-selected** from four candidates (so no fixed offset ever
scores), and there is a final **ROL64(32)** after the second XOR.

SDK output after the fix: 14199 classes, 33411 structs, 879 enums, 14062
functions. Properties still 0 — FField/FProperty layout is the remaining gap.

**Use the AngelScript signature strings as the general anchor on future patches.**
They survive Theia (they are needed at runtime for script binding) and name the
exact native function for anything script-visible: GetName, GetNameByIndex,
GetOuter, class/struct/enum accessors.

### CL-1325322 FField layout (verified 2026-08-09)
Anchor again a source-path string: `.../UObject/PropertyBool.cpp` (0x14B506FEC)
is referenced from `sub_1404478A0`, the FBoolProperty size check. Its assert path
decodes the field name for the message, which exposes both the offset and the
transform:
```
FField::NamePrivate      = +0x60
FField::Next             = +0x80    (probed live: 205/300 chains)
UStruct::ChildProperties = +0xD0    (probed live: 258/400 structs)
FBoolProperty::FieldSize = +0x9C    (bittest against 278 ⇒ sizes 1,2,4,8)

Name = ROL64(ROL32(PSHUFLW(E ^ 0xDB4ADB4ADB4ADB4A, 0x39) ^ 0x09DCB521A13AC4BC, 9)
             ^ 0x890EF320D7E2DC4C, 32)
```
The blend in the binary is `(E & A) | (~E & B)` with A = 0x24B5… and B = 0xDB4A…;
B == ~A so it collapses to a plain XOR with B. Decoding real chains yields
MaxScrollbackSize / PrimaryActorTick / StaticMesh / AssetUserData.

The generic Phase 2 and auto_offsets probes cannot find any of this (they need a
working name decode to score candidates — the thing they are trying to discover)
and they overwrite the values, so main re-asserts the layout after they run.

Full verified FField/FProperty layout. Offsets marked (ctor) come from the
FProperty constructors (0x448430 / 0x4316F0), `FProperty::SetupOffset`
(0x43D380) and the member-clone routine at 0x42A16A, which copies the whole
set in one place and is the best single confirmation of the layout:
```
FField::NamePrivate      = +0x60   encrypted (16B stored)
FField::FlagsPrivate     = +0x70   plain u32
FField::Owner            = +0x78   tagged ptr, bit0=1 ⇒ UObject
FField::Next             = +0x80   plain ptr
FField salt sentinel     = +0x88   const 0x4F463D342B221910
FProperty::RepIndex      = +0x98   plain u16
FProperty::ElementSize   = +0x9C   plain i32   (ctor)
FProperty::PropertyFlags = +0xA0   plain u64   (ctor)
FProperty::Offset_Internal = +0xB4 bswap32(real ^ 0x76C317A2)   (ctor)
FProperty::RepNotifyFunc = +0xD0   encrypted FName
FProperty::ArrayDim      = +0xE0   plain i32   (ctor)
FBoolProperty::FieldSize = +0x108, ByteOffset +0x109, ByteMask +0x10A,
                           FieldMask +0x10B                     (SetBoolSize @0x451980)
subclass data (Inner/Struct/PropertyClass/…) = +0x108 and up
UStruct::SuperStruct     = +0xA8   plain ptr, 0 when no parent
UEnum::Names             = +0xA8   TArray<TPair<FName,int64>> (UEnum is
                                   not a UStruct, so no conflict)
UClass::ClassCastFlags   = +0x120  exact metaclass oracle
```

Objects that merely *look* like types (a non-null SuperStruct or a walkable
ChildProperties chain) are mostly not types. Measured over 6000 such
objects: 2339 UFunction, 1050 UPackage, 818 CDOs (flags 0, all named
`Default__*`), against 956 UClass / 606 UScriptStruct / 230 UEnum. The
reclass pass therefore *drops* records whose cast flags give a definite
non-type verdict, instead of forcing them into the class/struct split.
`class ptr invalid` and `flags unreadable` never occurred, so a zero-flag
record is an ordinary instance, not a decode failure.

### UObject slot roles (CL-1325322)
All four slots at `Obj + 0x20 + idx*0x20` share ONE transform; the name just
needs a final ROL64(32) to bring CompIndex into the low dword:
```
Ptr   = ROL64(PSHUFLW(enc, 0x39) ^ 0xBF6D1474CC9622A5, 62) ^ 0xAB7645401DC01268
FName = ROL64(Ptr, 32)          → CompIndex = lo32, Number = hi32
NameIdx  = hash (see UObject::GetFName below)
ClassIdx = (NameIdx + 2) & 3    verified: 120/120 UFunctions → the "Function" UClass
OuterIdx = (NameIdx + 3) & 3    verified: ExecuteUbergraph → Object
```
`GetOuterPtr` had no v808 path, so `m_owner_to_funcs` was keyed on garbage and
**function parameters came back empty** even though the param FFields sat
correctly at UFunction+0xD0 with Owner pointing at the function. Confirmed
independently: 172/200 UFunctions have a valid param chain there.

The constant pair `0xBF6D1474CC9622A5 / 0xAB7645401DC01268` is what earlier
notes logged at 0x4D5341 as an unexplained "FName-shaped decoder" — it is the
UObject slot decrypt.

### GWorld (CL-1325322, verified 2026-08-09)
`RVA 0xE859548`, and it is a **double-deref**: the slot holds a wrapper whose
first qword is the UWorld (0xE859548 -> 0xE1A500A0 -> UWorld).

`DiscoverGWorldV808` resolves it from the live object graph instead of by
sig-scan: find the object whose class is named "World" (skipping the
`Default__World` CDO), then sweep .data for the slot that reaches it. It runs
after the object array is up, so the older pre-array GWorld phase and the
`mapstate` check still print "unavailable" — cosmetic, the anchor is corrected
right afterwards.

Two traps found while building this:
- **No direct `UWorld*` slot exists** in .data, only wrapper slots.
- **Xref ranking does not work.** A full capstone sweep of .text found ZERO
  rip-relative references to any candidate — Theia reaches GWorld through
  computed paths only. An earlier ranking that approximated the displacement as
  the last 4 instruction bytes produced 9/8/6 counts that were pure noise and
  picked the wrong slot.

What does separate them: three .data slots reach the same UWorld and every
wrapper looks like `{UWorld*, UObject*, 0xFFFFFFFF, ...}`. The world-subsystem
records carry the subsystem at +0x08 (e.g. "SignificanceManager", its name
inline as UTF-16 from +0x18); GWorld has no named object there. Exactly one
candidate passes. That filter is a heuristic, not a proof, so every candidate is
logged with its `subsystem_record` verdict — if it ever picks wrong, the correct
RVA can be read straight off the log.

### SDK output (CL-1325322, 2026-08-09)
```
Classes 19349   Structs 61042   Enums 877   Functions 48415
Properties 344994 (344522 named)   FProperty_Unknown 0.0%
struct_props 276822   param_props 68172
Naming rate 290781/290781 = 100.0%   unique names 141901
```

### CL-1325322 UObject::GetFName (RVA 0x343950, verified 2026-08-09)
```
Seed = Obj + 0x10
P = 0x1000193, ADD = 0x31F5C55F
H = (lo32(Seed) >> 4) * P + ADD
H = ROL32(H, 22) * P
H = H + hi32(Seed) + ADD
H = (H >> 4)   * P + ADD
H = (H >> 0xA) * P + ADD
S = H ^ (H >> 16)
Idx = ((((~S | 0x565AFC0) & 0x565AFC1) | (S & 2)) ^ 0x565AFC3) & 3
Slot = Obj + 0x20 + Idx * 0x20            <-- four slots, hash-selected
V = ROL64(PSHUFLW(*Slot, 0x39) ^ 0xBF6D1474CC9622A5, 62)
V = V ^ 0xAB7645401DC01268                 (= 0xB7148246A35721EF ^ 0x1C62C706BE973387)
FName = ROL64(V, 32)
CompIndex = lo32(FName), Number = hi32(FName)
```

### Where the UObject name decrypt must be (narrowed 2026-08-09, superseded)
Scanning for `pshuflw xmm, [mem]` finds only the pointer idiom — that instruction
form is the wrong anchor. Theia's field decrypt is normally:
```
movdqa xmm0, [reg + disp]      ; 66 0F 6F /r   (or movdqu, F3 0F 6F)
pxor   xmm0, xmmword[rip]
psrlq/psllq -> por             ; ROL64
pshufb xmm0, xmmword[rip]      ; or pshuflw
movq   rax, xmm0
```
Scan for that form and **exclude RSP/RBP/RIP as base** — stack-local pointer
decrypts otherwise dominate the histogram (1715 sites at `[rsp+0x60]`, 1628 at
`[rsp+0x50]`) and drown out the object-field sites. With those excluded only
~70 object-field sites remain, at disp 0x10 (12), 0x20 (8), 0x50 (19),
0x70 (2), 0x110 (18), 0x150 (18). The UObject name decrypt is among these.

FNames handed to the name helpers (`sub_1405087E0`, `sub_140526F40`) are often
**plaintext** qwords read straight from a struct (`mov rcx, [rbx]`), so not every
FName in the game is encrypted. Plaintext FName dwords do exist inside UObjects
at +0xB0, +0xC8, +0xD8, +0xE8 and resolve to real names (+0xD8 yields class
names: FloatProperty, ObjectProperty, StructProperty, NameProperty), but all are
dominated by "None" and none is the object's own name. A plaintext sweep of
0x00..0x418 over 600 spread-sampled objects found no high-diversity name field,
so NamePrivate is encrypted.

### Uprobes do not work on this target (established 2026-08-09)
The game's code is mapped from `/memfd:wine-mapping` as **`r-xs` (MAP_SHARED)**.
Address resolution is fine — the driver's reported `file_offset` matches the VMA's
`pgoff + (vaddr - vm_start)` exactly — but no probe ever fires. Four probes at four
different addresses (0x1404C1602 PEB salt, 0x140231AB9 CompIndex, 0x140230020
string decrypt, plus the dumper's own 0x1404A84A4) all reported `active: true`
with `total_hits: 0`, including during active gameplay and UI interaction.
Treat live-capture via uprobe as unavailable; the dumper's `CaptureSimdPebKey()`
uprobe path is dead weight for the same reason. Get the PEB by scanning for
`PEB+0x10 == ImageBaseAddress` instead (see the GObjectArray section).

### Investigation pitfalls (cost real time on 2026-08-09)
- **Never sample the first N entries of the object array.** They are clone
  instances of one class; no field varies, so every search returns nothing and
  every negative result is meaningless. Sample with a stride across all chunks.
- **Valid-CompIndex membership is a weak filter.** Names sit 4–8 CI steps apart
  inside a chunk, so chunk-0 density is ~7.6% and the full set is dense in the
  low range. Solving an unknown XOR constant against "lands in a valid CI" yields
  plateaus at exactly |ValidCi| and degenerate answers (all objects → one name).
- **Exclude constant and zero-valued columns before solving.** A slot that is
  identical across objects makes every candidate constant "work".
- Score candidates by **distinct decoded names**, never by hit count alone.

### Config hygiene (fixed 2026-08-08)
`config_loader.h` used to gate only the `offsets` block on image_size; anchors, patch constants, vtables, GNames and the FName resolver loaded anyway and then caused auto-discovery phases 3/5/6/7/8 to be SKIPPED with stale values. A failed run also overwrote `decrypt_export.json` under the new patch tag, so the next run accepted the garbage as matching. Now: image_size mismatch discards the WHOLE config, and `AutoExport::ArchiveForeignConfig()` renames a foreign-patch config to `decrypt_export.json.imgsize-0xXXXX` instead of clobbering it.

## Previous Patch: CL-1315578 (2026-07-09)
Live-verified 2026-07-14 against PID 8082. Image size 0x117E1000.
UObject slot decode: ROL64(29) → PSHUFLW(0x39) → ROL32(5) → lo64, CI in hi32.
FField NamePrivate: XOR(0x8FFAB191C340B792) → ROL16(12) → PSHUFB([07,06,04,05,02,03,00,01]) → ROL64(32).
PropertyOffsetXor: 0xA271DBC5. Field offsets shifted +0x50 from CL-1299607.
FName shard hash uses `-109*T+82` slot-select formula (NOT `H^(H>>16)` like CL-1299607).

SDK stats (2026-07-21): 85831 classes/structs (21315 classes, 64516 structs), 2939 enums, 61564 functions, 310065 properties (309085 named), 0% FProperty_Unknown, 192 skeletons, 9338 bones.

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
| `qd_engine.h` | QuickDecrypt micro-program interpreter (record/replay/codegen SIMD chains) |
| `insn_decoder.h` | Zydis 4.0 wrapper — InsnType enum, DecodedInsn, InsnDecoder |
| `func_analyzer.h` | Function analysis — ROL pair detection, SIMD/LEA target extraction |

### Discovery Phases (auto_discovery.h)
0. Module bounds (PE header parse)
1. Engine vtable discovery (score-density clustering of GObjectArray seed objects)
   - 1.5: Dedup + anchor-based correction
   - 1.6: ScriptStruct oracle validation (main.cpp)
2. FField NamePrivate XOR key extraction
3. FProperty Offset_Internal XOR key + bswap extraction
4. UObject slot decrypt params (PSHUFB mask + PXOR constant + ROL64 amount)
   - 4c: QD generic slot recorder (records arbitrary SIMD chain via Zydis, histogram consensus)
5. FName function RVA (via xor+bswap caller-frame anchor)
6. GNamePool base (call-chain .data LEA walk from FName fn)
7. FName keystream table (clustered .rdata loads in FName call chain)
8. FFieldClass globals (5-arg constructor pattern)
9. USkeleton BoneInfo offset (auto-probed via bone hierarchy invariant on sample objects)

### What Auto-Discovers vs. Hardcoded
**Auto-discovers (survives patches zero-touch):**
- PE binary base, module bounds
- 6+ RVAs via sig-scan
- FName decrypt entry function
- FName XOR/ROL constants (extracted from function body)
- FProperty Offset XOR key
- UObject slot decrypt SIMD params (+ QD-recorded generic program)
- GNamePool base + keystream table
- USkeleton BoneInfo TArray offset (hierarchy-validated auto-probe)
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

### CL-1325322 FName Pipeline (live-verified 2026-08-08, `ArcDecrypt::v20260808`)
```
GNamePool @ RVA 0xE431980 (inline .data array, NOT a pointer — the heap-probe
tie-breaker in Phase 6 picks the wrong candidate on this patch).
Keystream  @ RVA 0xE3707F4, uint16[160], decrypt entries start at index +44.

CI → chunk: identity (SIMD chain across sub_1402319F0/B120/AAE0 cancels)
  NameOff = CI & 0xFFFF, ChunkOff = (CI >> 8) & 0xFFFF00

Shard Hash (FNV32, SHR-based — the disasm at 0x140231AD9, NOT the pseudocode):
  SeedAddr = ChunkAddr + 0x4C90
  Lo = lo32(SeedAddr), Hi = hi32(SeedAddr)
  H = (Lo >> 4) * P + 0x46BD406E
  H = (H  >> 3) * P
  H = H + Hi + 0x46BD406E
  H = (H  >> 4) * P + 0x46BD406E
  H = (H  >> 3) * P + 0x46BD406E
  S = H ^ (H >> 16)
  Bidx1 = S & 7, Bidx2 = (S + 1) & 7

Block Decode (8 blocks at ChunkAddr + 0x4CA0, stride 32):
  Block = ROL64(PSHUFLW(raw, 0x93) ^ 0x07C3784BD4ECB382, 15)

FNV64 Chain:
  Fv1 = 0x100000001B3 * ROL64(V13, 40) + 0xBB3A9A3B042493AE
  Fv2 = 0x100000001B3 * ROL64(Fv1, 57) + 0xBB3A9A3B042493AE
  RawPtr = V13 + (V15 ^ Fv2) + 2*NameOff

Pointer XOR Chain (unchanged shape):
  Step1 = bswap64(RawPtr ^ 0x3E9E7ED8)
  Step2 = Step1 ^ 0x0000801B00000000
  EntryPtr = bswap64(Step2 ^ 0xD87E1E2500000000)

String Header (16-bit):
  length = (hdr >> 5) & 0x3FF
  isWide = (hdr & 0x8000) != 0          <-- moved from 0x20
  bytes  = isWide ? ((hdr >> 4) & 0x7FE) : (hdr >> 5)

String Decrypt (sub_140230020) — linear schedule, the v709 LCG is gone:
  K = (length + 34) & 0xFF
  per pair: buf[i]   ^= KeyTable[(K & 0x3F) + 44] >> 3   (narrow; wide skips >>3)
            buf[i+1] ^= KeyTable[((K + 11) & 0x3F) + 44] >> 3
            K = (K + 22) & 0xFF
  odd tail: one more with (K & 0x3F) + 44
```

Phase 6.7 (`DiscoverV808Pipeline`) pins both anchors against known plaintext
instead of sig-scanning: CI=0 must decode to "None" (4-char narrow), then the
keystream is found by sweeping .data/.rdata for the table satisfying the 4-byte
"None" constraint, and the whole thing is confirmed by decoding "ByteProperty".
Zero hardcoded RVAs on the hot path.

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
| USkeleton::BoneInfo | — | — | — | — | — | +0xE8 (auto-probed) |

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
- IDA instances: `jat2` (CL-1325322, **base 0x140000000** — IDA addr = 0x140000000 + RVA),
  `oo5g` (older PioneerGame-e_dumped.exe), `3q7c` (CL-1195482)
- ⚠️ IDA base differs per instance. `oo5g`/`3q7c` are based at 0 (subtract
  0x140000000 from live RVAs); `jat2` is based at 0x140000000 (add nothing).
  Check with a known byte before trusting an address — e.g. RVA 0x231B51 must be
  `49 BA 82 B3 EC D4 4B 78 C3 07` (movabs r10, BLOCK_FNV_XOR).
