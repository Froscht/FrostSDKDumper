# FrostSDKDumper — Consolidated Reference

## Project Overview
External SDK dumper for ARC Raiders (Unreal Engine 5, Theia-obfuscated). Reads game memory via `/dev/memreader` kernel module (or `process_vm_readv` fallback). Outputs `SDK_Output.txt` + `generated_decrypt.h` + `dump_bones.txt`. Runs on Linux against Wine-hosted game process.

Build: `g++ -std=c++17 -O2 -march=native -mavx2 -msse4.1 -I KernelDriver/include -o FrostDumper main.cpp build/Zydis.o -lcapstone -lunicorn -lm`
Run: `sudo ./build_and_run.sh [PID]`

## Current Patch: Steam build 24710327 / CL-1341255 (2026-08-18)
Image size **0x116E7000**, game version 1.42.x. Offline work used the EasyDump
image `pioneer_steam_1.42.x-CL-1341255_2026_08_18__11_32_82pct.exe` (flat, so
file offset == RVA); IDA instance `vv9q`, **base 0x140000000**.
**FULLY REVERSED AND LIVE-VERIFIED 2026-08-18 vs PID 190094** — 297644 / 297663
objects named (0 failed, 0 empty), 181516 distinct names, 0.0% FProperty_Unknown.

### Theia changed SHAPE here, not just addresses
This is the important thing to internalise before triaging the next patch. Every
previous patch moved constants; this one replaced primitives:
- the UObject slot decode is now **PCLMULQDQ** (carry-less multiply over GF(2)),
  where every earlier build used shuffle/rotate/xor chains
- the chunks_manager lost its **vtable-and-thunk indirection entirely** — no PEB
  salt, no thunk interpreter, no 37-vtable pool
- **UObject::InternalIndex moved from +0x0C to +0x90**
- the FNameEntry header changed field layout (plain 10-bit length, wide = sign bit)
- FField::NamePrivate gained a key again, and its second stage is a per-dword
  **PADDD**, not an XOR

Consequence: a pipeline built from the previous shape does not fail loudly, it
returns plausible numbers. Every stage therefore self-tests against plaintext
(`CI=0 == "None"`) or an invariant, and the v818 code path is kept separate from
v811 rather than parameterised into it.

### Verified constant sheet (v20260818)
```
GNamePool          RVA 0xE35AB00
FName resolver     RVA 0x236220        (the only 4 sites of `and r32, 0xFFFF00`
                                        in .text are this family — best anchor)
keystream table    RVA 0xE2997F4, decrypt window at +0xA0 (0xE299894)
KEY_INIT_ADD       0xD917
chunks_manager     RVA 0xE616340       standalone encrypted 16B global
UObject::GetFName  RVA 0x364780
slot decoder       RVA 0x3550C0        shared leaf; constants passed per site

CI decode: identity.  NameOff = CI & 0xFFFF ; ChunkOff = (CI >> 8) & 0xFFFF00

Shard hash (P = 0x1000193, ADD = 0x30091BB7), SeedAddr = ChunkAddr + 0x6FD0:
  H = ROL32(Lo, 0x17) * P + ADD          ; ROL-based again, not SHR-based
  H = ROL32(H, 0x15) * P + Hi + ADD
  H = ROL32(H, 0x17) * P + ADD
  H = (H >> 0x0B) * P + ADD
  S = H ^ (H >> 16) ; B1 = S & 7 ; B2 = (S + 1) & 7

Block decode (8 blocks at ChunkAddr + 0x6FE0, stride 32) — no shuffle stage:
  D = ROL32_perdword( ROL64(raw, 4) ^ 0xF31D220392B6800B, 2 )
  block xor constant at RVA 0xB3BEC30
FNV64 (P64 = 0x100000001B3, ADD64 = 0x6463CD794F959557):
  Fv1 = ROL64(V13, 0x30) * P64 + ADD64
  Fv2 = ROL64(Fv1, 0x2E) * P64 + ADD64
  EntryPtr = V13 + (V15 ^ Fv2) + 2*NameOff      <-- no pointer-xor chain at all

FNameEntry header (uint16 at EntryPtr, string at EntryPtr+2):
  length = h & 0x3FF        ; wide = (h & 0x8000) != 0
String decrypt (single cyclic sequence, +1 per element):
  K = length + 0xD917 ; index (K + i) & 0x3F
  narrow: buf[i] ^= (uint8)(KS[(K+i) & 0x3F] >> 3)
  wide  : buf[i] ^= KS[(K+i) & 0x3F]

UObject::GetFName (P = 0x1000193, ADD = 0xD4C2DB3A), Seed = Obj + 0x10 (ADDRESS):
  H = ROL32(Lo, 0x19) * P + ADD
  H = ROL32(H, 0x0E) * P + Hi + ADD
  H = ROL32(H, 0x19) * P + ADD
  H = ROL32(H, 0x0E) * P + ADD
  S = H ^ (H >> 16)
  Name = Obj + 0x20 + ((S & 3) ^ 2) * 0x20 ; Class = S & 3 ; Outer = (S + 1) & 3
  A = slot[0..8) , B = slot[8..16)
  T = B ^ clmul_lo(0x0B6641A64F1B214D, A)
  V = clmul_lo(0x8FA21A13D9179A47, T) ^ A
  FName = ROL64(V, 32)   -> CompIndex = lo32, Number = hi32
```

### GUObjectArray (verified: NumElements 312137, 5 chunks, invariant 430/430)
Still a standalone encrypted 16-byte global — but the vtable indirection is gone,
so this build needs **neither the PEB sweep nor the thunk interpreter**.
```
Mgr = lo64( ROL32_perdword( PSHUFB( ROL64(xmmword[0xE616340], 50),
                                    [05 00 04 06 07 02 03 01] ), 22 ) )
  pshufb mask @ RVA 0xB3850F0
NumElements = bswap32( u32[Mgr + 0x0C] ^ 0xC460461F )
ChunkArray  = bswap64( u64[Mgr + 0x20] ^ 0xED46031B00000000 )
Chunk = ChunkArray[Idx >> 16] ; Item = Chunk + 20 * (Idx & 0xFFFF)
Object = *(Item + 0) ; FUObjectItem::Flags = u32[Item + 8]
UObject::InternalIndex = +0x90          <-- moved from +0x0C
```
The two clearest read sites are `sub_14032F845` and `sub_1402E8C5D`; both are
small, both carry the whole scheme inline, and they agree exactly.

### Layout (all live-verified)
```
UStruct::SuperStruct   +0xB0    UStruct::Children (UField)  +0xE0
UStruct::ChildProps    +0xF8    UStruct::PropertiesSize     +0x108
UClass::ClassCastFlags +0x130   UClass::ClassWithin         +0x128
UEnum::Names           +0xB0

FField::NamePrivate    +0x50    FField::Next        +0x60
FField::ClassPrivate   +0x70    FField::FlagsPrivate +0x78
FField::Owner          +0x80    (tagged, bit0=1 => UObject)

FProperty::Offset_Internal +0xA4   xor 0x7BDAAA72
FProperty::PropertyFlags   +0xC0
FProperty::ArrayDim        +0xD0   FProperty::ElementSize  +0xD8
sizeof(FProperty)          +0x100
FBoolProperty FieldSize/ByteOffset/ByteMask/FieldMask = +0x100..+0x103

Offset_Internal = bswap32(stored) ^ 0x7BDAAA72
FField::NamePrivate:  V = ROL32_perdword(enc ^ 0xFDF20AE0DF1B2EFB, 29)
                      V = PADDD(V, 0x020DF52020E4D105)      <-- ADD, not XOR
                      CompIndex = lo32( ROL64(V.lo64, 32) )
  key constants @ RVA 0xB3DB830 and 0xB3DB840
```

### How each piece was found — reuse this order on the next patch
1. **chunks_manager**: auto-resolve's stride-20 vote already named it
   (0xE616340, 399 of 767 sites, nothing else close). It only failed *validation*
   because the validator assumed the v811 vtable shape. Take the vote, then read
   the containing function instead of trusting the compiled decode.
2. **GetFName**: the AngelScript binding string `"FName GetName() const"` still
   works and is still the fastest route. It sits at RVA 0xBF7BD95, has exactly
   two rip-relative references in .text, and the `lea` immediately above the
   second one loads the native function pointer (RVA 0x364780).
3. **FName resolver**: scan .text for `and r32, 0xFFFF00`. That is the
   `ChunkOff = (CI >> 8) & 0xFFFF00` step and it occurs **4 times in the whole
   image**, all four in this family. Far sharper than any FNV-prime scan
   (10317 hits for the FNV-64 immediate alone on this build).
4. **FField / FBoolProperty**: the `PropertyBool.cpp` assert path again — three
   references, all in `FBoolProperty::GetCPPType`-style functions. The decompiled
   form reads the name at `a1 + 5` (+0x50), the size at `a1[13].m128i_i32[2]`
   (+0xD8) and the field mask at `a1[16].m128i_i8[3]` (+0x103), which pins
   sizeof(FProperty) at 0x100 without any probing.
5. **FProperty::SetupOffset**: `xor eax, imm32 ; bswap eax ; mov [rsi+disp]`.
   122 xor+bswap sites exist but only one stores through a `mov [reg+0xA4]`
   right after a `movzx eax, word [rdi+0x32]` — that is the site (RVA 0x432E44).
6. **Everything else was probed live** once names worked: SuperStruct by walking
   the hierarchy to Object -> 0, PropertiesSize by `FVector == 24`,
   ClassCastFlags by `Field == 1 && Struct == 9 && Class == 0x29`,
   Next by requiring ascending `Offset_Internal` along the chain.

### FField::Next was decisive this time
The trap documented for build 24653108 (Next ties with the UField/PropertyLink
list) did not bite here, because the ascending-offset test separated them
cleanly over 250 sampled chain heads:
```
+0x60   104 chains   104 ascending (100%)   334 distinct names   <- FField::Next
+0xF8   176 chains    98 ascending ( 56%)   482 distinct names   <- a link chain
+0xE8    69 chains    28 ascending ( 41%)
```
Hit count alone would have picked +0xF8 and been wrong. The ratio is the signal.

### Structural bugs this patch exposed in the dumper itself
Three were latent and only a shape change made them visible. All are fixed, and
all three are the same class of mistake — a gate that names pipelines explicitly
instead of asking what the pipeline can do:
- **Auto-resolve ran after the object array.** Phase 6.5 resolves the
  chunks_manager, and Phase 6.5 sat *after* GObjectArray init — so on the one
  day it matters it could not run at all. It is now `RunAutoResolve()`, called
  from Phase 0c before anything consumes it, and idempotent so the old call site
  is a no-op.
- **`AdoptV811` was gated on `ImageSize == v20260811::IMAGE_SIZE`.** A patch
  changes the image size by definition, so that gate guaranteed the pipeline was
  off exactly when it was needed. The gate is now the plaintext self-test the
  function already performs.
- **`ReadClassCastFlags` listed v811 and v808 by name.** v818 was not in the
  list, so the metaclass oracle was silently off and the weak vtable heuristics
  promoted asset instances to classes: 24634/55433 classes/structs instead of
  14983/8534, and 33931 fewer records dropped as non-types. This is the *second*
  time this exact gate has gone stale — when adding a pipeline, grep for
  `IsV8..Active` and update every site.
- **`GetPackagePtr` still decoded slots with the legacy decoder**, so every
  package resolved to nothing and the emitter synthesised `/Script/<ClassName>`.
  Every class header read `/Script/Actor.Actor`. Now it walks `GetOuterPtr` —
  which dispatches per pipeline — and takes the first name starting with `/`.

### Auto-resolve on this patch: 5/5 areas, all sabotage-verified
`auto_resolve818.h` + Phase 0c2. Everything the pipeline needs is extracted from
the binary and validated, so the next patch should need no source edit:
```
chunks_manager   global RVA, ROL64/PSHUFB/ROL32 shape, and BOTH encoded fields
                 (NumElements off+xor, chunk array off+xor). Anchored on the
                 stride-20 index idiom; validated by decoding the manager and
                 requiring the count in range and chunk[0] readable.
FName pipeline   pool, seed off, block base/stride, the whole shard hash as a
                 PROGRAM, block ROL64/ROL32/xor, FNV-64 add and both rotates,
                 key init, header masks, keystream window. Anchored on
                 `and r32, 0xFFFF00`; decided by CI=0 -> "None" plus a second
                 longer plaintext.
FField name      NamePrivate offset, both key constants, ROL32, ROL64 and
                 sizeof(FProperty). Anchored on the PropertyBool.cpp assert.
Offset_Internal  offset and xor, from the `movzx ; xor imm32 ; bswap ;
                 mov [reg+disp32]` encode site.
GetFName         seed off, hash program, slot base/stride/xor, both clmul
                 polynomials, final rotate. Anchored on the FNV-32 prime,
                 consensus over the Name-role copies.
struct layout    ChildProperties, FField::Next, FField::Owner, SuperStruct —
                 probed live, since no static anchor reaches them.
```

**Both hash chains are recorded as HashOp programs, not fixed op slots.** The
shard hash has been ROL-form (CL-1325322), SHR-form (24653108) and ROL-form
again (CL-1341255). A fixed-slot representation cannot express that without a
source edit, and expressing it as a program costs nothing.

**`FROST_SABOTAGE818=chunkmgr|fname|ffield|getfname|propoff|layout|all`** wrecks
the compiled defaults before auto-resolve runs, so every recovery path can be
fired on demand. Verified 2026-08-18 against PID 190094: each area individually,
and all six at once, recover to the identical dump —
```
                 clean            all six sabotaged
Classes          14979            14979
Structs          8562             8562
Properties       246509           246487
FProperty_Unknown 0.0%            0.0%
slot selector    400/400          loaded 6/400 -> auto-resolved 400/400 -> adopted
layout probe     agrees           +0x128/+0xE8/+0x40/+0x128 -> +0xF8/+0x60/+0x80/+0xB0
Offset_Internal  +0xA4 44 chains  previous +0x99 gives 0 -> extracted kept
```
A self-healing path that has never fired is unproven. Re-run this matrix after
touching any of it.

`FROST_AR818_DEBUG=<hex func rva>` prints why one specific candidate was
rejected. Reject histograms tell you the shape of the failure; this tells you
whether the function you care about reaches the extractor at all, which is a
different question and usually the one that matters.

### Four traps hit while building the 818 extractors
- **`||` short-circuit.** `IsCall = (In.type == INSN_CALL_RIP) || ReadCallRel32(...)`
  never ran the byte check, because the decoder already reports a relative call
  as INSN_CALL_RIP with `hasRipRel` clear. Every other GetFName field came out
  correct and only `DecoderRva` was zero — a shape check that is *almost* right
  returns a fully populated record with one zero in it. Evaluate the byte form
  first and unconditionally.
- **`ApplyOffsets818` re-asserting over adoptions.** It runs several times per
  session, so writing compiled defaults into the sheet silently undid whatever
  the earlier call had enabled. It now writes a default only where nothing
  better is known, gated on per-area `*818Resolved` flags.
- **A dependency cycle between two probes.** The Offset_Internal check walks
  chains and so needs the layout; the layout probe separates FField::Next from
  the property-link chains by ascending offsets and so needs Offset_Internal.
  With both sabotaged neither recovered. Broken by adopting the extracted
  offset in Phase 0c2 outright — the encode shape is specific enough to trust —
  and demoting the live check to a revert-on-strict-loss verification.
- **`Detail::ReadMovabs`.** The decoder does not report the destination register
  for `movabs r64, imm64`, and the destination is exactly what tells the two
  slot-decoder polynomials apart. Read it off the opcode.

### Theia's descriptor-literal cipher is now SOLVED, not decoded
CL-1341255 changed the PRNG's additive constant — 0xA7A3FF6B does not occur
anywhere in the image — so the hardcoded stream produced 10544 nameless
descriptors out of 10554. It is no longer hardcoded, and does not need to be:
```
the stream is seeded with ZERO, so it is identical for every string
only FIVE bits of it reach each position
=> per position, try all 32 keys and keep the one that turns the most
   ciphertexts into name characters
```
Candidates are every .rdata qword pointing into .rdata — no descriptor
structure required, so this survives a layout change too. Measured on
CL-1341255: **97.5% at position 0 over 174101 buffers, and only 3 of 84
positions agree with the compiled PRNG.** Result: 358 wrappers, 15533
descriptors, **14014 types / 27659 members / 10838 enum values**, and
**2054 of 2078 comparable enums match the live dump exactly** (the rest are
`_Max` spelling, one 91-char name past the keystream, and one `bone`/`Bone`).

Three things this took, each worth keeping:
- **Score by character FREQUENCY, not by a yes/no identifier test.** The binary
  test picks the right key, but by a 1% margin — many wrong keys also land
  inside the alphabet. Weighting by how often each character actually occurs in
  UE identifiers widens the same decision to ~1.6 nats. The frequency table is a
  heuristic, not a patch constant: C++ identifier statistics do not move when
  Theia rekeys.
- **The "still alive" alphabet is WIDER than the name alphabet.** Enum entries
  are stored fully qualified (`EnumName::Entry`) and CppType strings carry
  `<>,.`. Killing a buffer at its first non-identifier character killed exactly
  the long buffers the tail depends on: the solve stalled at 60 positions and
  silently truncated every qualified name longer than that —
  `ExecuteAndResetPeriod` came out as `ExecuteAndRese`. With `:<>,./ ` allowed
  the solve reaches 84.
- **Stop while the winner is still winning.** A wrong tail key corrupts long
  names instead of truncating them, which is the worse failure. Pushing past the
  margin gate to 82 positions produced `CustomizationItemWrap*ad`.

### Phase 6.4 had silently stopped running
`DiscoverFNameConsts()` returns early when the LEGACY FName decrypt function
cannot be located — which on any modern patch is always — and everything after
that point in the function went with it, the static-reflection phase included.
It never needed that function, only module bounds. Hoisted into
`RunTheiaStatic()` and called from Phase 0d. Two smaller fixes fell out:
- The `.text` reload tried fallback images only until one cleared an 80%
  threshold. How much live `.text` is readable varies run to run, so one run
  stopped at 283 wrappers / 10570 descriptors and the next reloaded and got
  358 / 15533 from the same binary. It now tries every image and keeps the best.
- **`ReadClassCastFlags` was used where `ReadClassCastFlagsChecked` belongs.**
  The unchecked read conflates "the oracle could not run" with "the flags really
  are zero", so on a run where the vtable clustering failed to find a Class
  vtable at all, 62208 records were decided by the weak vtable heuristic instead
  of 0, and the class count went 15338 -> 68403 against the same live process.
  This is the *third* incident of this exact class. When the oracle can run, its
  verdict is final — including its zero.

### Native (unreflected) fields are now emitted
Reflection only knows UPROPERTYs. `ULevel::Actors`, `APlayerCameraManager::LockedFOV`
and everything like them are plain C++ members with no markup, so no
reflection-driven dumper can see them — and they are exactly the fields worth
having. They are recovered from the HOLES between reflected offsets and typed by
reading the same address across live instances:
```
16B, 8-aligned, {ptr, num, max} sane and elements carry module vtables -> TArray<UObject*>
8B,  8-aligned, non-null in every instance and target has a module vtable -> <Class>*
4B,  finite and |v| in [1e-4, 1e9] across every instance                 -> float
4B,  all zero                                                            -> "?" (see below)
```
Sampling pools SUBCLASS instances too, since a subclass instance is layout
compatible for everything the base declares — without that, abstract and
near-singleton classes are unreachable: `APlayerCameraManager` has exactly one
live instance. Every entry carries `n=<samples>`; one sample is enough to prove
the offset exists and not enough to type it, and the output says so.

**All-zero is reported as `?`, never as `uint32_t`.** It is evidence of nothing,
and `LockedFOV` is precisely the trap: a float that reads zero whenever the FOV
is not locked. Printing a confident integer type there is worse than printing
nothing.

Yield on CL-1341255: **3072 classes carrying 149058 native fields.** Verified
against the two cases that motivated it —
```
ULevel                 +0x108 TArray<UObject*>   (Actors, live num=564 max=744)
                       +0x118 TArray<UObject*>   (ActorsForGC)
APlayerCameraManager   +0x3EC ?                  (LockedFOV)
                       +0x3F4 ?                  (LockedOrthoWidth)
```
`FROST_NO_NATIVE_FIELDS=1` turns the pass off.

**The names are NOT recoverable and no attempt is made to guess them.** They
exist nowhere in the binary. Deriving them from UE source field order is how
`LockedFOV` gets placed one field too far: the order is
`DefaultFOV, LockedFOV, DefaultOrthoWidth, LockedOrthoWidth`, so with
`DefaultFOV` at +0x3E8 and `DefaultOrthoWidth` at +0x3F0 reflected, LockedFOV is
the 4-byte hole at **+0x3EC**, not the one at +0x3F4. What settles it is the
disassembly, not the source order:
```
APlayerCameraManager::GetFOVAngle  (vtable +0x818)
  movss   xmm0, [rcx + 0x3EC]        ; LockedFOV
  ucomiss xmm0, 0 ; ja ret           ; return LockedFOV when > 0
  call    [rax + 0x790] ; movss xmm0, [rax + 0x58]   ; else CameraCache.POV.FOV
```
Use the emitted gap list to find the candidates, then read the function that
uses one to settle which is which.

### SDK output (2026-08-18)
```
Classes 14983   Structs 8534   Enums 2778   Functions 50615
Properties 246612 (246144 named)   FProperty_Unknown 0.0%
struct_props 174583   param_props 72029
Objects 297644/297663 named   unique names 181516
Skeletons 88   bones 2771
GWorld RVA 0xE782D78 (double-deref)
ClassCastFlags: 23514 records decided, 154240 instances dropped, 33931 non-types
```


## Signature sheet — cross-checked over 13 builds (2026-04-02 .. 2026-08-18)

Every pattern below was run against all 13 images in `ArcBinaryDumps/Steam`, and
where CLAUDE.md already records the answer for a patch, the extracted value was
compared against it. Hit counts are measured, not estimated. IDA byte order,
`??` = wildcard.

**Durable — found on all 13 builds:**
```
FProperty::SetupOffset          0F B7 ?? ?? 35 ?? ?? ?? ?? 0F C8 89 ?? ?? ?? ?? ??
  movzx r32,word[src+X] ; xor r32,KEY ; bswap r32 ; mov [dst+disp32],r32
  EXACTLY 1 hit on every build. imm32 = Offset_XOR, disp32 = Offset_Internal.
  Verified against the recorded values: CL-1299607 0x057F15E5/+0x94,
  CL-1325322 0x76C317A2/+0xB4, CL-1315578 0xA271DBC5/+0xE4,
  24653108 0xEE0CA1CB/+0xC4, CL-1341255 0x7BDAAA72/+0xA4, CL-1177146 +0xC4.
  6 of 6 documented cases exact. This is the sharpest signature in the image.

FName resolver / GNamePool      81 ?? 00 FF FF 00        (and r32, 0x00FFFF00)
                                25 00 FF FF 00           (and eax form)
  The ChunkOff = (CI >> 8) & 0xFFFF00 step. 5-10 raw hits per build; filtering
  to "followed within 40 bytes by a rip-lea into .data, with an FNV-32 imul
  inside the next 0x120 bytes" leaves EXACTLY ONE candidate on every build, and
  its lea target is GNamePool. Verified: CL-1299607 0xE4A3A00, CL-1315578
  0xE4F2A00, CL-1325322 0xE431980, 24653108 0xE38FA00, CL-1341255 0xE35AB00 —
  5 of 5 exact.

chunks_manager                  [48-4F] 8D [04|0C|14|1C|24|2C|34|3C]
                                        [80|89|92|9B|AD|B6|BF]
  `lea r64,[r + r*4]` with index == base — the FUObjectItem stride-20 index
  computation. 8.5k-16k sites per build; take the containing region, vote on
  the first `movdqa xmm,[rip+X]` into .data. Verified: CL-1341255 0xE616340,
  24653108 0xE64B260, CL-1195482-era 0xDDCB420 exact, CL-1325322 0xE6ED2A0
  which is the documented 0xE6ED190 + 0x110 (the blob, not the struct base).
  NOTE the SIB scale: it is 0x80|(X<<3)|X, not 0x00|(X<<3)|X. Getting that
  wrong finds thousands of sites and votes for the wrong global.

"FName GetName() const"         AngelScript binding string -> UObject::GetFName
  Present on all 13 builds, 2 rip-refs (1 on the two oldest). The `lea` right
  above the second ref loads the native function pointer.

".\\Runtime/CoreUObject/Private/UObject/PropertyBool.cpp"
  Present on all 13 builds with EXACTLY 3 rip-refs every time. Leads to
  FBoolProperty::GetCPPType, whose assert path carries the FField::NamePrivate
  offset, both key constants, the rotate, and — via its FieldMask test —
  sizeof(FProperty).
```

**FName-Index-Decrypt (Ersatz fuer das kaputte `Dec_FIndex`).** Die kursierende
Signatur `48 C7 07 00 00 00 00 48 83` trifft auf keinem Build eine FName-Funktion.
Zwei zulaessige Kopfformen, weil der Compiler das High-Dword mal sofort abspaltet
und mal in einem Register haelt:
```
A  48 8D [41|49|51|59|61|69|71|79] ?? 4? 89 ?? 4? C1 E? 20 C1 ?? ?? 69 ?? 93 01 00 01
B  48 8D [41|49|51|59|61|69|71|79] ?? 4? 89 ??             C1 ?? ?? 69 ?? 93 01 00 01
Name-Rolle: `83 E? 03` innerhalb 0x80, direkt gefolgt von `83 F? ??`
```
505-793 Treffer pro Build, nie null; alle sind echte Accessor-Koepfe (Verlaengern
um die zweite FNV-Runde aendert die Zahl nicht), und alle Klone dekodieren gleich.

**Fuer genau EINE Funktion** den AngelScript-String dazunehmen: Referenzen darauf
suchen, bis 200 Bytes rueckwaerts nach `48/4C 8D 05 disp32`, Ziel behalten wenn
Form A oder B innerhalb 0x100 passt. Das liefert auf 13 von 14 Builds genau einen
Kandidaten und trifft CL-1325322 0x343950 und CL-1341255 0x36477D exakt.

**Die Registerbelegung ist die Falle.** Eine Kopfsignatur mit festem `48 89 C2` /
`05` ist CL-1341255-spezifisch: CL-1325322 nutzt `49 89 D0` / `81 C2`, CL-1169740
laesst das `shr` weg. Mit fester Belegung findet man ueberall irgendwelche Klone,
aber nie den kanonischen - der Ein-Funktion-Weg faellt damit von 13/14 auf 1/14.

**Invariants, not signatures.** These occur everywhere and only serve to
generate candidates:
```
FNV-32 prime   69 ?? 93 01 00 01              78k-139k hits per build
FNV-64 prime   B3 01 00 00 00 01 00 00        7.5k-14k hits per build
```

**Build-specific — do NOT carry these forward:**
```
PCLMULQDQ  66 0F 3A 44        33 hits on every build BEFORE CL-1341255 (CRT
                              code), 242 on CL-1341255. Theia only moved the
                              slot decode to carry-less multiply on this patch.
FField PADDD decode           223 hits on CL-1341255, ZERO on all 12 older
                              builds. Pure v818 shape.
chunkarray xor+bswap          1 hit on CL-1341255, zero elsewhere.
FName block decode            2 on CL-1341255, 2 on CL-1299607/CL-1325322,
                              1 on CL-1195482, 0 on the rest.
```

The lesson the table makes concrete: **signatures that describe a SHAPE Theia
owns die within one patch; signatures that describe something the ENGINE needs
survive.** SetupOffset's encode idiom, the ChunkOff mask, the stride-20 index
and the two source strings are all the latter, which is why auto_resolve anchors
on those and never on a SIMD op sequence.

## Previous Patch: Steam build 24653108 (2026-08-11)
Image size **0x117E9000**. Offline work used a full module dump at
`module_dump_0x140000000.bin`; it is not kept in-tree (280 MB, one build
only) — re-pull it from the live process when a patch needs offline
analysis. Remember that two regions in it are encrypted at rest: the
keystream table and `.text 0x4BD000-0x4BDFFF`.
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

### FProperty subclass data starts at +0x120, and Inner is at +0x128
Inherited 0x138 from CL-1315578 reads past the FProperty allocation and
lands on the NEXT field in the chain. Every array's Inner then resolved to
the following property, so the synthetic `__Item` record collided with that
property in the ff_addr map and evicted it. Symptoms: `AActor::RootComponent`,
`ParentComponent` and `BlueprintCreatedComponents` missing from the dump, and
`Tags` typed as `TArray<FMulticastSparseDelegateProperty>` — the delegate that
follows it. Probing the live layout settles it:
```
+0x110, +0x118   link fields, both hold Next
+0x120           first subclass slot (FSet element, FStruct, FObject class)
+0x128           FArrayProperty::Inner
```
The check that proves it is element size, not pointer plausibility:
TArray<FName> gives 8 and TArray<FSoftObjectPath> gives 32 at +0x128, while
+0x110/+0x118 give the next field's size.

**Properties must be sorted before emission.** `best_at_ff` is an
`unordered_map`, so iterating it yields hash-bucket order and discards the
offset sort `ReadPropertyChain` already did. A layout dump in arbitrary
order looks like the offsets themselves are wrong.

**All of AActor's chain heads are legitimate.** +0xD0, +0xE8 and +0x100 walk
44 / 54 / 85 fields and every one of them is owned by the struct — they are
UE's PropertyLink / RefLink / DestructorLink orderings of the same set, not
foreign data. Do not "fix" the multi-head walk by dropping heads.

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

### Patch-day automation (auto_resolve.h, added 2026-08-11)
Phase 6.5, advisory. Relocates and re-extracts the two pieces that cost the
most manual reversing, then prints them against the compiled sheet so drift
is visible the moment a patch lands. On build 24653108 it recovers
**11/11 GetFName constants and the chunks_manager global exactly**, with no
hardcoded RVA on either path.

Three invariants Theia has never moved carry the whole thing:
```
FNV-32 prime 0x1000193      locates every slot accessor and the shard hash
FUObjectItem stride 20      locates the object-array access routine
CompIndex 0 == "None"       validates the whole FName pipeline
```

- **Slot accessors**: scan .text for `imul r32,r32,0x1000193` (the immediate
  sits 2 bytes after the 0x69 opcode either way, so scan the immediate and
  check backwards). 12468 functions carry 4+ of them, so prefilter on a
  `pshufb xmm,[rip]` within the first 256 bytes before decoding — that cuts
  to 222 and is what makes the pass affordable. **Do not cap the candidate
  list instead**: the real GetFName sat past a 2000-entry cap on this build,
  which produced "0 Name copies" and looked like a missing feature.
- **Classify by role before taking consensus.** Class / Outer / Name share
  one FNV chain and differ only in the slot adjustment (`S&3`, `(S+1)&3`,
  `(S&3)^2`). 194 / 19 / 9 copies of each here. Averaging over all of them
  yields a slot xor of 0 and a wrong final rotate, because only the Name
  copies carry those. The role split also hands you the Class/Outer slot
  offsets for free.
- **Theia's clones are free redundancy.** Take the per-field majority across
  copies rather than trusting whichever is found first; all 9 Name copies
  agreed on every value here. The RVA is deliberately not compared — which
  clone is found first carries no information.
- **chunks_manager**: the 20-byte FUObjectItem stride forces a distinctive
  index computation (`lea r,[r+r*4]` with index==base and scale 4, then
  `shl r32,2`). 734 such sites; take the containing function and the first
  rip-relative SIMD load from .data. 377 of them vote for 0xE64B260 and
  nothing else comes close. Validate by decrypting and checking the vtable
  lands in-module and its slot-6 thunk in .text.

**Coverage.** Auto-resolve now recovers the FName pipeline as well as the
slot accessors and the object array, all validated rather than assumed:
```
FName pipeline   8/8   pool, seed off, block base, block xor, FNV add/rol,
                       keystream window — anchored on the FNV-64 prime
                       0x100000001B3 and proved by CI=0 -> "None"
GetFName        11/11   anchored on the FNV-32 prime, consensus over 9 copies
FProperty        4/4    Offset_Internal +0xC4 and its XOR, ClassCastFlags
                       +0x1E8, PropertiesSize +0x110 — all four out of
                       FProperty::SetupOffset, anchored on `xor r32,imm32 ;
                       bswap r32`, the Offset_Internal encoding, which
                       appears essentially nowhere else
KEY_INIT_ADD     exact  0x7216, 154 votes across 116 table-load sites. It
                       cannot be derived from decoding — only its value mod
                       64 matters and the keystream sweep already absorbs
                       that — so it is read out of the string-decrypt sites,
                       found via a rip-LEA whose target sits just below the
                       resolved keystream window
FField layout    exact  ChildProperties +0x100, NamePrivate +0x70 and
                       Owner +0xA0, probed against the live object graph
                       after the array is up
FBoolProperty    exact  the four bytes at +0x120, from the 0x01010000 store
                       in SetBoolSize
FField::Next     reported, NOT adopted — see below
chunks_manager   exact  anchored on the FUObjectItem stride-20 idiom
```

**Owner is the sharpest FField test and needs no names at all.** It is a
tagged back-pointer, so for the right offset the field's owner IS the object
walked from: `(value & ~1) == obj` holds for 102 of the sampled fields and
for nothing else. Prefer it over name-based scoring wherever it applies.

**FField::Next is found but deliberately not adopted, and this looks
final.** The probe picks +0x80 correctly and the scoring was improved twice,
but no version separates it from its runner-up well enough to justify
overwriting a working offset:
```
names only, first field counted        14 vs 14   no separation at all
names reached through Next only        14 vs 14   still tied
+ ascending Offset_Internal, 3 links   53 vs 44   best, still not decisive
+ ascending, 5 links, 4 names          42 vs 40   tightening made it worse
```
Some other offset genuinely yields equally long ascending chains — plausibly
the UField list, which is a real linked list of real fields and so passes
every structural test Next does. Separating them needs a criterion that
distinguishes *which* list, not how well-formed it is.

Two mistakes on the way, both worth not repeating: an absolute score
threshold is the wrong instrument, because how many chains the seed sample
contains varies run to run; and counting the first field's name gives every
candidate an identical score, since that name decodes regardless of Next.

Reporting without adopting is the right end state. The value is in the log
for a human, and after the +0x150 incident a weak signal must never
overwrite a working offset.

**FBoolProperty cannot be anchored on its immediate alone.** The 0x01010000
store also initialises unrelated structures, and the most common
displacement is the wrong one (+0xB0, four sites, all vector inits). Nor
does a byte store follow it, contrary to what the CL-1325322 notes imply.
What does isolate it: skip `[rsp+...]` forms, then keep only displacements
just past the already-resolved `Offset_Internal` — FBoolProperty's bytes sit
immediately after the FProperty base. That leaves exactly one site.

**The FField probe is the one place where the weak-filter trap bites for
real.** Scoring candidates by "how many decode to a printable name" gave a
confident 80/80 for the wrong pair (+0x150 / +0xD8); adopting it cut the
property count from 281k to 7k. The fix is the rule already written in this
file — score DISTINCT names, never hit count — plus a chain walk that
requires at least three linked fields whose `Offset_Internal` values ascend.
With both, the correct pair wins with 18 valid chains and 136 distinct
names and the wrong one scores nothing. Do not weaken this back to a
per-field test.
`ReadClassCastFlags` was gated on `IsV808Active()` alone, so the metaclass
oracle was silently off on this patch — `GetClassPtrAuto` resolved fine and
the function returned 0 before ever reading the flags. With it on, the
reclass pass drops ~28k objects that merely looked like structs, which is
the intended behaviour: a non-null SuperStruct or a walkable
ChildProperties chain does not make something a type.
Three traps cost real time while building this and are handled explicitly:
- **The FNV-64 immediate is `B3 01 00 00 00 01 00 00`,** not
  `B3 01 00 00 01 00 00 00`. The wrong byte order finds zero sites and looks
  like the anchor does not exist.
- **The hash collector must stop at `S = H ^ (H >> 16)`.** Otherwise it runs
  on into the FNV-64 fold and swallows its 40/41-bit rotates as hash steps.
  Every constant still comes out correct and only the program is wrong, so
  the symptom is CI=0 resolving to garbage — which reads as a bad pool
  address, not a bad hash.
- **The keystream sweep must read LIVE memory.** Sweeping the module cache
  finds nothing, because the table is decrypted in place at load.

**The sheet is live, not compiled.** Everything auto-resolve can extract sits
in `ArcDecrypt::g_Sheet` (arc_decrypt.h), defaulted to the v20260811 numbers
and read by the v811 paths at runtime. A patch that only moves these values
no longer needs a source edit. Adoption order matters and is deliberate:
the chunks_manager global is adopted in Phase 6.5 straight away because its
validator already decrypted it and checked the vtable/thunk, while the slot
values are only *staged* there — they cannot be judged until objects exist.
Phase 7.5 scores them and swaps them in only if they beat what is loaded.

**Self-healing is verified on every area.** FField offsets sabotaged to
0x148 / 0xB8 are probed back to 0x100 / 0x70 and adopted.

**Self-healing is verified on all three areas.** Sabotaging the property
offsets (`PropOffsetInternal` -> 0x99, `PropOffsetXor` -> 0x11223344,
`ClassCastFlagsOff` -> 0x77) changes nothing about the output: auto-resolve
recovers 0xC4 / 0xEE0CA1CB / 0x1E8 and the run produces the same property
count at 0.0% unknown.

**Self-healing is verified on both FName halves.** Sabotaging the FName side
(`PoolRva` -> 0xDEAD000, `KeystreamWindowRva` -> 0xBEEF000) still finishes at
a 100.0% naming rate: auto-resolve recovers 0xE38FA00 and 0xE2CE894 and
adopts them. Sabotaging `SlotShiftA` (3 -> 4)
and running against the live game: the loaded selector scores 104/400 =
26.0% (chance level), is rejected, the auto-resolved values score 400/400,
get adopted, and the run finishes at a 100.0% naming rate. Repeat that test
after touching any of this — a self-healing path that has never fired is
unproven.

The structural slot validator in `ScoreNameSlotSelector` exists for the bug
class that is otherwise silent: the name slot is identifiable *without* the
hash, because a decrypted name has CompIndex in the high dword and Number
(almost always 0) in the low dword, while pointer slots fill the low dword
and leave the high clear. Objects with exactly one such slot are ground
truth to score any candidate hash against. A wrong hash still returns a
plausible number and still picks *a* slot — it just picks the wrong one.

### Anchors that survived this patch
The AngelScript binding signature strings and the CoreUObject source-path
assert strings both still work and remain the fastest route to any
script-visible native function. Use them first on the next patch.

### Theia's descriptor-literal cipher — BROKEN (2026-08-17, theia_static.h)
Every `NameUTF8` in the generated `Z_Construct_*` descriptor tables is
encrypted at rest, and the ciphertext is identical in the module dump and in
live memory (they are decrypted on demand into a 255-byte stack buffer, not in
place at load). The cipher is a **PRNG stream seeded with zero** — decode loop
inside `ConstructU*` at RVA 0x4ED320, seed set by `xor ecx, ecx` @ 0x4ED3BF:
```
State' = ROL32(State * 0x1000193 + 0xA7A3FF6B, 0x13)
State  = (State' + State) * 0x1000193
V      = (State & 0x1F) ^ (int8)Cipher          ; only 5 bits of key
Out    = Wrap(V)          ; branch-free cascade, keeps the result an identifier
  A = ((V-0x50) <u 0x2F) ? -47 : 0 ; if ((V-0x21) <u 0x2F) A =  47 ;  X = V+A
  F = ((X-53)  >=u 5)
  B = ((X-48)  <u 5)    ?   5 : F*5-5                                ;  Y = X+B
  C = ((Y-110) <u 13)   ? -13 : 0 ; if ((Y-97)  <u 13)   C =  13     ;  Z = Y+C
  D = ((Z-78)  <u 13)   ? -13 : 0 ; if ((Z-65)  <u 13)   D =  13     ;  W = Z+D
  E = ((W-80)  <u 0x2F) ? 209 : 0 ; if ((W-33)  <u 0x2F) E =  47     ;  Out = W+E
```
The **plaintext** NUL terminates; the ciphertext is NOT NUL-terminated, which
is why the game decrypts a fixed 254 bytes and then relies on strlen. Seed 0
means no PEB, no address salt, no live state: everything decrypts offline.
`TheiaStr::Encrypt` inverts it by searching the 256 candidate bytes per
position, which lets you *search* the binary for a known name's ciphertext.

Two dead ends that look right and are not:
- It is **not** the FNameEntry keystream cipher. Feeding the live keystream
  table through `KS[(K+i)&0x3F]>>3` produces garbage; there is no table here.
- The key is **not** positional. Identical ciphertext prefixes across strings
  of different length come from the stream restarting at State=0 per string,
  not from a position-indexed key. Both a purely positional key and every
  periodic key (4/8/16/32/64) are provably inconsistent with the data.

### Static descriptor layouts (build 24653108)
```
FPackageParams      +0x00 NameUTF8 (PLAINTEXT "/Script/X", stored inline at
                          params+0x20)      +0x08 SingletonFuncArray
                    +0x10 NumSingletons     +0x14 PackageFlags (0x10 CompiledIn)
                    +0x18 BodyCRC           +0x1C DeclarationsCRC
FEnumParams         +0x00 OuterFunc  +0x08 DisplayNameFunc  +0x10 NameUTF8
                    +0x18 CppTypeUTF8  +0x20 EnumeratorParams  +0x28 ObjectFlags
                    +0x2C NumEnumerators (u16) ; FEnumeratorParam = {char*, i64}
FFunctionParams     +0x00 OuterFunc  +0x08 SuperFunc  +0x10 NameUTF8
                    +0x28 PropertyArray  +0x30 NumProperties (u16)
                    +0x32 StructureSize  +0x38 FunctionFlags  +0x3A flag byte
FStructParams       name at +0x18 (Outer/Super/StructOps precede it)
FPropertyParams     sizeof 0x38
                    +0x00 NameUTF8      +0x08 RepNotifyFuncUTF8
                    +0x10 PropertyFlags (u64)
                    +0x18 EPropertyGenFlags  <-- the usmap type enum
                    +0x1C ObjectFlags   +0x20 SetterFunc  +0x28 GetterFunc
                    +0x30 ArrayDim      +0x38 typed extension
                      e.g. FObjectPropertyParams: ClassFunc (Z_Construct_*_NoRegister)
```
`EPropertyGenFlags`: type in the low 6 bits (Int=0x03, Bool=0x0C, Object=0x12,
Array=0x16, Struct=0x19, Enum=0x1E, …), modifiers above (0x40 seen on bools =
NativeBool and on objects).

**Classes are NOT statically reachable and this looks structural.** Class names
do exist as ciphertext (`Encrypt("StaticMeshComponent")` finds 9 copies), but
nothing in .rdata points at the class-name copy and no `lea` in .text does
either: Theia passes those pointers as encrypted 16-byte blobs
(`ROL16(PSHUFLW(ROL64(p,55),0xB1),1)` to encode, inverse in the char*→FName
helper at RVA 0x232EC0). `FClassRegisterCompiledInInfo` tables are gone too — a
scan for {textptr, textptr, name, size, crc} yields 2 coincidences. This is the
same reason xref ranking never works on this target. The live pipeline resolves
classes at 100%, so the two routes are complementary.

### What the static sweep produced (verified against the live dump)
`theia_static.h`, Phase 6.4, advisory, writes `static_reflect.txt`. 0.5 s over
the whole image, no live state needed beyond a reader for the module bytes.
Against a COMPLETE module image (offline, e.g. the EasyDump `*pct.exe`):
```
359 package wrappers  15222 descriptors  13878 types
  2059 enums (10736 values)   5961 structs/functions (27147 members)
  5858 bare (no member array)  1344 no-name
```
In-process it now reaches the same numbers, but only because of an explicit
workaround, and the diagnosis took three wrong turns worth recording:
- `.rdata` reads live with **zero** gaps and is byte-identical to the offline
  image (313 FPackageParams and 174063 code pointers either way). Every
  descriptor is therefore reachable live. Only `.text` is a problem, and
  `.text` is needed *solely* to put a NAME on a package wrapper.
- The 28.5k unreadable `.text` pages are **not** the cause. Filling them from
  `module_dump_0x140000000.bin` changed nothing: 146 of 359 wrappers either
  way. The real cause is that live `.text` pages which read *successfully*
  still hold different bytes than an externally unpacked image — the wrapper
  prologue with `lea rdx,[rip+FPackageParams]` simply is not there yet.
- So `Run()` reloads `.text` wholesale from a full image when the wrapper yield
  falls below 80% of the FPackageParams count. `module_dump_*.bin` is useless
  for this (the sig scanner builds it from the same live reads — it yields 0
  wrappers); the EasyDump `*pct.exe` yields all 359. With that, a live run
  produces exactly the offline result: 359 / 15222 / 13878 / 27147.

Two traps in the fallback plumbing:
- A successful read of an all-zero page is not a fill. Accepting it retires the
  gap and starves the next fallback, so `FillFromImage` rejects zero pages.
- A flat memory dump keeps the ORIGINAL section table, whose
  `PointerToRawData` describes the on-disk layout, not the dump. Deciding
  offset==RVA by comparing `VirtualAddress` with `PointerToRawData` therefore
  picks the wrong mapping and yields 0 wrappers. Decide by size instead: a
  dump spans the whole `SizeOfImage`.
Cross-check against `SDK_Output.txt`: **2049 of 2049 comparable enums match
exactly**, names and values. It started at 2048/2049, and the one disagreement
turned out to be a live-side bug that the static route exposed — see
FName::Number below. That is the payoff of having two independent routes: the
static one is ground truth for names, so it can audit the live one.

### Asset instances were being emitted as classes (fixed 2026-08-17)
`ReadClassCastFlags` returns 0 both when the oracle cannot run and when the
metaclass genuinely carries no CASTCLASS bit, and every caller read that as
"undecided" rather than "ordinary instance". The weaker vtable/reference
heuristics then promoted the object to a class. `ReadClassCastFlagsChecked`
separates the two cases (it also verifies the metaclass has an in-module
vtable) and the main loop drops a clean zero-flag object. `FROST_KEEP_INSTANCES`
restores the old behaviour.
```
emitted blocks              25314 -> 20290      records with size outside
types with no properties     6116 -> 1259         [0x28,0x100000]: 1012 -> 0
metaclass is not a type     12337 -> 7361
```
What went out: 4930 class blocks and 102 struct blocks — NiagaraEmitter 1503,
CharacterVisualPartOnlineItemDataAsset 261, SoundCue 184, NiagaraScript 178,
AnimSequence 126, SoundWave 97, StaticMesh 38 and so on. The 7361 that remain
"not a type" are all legitimate type metaclasses: ASClass 4956, ASStruct 2121,
SMBlueprintGeneratedClass 175, RigVM*/ControlRig* generated classes.
**Do not judge a dropped record by its name.** `AimAssistManagerComponent` and
`ACLAnimBoneCompressionSettings` read like classes and are not: the first is an
instance of `PioneerAimAssistManagerComponent`, the second an instance of
`AnimBoneCompressionSettings`. `dump_classes.txt` prints the real metaclass per
address and is the fastest way to settle such a question.

**Beware the header counts.** The `Classes:` / `Structs:` lines count records
before emission, not emitted blocks: 19716/28152 was printed for a file holding
25314 blocks. After this change the header reads 14647/8358 while the file
actually lost only 102 struct blocks. Measure the file, not the banner.

### UStruct chain head +0xE0 was missing (fixed 2026-08-17)
`kChainOffs` listed 0xB0, 0xB8, 0xC8, 0xD0, 0xE8, 0xF0, 0xF8, 0x100, 0x108,
0x110, 0x118, 0x120 — but not 0xE0, which is the densest head on this build.
Over 250 sampled healthy types, walking each candidate and decoding
`Offset_Internal`:
```
head    chains  fields  ascending          head    chains  fields  ascending
+0xE0    232     2203     229              +0xE8     55     1358      40
+0x100   189     1316     189              +0xF0     54      376      54
+0xD0    160     1815     156              +0xF8     59       59      59
```
Against the union of all twelve other heads it still contributes 72 offsets on
23 of 244 objects. Live effect on the dump: member lines 225720 -> 234977
(+4.1%) and 112 fewer types with no properties at all. Found by diffing against
an independent dumper (`Analyze/anothersdk.txt`) that uses 0xE0 as its *only*
ChildProperties offset.

That dumper is also a warning about comparing raw counts: it flattens
inheritance, so `StaticMeshComponent` re-lists `ActorComponent`'s fields even
though it declares `: public MeshComponent`. Of its 126088 member lines only
40823 are own properties (offset >= its `Inherited:` value). On the 9797 shared
type names, own-vs-own, this dumper has more members on 4922 types and it has
more on 13.

### FName::Number was being dropped (fixed 2026-08-17)
An FName is `{ComparisonIndex, Number}` and UE splits a trailing number off the
literal when interning it: `H5_5` is stored as the entry `H5` with Number 6,
and `ToString` re-appends `_(Number - 1)`. `ReadEnumEntries` read only
`Read<int32_t>(ep + 0)` and threw the Number at `ep + 4` away, so every such
name came out truncated — `EEmbarkUITextType` had `H5` twice, at 4 and at 5.
Fixed via `FNameDecryptor::CompIndexToNameNumbered`. Effect on the dump:
```
duplicate entry names within an enum   10 across 5 enums  ->  0
entry names carrying a number suffix    2                 ->  20
```
The 18 recovered names are all genuine: `PF_PLATFORM_HDR_0/1/2`, `CP_1`..`CP_7`,
`ACLRF_Quat_128`, `ACLVF_Vector3_96`, `Limited_24_8`, `MP_Bink_Sound_51/71`,
`PCM_16`, `H5_5`. Only the enum-entry path is fixed; the general object and
property name paths still resolve a bare CompIndex, which is harmless for types
(their Number is 0) but would truncate instance names the same way.

For structs/functions: 5254 of 5956 static types also appear as live
class/struct blocks, and 1175 members across 1015 types are missing from the
live output. The 702 "only static" types are NOT missing live — they are
delegate signatures that the live dump emits as *functions* instead of blocks,
so a Class/Struct-block comparison undercounts. Do not read that number as
coverage.

**Loose descriptor discovery is noise — measured, not assumed.** Accepting any
.rdata position whose +0x00 is a code pointer raises struct/func records from
5961 to 33875, but exact member agreement against the live dump stays flat
(4239 -> 4237 types) while missing members climb 1175 -> 6412 and 8452 names
duplicate. A middle road that recovers wrappers by voting on OuterFunc values
seen in .rdata (>= 3 valid-looking descriptors each) gives 1803 wrappers and
26163 records, still with 2130 missing members and 3212 duplicates. So the
sweep stays keyed on the .text-derived wrapper set; the vote lives behind
`FROST_THEIA_VOTE=1`. Judge any change here by member agreement, never by
record count.

**Open item before this can feed a usmap: property ORDER differs between the
two routes.** `InstancePointDamageSignature__DelegateSignature` is
`InstanceIndex, Damage, InstigatedBy, HitLocation, ShotFromDirection,
DamageType, DamageCauser` in the descriptor's PropertyArray and
`InstigatedBy, HitLocation, ShotFromDirection, DamageType, DamageCauser,
InstanceIndex, Damage` live (the SDK sorts by offset). Neither is the reverse
of the other, so which one matches UE's unversioned-serialization schema order
is still unproven — settle that before trusting either for a usmap.

### Asset extraction: the paks are neither encrypted nor compressed (2026-08-17)
All 28 `.utoc` in `PioneerGame/Content/Paks` (TOC version 5, header 0x90):
`ContainerFlags` = 0x04 on global.utoc (Signed) and 0x0C on the other 27
(Signed|Indexed) — `Encrypted` (0x02) is never set and `EncryptionKeyGuid` is
all zero. `CompressionMethodNameCount` is 0, so chunks are stored raw: no AES
key to recover and no Oodle dependency. The only missing piece for
mesh/material/texture extraction is a `.usmap`, and none ships with the game.

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
| `auto_resolve.h` | Patch-day extraction for the v20260811 shapes |
| `auto_resolve818.h` | Patch-day extraction for the CL-1341255 shapes (Phase 0c2) |
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
| Field | CL-1177146 | CL-1177678 | CL-1201801 | CL-1233465 | CL-1299607 | CL-1315578 | 24653108 | CL-1341255 |
|-------|-----------|-----------|-----------|-----------|-----------|-----------|----------|------------|
| FField::NamePrivate | +0x70 | +0x30 | +0x40 | +0x90 | +0x40 | +0xA0 | +0x70 | +0x50 |
| FField::Next | +0x80 | +0x48 | +0x50 | +0xB0 | +0x60 | +0x78 | +0x80 | +0x60 |
| FField::ClassPrivate | +0x90 | +0x50 | +0x60 | +0xC0 | +0x70 | +0xB8 | — | +0x70 |
| FField::Owner | +0x10 | +0x10 | +0x70 | +0xA8 | +0x58 | +0x80 | +0xA0 | +0x80 |
| FProperty::Offset_Internal | +0xC4 | +0x88 | +0x94 | +0xE4 | +0x94 | +0xE4 | +0xC4 | +0xA4 |
| FProperty::ElementSize | — | — | +0xC8 | +0x118 | +0x7C | +0xD0 | +0xF8 | +0xD8 |
| FProperty::ArrayDim | — | — | +0xC0 | +0x110 | +0xC0 | +0x110 | +0xF0 | +0xD0 |
| FStructProperty::Struct | +0x108 | +0xC8 | +0xE8 | +0x130 | +0xE8 | +0x138 | +0x120 | +0x100 |
| FArrayProperty::Inner | +0xF0 | +0xC8 | +0xF8 | +0x140 | +0xE8 | +0x138 | +0x128 | +0x108 |
| FBoolProperty::FieldSize | — | — | +0xF0 | +0x138 | +0xE8 | +0x138 | +0x120 | +0x100 |
| UStruct::ChildProperties | +0x168 | +0xB0 | +0x108 | +0x118 | +0xC8 | +0xF0 | +0x100 | +0xF8 |
| UStruct::PropertiesSize | — | — | +0x110 | +0xE0 | +0x90 | +0xD0 | +0x110 | +0x108 |
| PropertyOffsetXor | — | — | 0xBAB939DB | 0xEAABEC11 | 0x057F15E5 | 0xA271DBC5 | 0xEE0CA1CB | 0x7BDAAA72 |
| USkeleton::BoneInfo | — | — | — | — | — | +0xE8 (auto-probed) | +0xE8 | +0xE8 |

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
- IDA instances: `vv9q` (CL-1341255, **base 0x140000000**), `jat2` (CL-1325322, **base 0x140000000** — IDA addr = 0x140000000 + RVA),
  `oo5g` (older PioneerGame-e_dumped.exe), `3q7c` (CL-1195482)
- ⚠️ IDA base differs per instance. `oo5g`/`3q7c` are based at 0 (subtract
  0x140000000 from live RVAs); `jat2` is based at 0x140000000 (add nothing).
  Check with a known byte before trusting an address — e.g. RVA 0x231B51 must be
  `49 BA 82 B3 EC D4 4B 78 C3 07` (movabs r10, BLOCK_FNV_XOR).
