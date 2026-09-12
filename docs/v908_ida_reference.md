# v908 (CL-1372005) IDA reference

Fixed_steam.exe, base 0x140000000. Anchors that survive Theia obfuscation for patch-day triage.

## GWorld / GameInstance / player state

### World hashtable lookup (world_resolve helper)
- **Renamed**: `World_HashTableLookup_v908` @ RVA `0x3B62750` (VA `0x143B62750`)
- **What it does**: reads a game-global hashtable seeded at `g_WorldHT_Entries` (RVA `0x10967B98`) — this IS the `World 0x10967B98` value hard-coded in NewESP `arc_offsets.h`. The function takes an object key `a1`, hashes it with a two-round FNV-shaped mix (constants `-2048144789` = `0x85EBCA6B`, `-1028477387` = `0xC2B2AE35`, i.e. the standard MurmurHash3 finalizer minus `-C2B2AE35`) and walks the collision chain at `entries + 24*idx`. Returns the value stored at `+8` from the matching entry — this is where the UWorld pointer ends up on the double-deref.
- **Signature (IDA)**:
  ```
  8B 05 ? ? ? ? 3B 05 ? ? ? ? 0F 84 ? ? ? ? 48 89 C8 48 C1 E8 ?
  89 C2 C1 EA ? 31 C2 69 C2 ? ? ? ? 89 C2 C1 EA ? 31 C2 69 C2 ?
  ? ? ? 89 C2 C1 EA ? 31 C2 48 8B 05 ? ? ? ? 48 85 C0 4C 8D 05
  ? ? ? ? 4C 0F 45 C0 8B 05 ? ? ? ? FF C8 21 D0 45 8B 04 80 41
  83 F8 ? 74
  ```
  Length 98, unique. Immediates wildcarded — durable across patches so long as the MurmurHash3-style finalizer body stays.
- **Xref anchor (fallback if signature dies)**: `g_WorldHT_Entries` sits at RVA `0x10967B98`. Any function that does `movsxd rax, dword_150967BA0` / `cmp` against `dword_150967BCC` on the same block is this family. Seven callers exist (see xrefs to `World_HashTableLookup_v908`); `sub_143B61CE0`, `sub_143DB9580` and `sub_144674E90` are the ones NewESP reaches through.
- **Renamed globals**:
  - `g_WorldHT_Entries` @ RVA `0x10967B98` (24-byte entry stride: `{key, value, next_idx}`)
  - `g_WorldHT_Count` @ RVA `0x10967BA0`
  - `g_WorldHT_Deleted` @ RVA `0x10967BCC`
  - `g_WorldHT_BucketsInline` @ RVA `0x10967BD0`
  - `g_WorldHT_Buckets` @ RVA `0x10967BD8`
  - `g_WorldHT_BucketMask` @ RVA `0x10967BE0`

### GWorld itself (double-deref)
- **Status**: not renamed — the direct GWorld pointer wrapper is reached only through `World_HashTableLookup_v908`; there is no standalone accessor with a stable string or FNV anchor visible on this build. NewESP calls `World_HashTableLookup_v908(key)` where the key comes from the calling actor and the returned value's `+0` qword is the UWorld pointer (i.e. the "double-deref" documented in CLAUDE.md).
- **UWORLD_BASE_RVA**: `0x10967B98` (live-verified 2026-09-08). Chain: `Read(base + 0x10967B98)` → intermediary wrapper → `Read(ptr + 0x00)` = UWorld.
    - Previous patch v818 baseline was `0xE782D78`.
    - Intermediary wrapper carries a vtable at VA `0x14DD21510` (RVA `0xDD21510`) — strongest durable anchor for the wrapper on v908. The vtable has **exactly 1 xref** in the whole image, from the wrapper's constructor. That constructor is the only place the vtable is stamped into an instance, so a single successful xref lookup lands you at the wrapper family root.
- **Renamed**: `World_WrapperCtor_v908` @ RVA `0x8C4E20` (VA `0x1448C4E20`) — the wrapper constructor that installs the vtable.
- **Signatures (IDA `generate_signature`, both unique):**
    - `World_WrapperCtor_v908` @ RVA `0x8C4E20` (53 bytes):
        ```
        41 56 56 57 53 48 83 EC ? 0F 29 7C 24 ? 0F 29 74 24 ? 48 89 CE E8 ? ? ? ? 48 8D 05 ? ? ? ? 48 89 06 48 8D 05 ? ? ? ? 48 89 86 ? ? ? ? C6 86
        ```
    - Vtable install site inside the ctor @ RVA `0x8C4E3B` (44 bytes):
        ```
        48 8D 05 ? ? ? ? 48 89 06 48 8D 05 ? ? ? ? 48 89 86 ? ? ? ? C6 86 ? ? ? ? ? 48 C7 86 ? ? ? ? ? ? ? ? C6 86
        ```
- **Xref fallbacks (in order of durability)**:
    1. Xrefs to the vtable at RVA `0xDD21510` — exactly 1 site (`World_WrapperCtor_v908`); use `mcp__ida-multi-mcp__xrefs_to` if the signature drifts.
    2. Xrefs to `g_WorldHT_Entries` at RVA `0x10967B98` — every intermediary read goes through it.
    3. `World_HashTableLookup_v908` at RVA `0x3B62750` — 7 callers, of which `sub_143B61CE0`, `sub_143DB9580` and `sub_144674E90` are the ones NewESP reaches.

### UGameInstance TLS decrypt
- **Status**: not located — none of `GameInstance` / `UGameInstance` / `PlayerController` remain as strings on this build (Theia stripped them), and the TLS-based decrypt (stage A at TLS+0xEE0, chain-through 8 blocks × 0x90 with the func at vtable+0x48) hides behind register-based `gs:[58h]` accesses that hash-collide with thousands of TLS reads elsewhere in the image. Signature-scanning this out of `.text` needs a runtime probe (uprobe on the decrypt callee) which is out of scope for a static rename pass.
- **Fallback for next-patch triage**: on Wine, `gs:[58h]` reads the TEB, TLS array follows. Anchoring on `mov rax, gs:[58h]` + `mov rax, [rax+38h]` + `lea r_, [rax+0EE0h]` (the stage-A pointer) is the durable pattern. Grep the disassembly for `65 48 8B 04 25 58 00 00 00` and filter for a subsequent `lea` with disp `0xEE0`.

### APlayerCameraManager::GetFOVAngle
- **Status**: not located — no `PlayerCameraManager` or `FOV` string remains. On v818 CLAUDE.md documents the anchor as vtable slot `+0x818` reading `movss xmm0, [rcx+0x3EC]` (LockedFOV). Reproducing that here needs a real UObject-vtable walk (identify APlayerCameraManager's vtable, index slot +0x818), which requires a live probe.
- **Fallback**: once GObjectArray is walked (see chunks_manager section, elsewhere in this doc), find an instance of the "PlayerCameraManager" class and read its vtable slot at `+0x818` to get the function VA. Then rename + resig.

### Actor/Pawn/PlayerState chain accessors
- **Status**: not located — Theia stripped these accessor names too. The reference dumper reaches them via fixed offsets from `arc_offsets.h`:
  - `AController::LocalPawn` @ +0x418
  - `APawn::PlayerState` @ +0x3F0
  - `APlayerState::PlayerNamePrivate` @ +0x468
  - `AActor::RootComponent` @ +0x250
  - `USceneComponent::RelativeLocation` @ +0x2A8
  - `ULevel::ActorArray` @ +0x110
  - `UGameInstance::LocalPlayers` @ +0xB0
  - `UPlayer::PlayerController` @ +0xA0
- These offsets are the durable anchor: patch-day updates to the offsets themselves get caught by SDK regeneration. The accessor functions are inlined at nearly every call site; standalone accessors with unique signatures are rare and not worth chasing.

## GObjectArray / chunks_manager

### chunks_manager decrypt — INLINED, not a standalone function
Theia inlines the entire chunks_manager decode-and-access sequence at every call site. There is **no** `ChunksManagerDecrypt` function to rename. The sequence is a 6-instruction SIMD chain (`movdqa` → `pxor` with key → per-word `psrlw 3` / `psllw 13` OR'd = ROL16(13) → `pshuflw imm 0x1B` → `movq rax, xmm0`) followed by a straight `bswap32(xor NUM_XOR)` for NumElements and a `bswap64(xor ARR_XOR)` for the ChunkArray pointer indirection.

The important globals ARE named — patch-day work is to update those RVAs, not to hunt for a call-site rename. Key RVAs:

| Global | RVA | Absolute VA | Content |
|---|---|---|---|
| `GObj_ChunksManagerBlob_v908` | `0x10D853F0` | `0x150D853F0` | 16-byte encrypted global; page not statically loaded (runtime-populated) |
| `GObj_ChunksManagerKey_A_v908` | `0xD4B22B0` | `0x14D4B22B0` | 16-byte key A — `4E 9E 17 86 0E B6 A8 D4` repeated |
| `GObj_ChunksManagerKey_B_v908` | `0xD4BD610` | `0x14D4BD610` | 16-byte key B — used in the `(blob & K2) \| (~blob & K1)` blend that collapses to `blob ^ K_A` because `K_B == ~K_A` |

### Canonical decode idiom — the anchor to sig-scan for on patch day

```asm
66 0F 6F 05 ? ? ? ?       ; movdqa xmm0, cs:GObj_ChunksManagerBlob_v908
66 0F EF ??               ; pxor   xmm0, xmm_key   (key was pre-loaded)
66 0F 6F ??               ; movdqa xmm1, xmm0
66 0F 71 D1 03             ; psrlw  xmm1, 3
66 0F 71 F0 0D             ; psllw  xmm0, 13
66 0F EB C1               ; por    xmm0, xmm1
F2 0F 70 C0 1B            ; pshuflw xmm0, xmm0, 0x1B
66 48 0F 7E C0            ; movq   rax, xmm0
```

Following that, both fields are read from the decoded manager pointer at fixed offsets:
```asm
8B 48 ??                  ; mov ecx, [rax+04h]              ; NumElements raw
BA A1 7A 49 BD            ; mov edx, 0xBD497AA1              ; NUM_XOR
31 D1                     ; xor ecx, edx
0F C9                     ; bswap ecx                        ; -> NumElements
...
48 8B 40 ??               ; mov rax, [rax+30h]               ; ChunkArray raw
48 B9 00 00 00 00 86 FB C7 6B  ; mov rcx, 0x6BC7FB8600000000  ; ARR_XOR
48 31 C8                  ; xor rax, rcx
48 0F C8                  ; bswap rax                        ; -> ChunkArray pointer
```
Grep the disassembly for `66 0F 71 D1 03 66 0F 71 F0 0D` (ROL16(13) fingerprint on adjacent xmm regs) — that byte pair is rare enough to survive Theia's next reshuffle.

### Renamed accessor functions
Each of these does one full inline decrypt-and-touch cycle. They are the durable xref anchors: rip-refs to `GObj_ChunksManagerBlob_v908` from a `movdqa xmm, [rip+X]` in `.text` reach one of these families every time.

| RVA | Old name | New name | Signature (IDA, unique) |
|---|---|---|---|
| `0x3A57B7` | `sub_1403A57B7` | `GObj_MarkObjectUnreachable_v908` | `48 83 EC ? 48 89 44 24 ? 56 57 48 83 EC ? 48 BF` |
| `0x43D46A` | `sub_14043D46A` | `GObj_IsMarkedUnreachable_v908` | via xref to blob at inline sequence, sig at inline `movdqa xmm0, cs:GObj_ChunksManagerBlob_v908` at `0x43D4D3` |
| `0x37E850` | `sub_14037E850` | `GObj_ProcessSubgraphRecursive_v908` | Recursive; two inline decrypt-and-access loops. Sig for the first inline site at `0x37E95A` |
| `0x449130` | `sub_140449130` | `GObj_ProcessGCPurgeList_v908` | `41 57 41 56 41 55 41 54 56 57 53 48 81 EC ? ? ? ? 66 0F 7F B4 24 ? ? ? ? 41 89 C8` |
| `0x44C7C0` | `sub_14044C7C0` | `GObj_GC_GatherUnreachable_v908` | `41 57 41 56 56 57 53 48 81 EC ? ? ? ? 66 44 0F 7F 84 24 ? ? ? ? 66 0F 7F BC 24 ? ? ? ? 0F 29 B4 24 ? ? ? ? 89 CF` |

For `GObj_GC_GatherUnreachable_v908` there is a secondary anchor: the wide string literal `L"GC.GatherUnreachable"` is passed as the async-task display name inside its body, so xref-scanning that string on any patch reaches it in one hop.

### Object registration site — inlined too, but reachable via `sub_140449130` callers
On v818 CLAUDE.md documents `sub_1404B0BF0(&unk_14E6ED190, Obj)` — a two-arg helper that grew a new object into the chunk table. On v908 this helper has been fused into the callers (`GObj_ProcessGCPurgeList_v908` and its parent) rather than kept as a standalone function; the "grow a new slot" write is `mov [chunk + 24*(idx & 0xFFFF)], obj_ptr` inline. Patch-day recovery for the write-side scan pattern: `mov [rax], rbx` guarded by a stride-24 `imul` or `lea r,[r+r*2]; shl r,3` idiom.

Note the stride-24 `lea r,[r+r*2]` idiom itself (SIB scale-2, idx==base) does not turn up on `find_bytes` scans of the loaded image — the `.text` pages carrying it are among the runtime-decrypted ones, same as `GObj_ChunksManagerBlob_v908` itself. Anchor on the SIMD idiom above (which IS loaded, always).

### Fixed layout offsets (`FUObjectItem` on v908)
- **Stride**: 24 bytes
- **Object pointer offset**: `+0x08` (moved from `+0x00` on v818's `UE 5.6` shape)
- **Flags**: `+0x10..+0x17` (upper 32 = flags, lower 32 = index — same qword the atomic OR at line 138 of `GObj_ProcessSubgraphRecursive_v908` touches)
- **`UObject::InternalIndex`**: `+0x90` (verify from any live item's `u32[Obj+0x90] == chunk_idx*65536 + slot`)
- **Items per chunk**: 65536 (`0x10000`)

### Recovery for next patch
1. Grep image for the ROL16 fingerprint `66 0F 71 D1 03 66 0F 71 F0 0D`. Every hit sits inside a chunks_manager decode. The rip-relative displacement in the preceding `66 0F 6F 05 ? ? ? ?` (`movdqa xmm0, cs:BLOB`) is the new `GObj_ChunksManagerBlob_v908` RVA. Update `arc_decrypt.h::v20260908::RVA_CHUNKMGR_GLOBAL`.
2. The `pxor` right after loads the key — the rip-relative displacement in `66 0F EF 05 ? ? ? ?` (if the register form isn't used) is the new key A RVA. Update `RVA_CHUNKMGR_KEY`.
3. `BD 497AA1` (little-endian) is the NUM_XOR immediate. `86 FB C7 6B` (little-endian, high half of a movabs) is the ARR_XOR upper 32. If those change, they appear next to the corresponding `bswap`.
4. Verify by decoding one chunk pointer and reading `u32[Obj+0x90] == 0` for chunk 0 slot 0 — that invariant catches any wrong field offset.

## Renamed function summary
| RVA | New name | Notes |
|---|---|---|
| `0x3B62750` | `World_HashTableLookup_v908` | Backs NewESP's `World` field access |
| `0x3A57B7` | `GObj_MarkObjectUnreachable_v908` | Textbook inline chunks_manager decode + `InterlockedCompareExchange64` flag |
| `0x43D46A` | `GObj_IsMarkedUnreachable_v908` | Walks +0x68 chain, then inline decode + flag test |
| `0x37E850` | `GObj_ProcessSubgraphRecursive_v908` | Recursively descends `+0x150` list, does two decode passes |
| `0x449130` | `GObj_ProcessGCPurgeList_v908` | Uses the `"G"` async-task tag; drains `qword_150D6FCC0` |
| `0x44C7C0` | `GObj_GC_GatherUnreachable_v908` | Async-task display name `L"GC.GatherUnreachable"` |

## Renamed globals summary
| RVA | New name |
|---|---|
| `0x10967B98` | `g_WorldHT_Entries` |
| `0x10967BA0` | `g_WorldHT_Count` |
| `0x10967BCC` | `g_WorldHT_Deleted` |
| `0x10967BD0` | `g_WorldHT_BucketsInline` |
| `0x10967BD8` | `g_WorldHT_Buckets` |
| `0x10967BE0` | `g_WorldHT_BucketMask` |
| `0x10D853F0` | `GObj_ChunksManagerBlob_v908` |
| `0xD4B22B0` | `GObj_ChunksManagerKey_A_v908` |
| `0xD4BD610` | `GObj_ChunksManagerKey_B_v908` |

## Missing / needs live probe
| Item | Why | Next-patch workaround |
|---|---|---|
| GWorld standalone accessor | No such function on v908 — access is always through the hashtable | Call `World_HashTableLookup_v908` with the actor's own key |
| `UGameInstance` TLS decrypt | Bare `gs:[58h]` reads have too many false positives to statically pin | Wire a uprobe on any `stage_A[block].func_at_vt+0x48` site and read the resolved pointer |
| `APlayerCameraManager::GetFOVAngle` | Vtable +0x818 slot, needs a live vtable pointer for the class | After GObjectArray is up, find PlayerCameraManager instance → read `[vtable+0x818]` |
| Chain accessors (`GetLocalPawn`, `GetPlayerState`, `GetRootComponent`) | Almost universally inlined, no standalone accessor with stable signature | Use hard-coded offsets from `arc_offsets.h` — they are the durable anchor |

## FName pipeline

The pipeline is a two-function core plus heavily-inlined block/shard math.
Everything downstream (`ResolveEntry`, `DecryptNameString` in the dumper's
`auto_discovery.h::V908Detail`) is called through these two entry points.

### `FName_ResolverCore_v908` — `FNamePool::FindOrStore` core

- **RVA**: `0x2DA260` (VA `0x1402DA260`)
- **Purpose**: v908 FName resolver core. Byte-copies the 16-byte CI blob
  from `a3` into `a1`, one-shots the pool-init sentinel
  `byte_150AB5D98`, then decodes CI → `FNameEntry*` inline:
  - shard hash (FNV32 with `rol 19/13/19`, add `-1876097178 = 0x902D0766`)
  - block index via `((u8)(-109 * v9 + 102)) ^ ((u8)((P*v9 + A) >> 16)) & 7`
  - block decode `(blend collapses to XOR) → rol32(3) per-dword → paddd broadcast`
  - FNV64 fold `prime 0x100000001B3`, add `0x6292C37EFA7F5FA6`, rol 37 then 48
  - Pointer chain step 1: `bswap64(raw ^ 0x000000005D4B82B8)`
- **Byte signature (IDA)**:
  ```
  41 56 56 57 53 48 83 EC ? 0F 29 74 24 ? 49 89 D6 41 0F B6 00
  ```
  Unique (single occurrence).
- **Fallback anchors**:
  - Immediate `0x902D0766` (shard hash ADD) — the resolver is the one
    function that reaches it via three `imul r,r,0x1000193` within 40 bytes.
  - Immediate `0x100000001B3` FNV64 prime paired with immediate
    `0x6292C37EFA7F5FA6` in the same 24-insn window.
  - Reference to `unk_150AB5DC0` (pool base @ RVA `0x10AB5DC0`).
- **Callers**:
  - `0x2D5016` (in `sub_1402D4ECE`) — pool-state accessor
  - `0x2D580A` (in `sub_1402D56C0`) — pool-state accessor
  - `0x2DA564` (`FName_ResolverWrapper_v908`)
- **Notable inline constants / RIP loads**:
  - Pool base `unk_150AB5DC0` (RVA `0x10AB5DC0`)
  - Seed offset `0x2490`, block base `0x24A0`, stride 32
  - Slot XOR key at `xmmword_14D4D3C70`
  - Block blend keys at `xmmword_14D4D3C90 / C80 / CA0`
  - Block PADDD broadcast at `qword_14D4D3BC0`
  - Block2 XOR at `xmmword_14D4D3BB0`

### `FName_ResolverWrapper_v908` — public entry

- **RVA**: `0x2DA4A0` (VA `0x1402DA4A0`)
- **Purpose**: v908 outer wrapper around the resolver core. Copies 8 bytes
  into `a1`, applies XOR + ROL32(3) + PSHUFLW blend to the pool state,
  delegates to the core, then applies the final pointer chain XOR
  (`^ 0x0000516500000000`) on the way out. Second half of the three-step
  ptr chain — the third step (`bswap` in `FName_DecryptString_v908` header
  parse) closes it. Chain algebraically collapses to identity
  (`FNAME_PTR_CHAIN_IS_NOP = true` in the dumper).
- **Byte signature (IDA)**:
  ```
  41 56 41 55 56 57 53 48 81 EC ? ? ? ? 49 89 D6
  ```
  Unique.
- **Fallback anchors**:
  - XOR immediate `0x0000516500000000` — unique in the image.
    Byte pattern `00 00 65 51 00 00 00 00` as a `movabs` operand.
  - Callers list contains all 15 pool-state accessors plus
    `FName_DecryptString_v908` at `0x2BF29E`.

### `FName_DecryptString_v908` — name string decrypt

- **RVA**: `0x2BF200` (VA `0x1402BF200`)
- **Purpose**: takes a resolved `FNameEntry*`, parses the 16-bit header
  (bit 15 = wide, length = `((hdr >> 5) & 0x3F8) | (hdr & 7)`), then
  decrypts the payload using the keystream table at `unk_15095926C`
  (RVA `0x1095926C`).
  - Narrow byte-tap (short strings, `v7 < 0x28`): `Key = length + 0x2E0`,
    per-pair index `(K & 0x3F)+120` and `((K-1) & 0x3F)+120`,
    `Key += 0x67E` per pair. XOR by `ks[idx] >> 3`.
  - Narrow SIMD (`v7 >= 0x28`): 16-byte batches, unpacklo blends keystream
    halves, XOR full u16 shifted right by 3.
  - Wide byte-tap (`v7 < 0x50`): identical index schedule as narrow but
    no `>> 3` — the full u16 from keystream is XORed into the u16 char.
  - Wide SIMD (`v7 >= 0x50`): PSHUFB against `xmmword_14D4C0F10`,
    per-pair `Key += 1008`.
- **Byte signature (IDA)**:
  ```
  41 57 41 56 41 55 41 54 56 57 55 53 48 81 EC ? ? ? ? 48 89 D7
  48 8B 05 ? ? ? ? 48 31 E0 48 89 84 24 ? ? ? ? 83 79 ? ? 74
  ```
  Unique.
- **Fallback anchors**:
  - Immediates `0x2E0` (KEY_INIT_ADD) and `0x67E` (KEY_STEP_PAIR) inside
    the same function — this pair is the only site.
  - LEA against `unk_15095926C` inside a function consumed by the
    resolver wrapper.
  - Callers: 50+ heavy fan-in — any xref-walk from
    `FName_ResolverWrapper_v908` reaches it.
- **Notable constants**:
  - Keystream RVA `0x1095926C`, decrypt window at `+240` bytes (u16 idx `120`).
  - Header wide-bit `0x8000`.
  - Narrow shift `>> 3`, wide no shift.
  - SIMD PSHUFB masks at `xmmword_14D4D38B0` and `xmmword_14D4C0F10`.

### Block decode helper — inlined

There is no separate block-decode function. The sequence is emitted
inline inside `FName_ResolverCore_v908` around VA `0x1402DA3C1..0x1402DA414`:

```
pxor       xmm, xmmword_14D4D3CA0   ; blend + XOR collapses to plain XOR
pslld      xmm, 3                   ; ROL32 per dword (first half)
por        xmm, tmp                 ; second half of ROL
paddd      xmm, qword_14D4D3BC0     ; PADDD broadcast constant
```

Auto-resolver anchor: `pxor xmm,[rip+X]` followed within 8 insns by
`pslld xmm,3` and `paddd xmm,[rip+Y]` inside the resolver's ~0x230 bytes.

### FNV64 fold — inlined

Also inlined in `FName_ResolverCore_v908`, right after block decode:

```
movabs   r10, 0x100000001B3       ; FNV64 prime
imul     ...                      ; * ROL64(V13, 37)
add      r10, 0x6292C37EFA7F5FA6  ; + ADD
rol      r10, 48
imul     r10, 0x100000001B3       ; second imul
add      r10, 0x6292C37EFA7F5FA6  ; + ADD
```

FNV64 prime `0x100000001B3` and FNV32 prime `0x1000193` are the durable
invariants; neither has ever moved across UE 5.x builds.

### Pointer chain — collapsed to identity

The `FNameEntry*` pointer chain is three steps spread across three
functions:

1. `FName_ResolverCore_v908` — `bswap64(raw ^ 0x000000005D4B82B8)`
2. `FName_ResolverWrapper_v908` — `^ 0x0000516500000000`
3. `FName_DecryptString_v908` (header pre-parse) —
   `_byteswap_uint64(v47 ^ 0xB8821A3800000000ULL)`

The two XORs together are `0x0000516500000000 ^ 0xB8821A3800000000 =
0xB8824B5D00000000`, and `bswap64(bswap64(raw ^ 0x5D4B82B8) ^
0xB8824B5D00000000) = raw`. The dumper's `ResolveEntry` skips the chain
and uses `raw` directly; the source comment `FNAME_PTR_CHAIN_IS_NOP =
true` documents this.

### Constants that moved v818 → v908

| Constant | v818 (CL-1341255) | **v908 (CL-1372005)** |
|---|---|---|
| Pool RVA | `0xE35AB00` | **`0x10AB5DC0`** |
| Keystream RVA | `0xE2997F4` (window +`0xA0`) | **`0x1095926C`** (window at u16 idx `120`, byte +`0xF0`) |
| `KEY_INIT_ADD` | `0xD917` | **`0x2E0`** |
| `KEY_STEP_PAIR` | linear +1 per byte | **`0x67E` per pair** |
| Shard `SEED_OFF` | `0x6FD0` | **`0x2490`** |
| Shard `BLOCK_BASE` | `0x6FE0` | **`0x24A0`** |
| Shard `ADD` | `0x30091BB7` | **`0x902D0766`** |
| FNV64 `ADD` | `0x6463CD794F959557` | **`0x6292C37EFA7F5FA6`** |
| FNV64 rols | `48 / 46` | **`37 / 48`** |
| Block XOR | `0xF31D220392B6800B` | **`0x4F24BCC689EF2FA1`** |
| Block decode | `ROL64(4) ^ K → ROL32(2)` | **`(blend→XOR) → ROL32(3) → PADDD`** |
| Ptr chain step-1 XOR | (none — chain absent on v818) | `0x5D4B82B8` |
| Ptr chain step-2 XOR | — | `0x0000516500000000` |
| Ptr chain net effect | identity | identity |

### Renamed function summary (FName section)

| RVA | New name | Purpose |
|---|---|---|
| `0x2DA260` | `FName_ResolverCore_v908` | `FNamePool::FindOrStore` core, inline shard+block+FNV+ptr |
| `0x2DA4A0` | `FName_ResolverWrapper_v908` | Public entry, XOR/ROL/PSHUFLW preamble + final ptr XOR |
| `0x2BF200` | `FName_DecryptString_v908` | `FNameEntry*` header + keystream decrypt (narrow/wide × byte-tap/SIMD) |

### FName pipeline fallback playbook

If every above signature breaks in one patch, in order:

1. **Immediate `0x1000193` (FNV32 prime)** — always present. Filter to
   functions ≤ `0x300` bytes whose first `imul r,r,0x1000193` is
   preceded within 60 bytes by an `and r32, 0xFFFF00` — the CI →
   ChunkOff mask. That pair isolates the FName resolver on every build
   tested.
2. **Immediate `0x100000001B3` (FNV64 prime)** — filter further to
   functions that also contain the FNV32 prime and a paired `movabs`
   FNV additive constant.
3. **Pool base rip-relative LEA** — a `lea r64, [rip+X]` whose target
   is a ≥ `0x1000000`-byte `.data` block is very likely the FName pool.
   The dumper's auto-resolver already adopts that `X` as
   `Pool908Rva`; anything downstream in the same function is the
   resolver.

---

## FField / FProperty

Constants (all v908 ARC Raiders CL-1372005, base `0x140000000`):

| Constant | Value | RVA |
|---|---|---|
| `FFIELD_NAME_XOR_KEY`  | `0x0D58B9970DD2BBAF` | key at `0xD4DF960` |
| `FFIELD_NAME_PSHUFB`   | `{5,6,1,4,3,7,2,0}`  | mask at `0xD4DF950` |
| `FFIELD_NAME_ROL16`    | `13` | inline |
| `FFIELD_NAME_ROL64`    | `32` | inline |
| `FFIELD_NAME_OFFSET`   | `+0x90` on the FField | verified in decompile |
| `PropertyOffsetXor`    | `0xC2CEEE92` | inline in SetupOffset encode |
| `PropertyOffsetInternal` | `+0xB0` on the FProperty | store disp32 |
| `FBoolProperty::FieldSize offset` | **`+0xE0`** on FBoolProperty (v818 was +0x118) | verified |

### Renamed functions

| RVA | Name | Notes |
|---|---|---|
| `0x53E840` | `FProperty_SetupOffset_v908` | 0x53E size; encodes Offset_Internal via `xor eax,imm32 ; bswap eax ; mov [reg+0xB0],eax` at RVA `0x53ECC8` |
| `0x387AB0` | `FField_GetFNameForScript_v908` | AngelScript-registration path FField NamePrivate decode wrapper (size 0x75). Reads `[FField+0x90]`, PSHUFB → XOR → ROL16(13) → ROL64(32), then forwards to next helper |

### Byte signatures

| Purpose | Signature | Length | Unique | Site RVA |
|---|---|---:|---|---|
| **FProperty::SetupOffset encode idiom** | `0F B7 47 ? 35 ? ? ? ? 0F C8` | 11 | ✅ (1 hit whole binary) | `0x53ECC8` |
| **FProperty_SetupOffset entry** | too long (>1000) | — | — | `0x53E840` |
| **FField_GetFNameForScript entry**  | `56 57 53 48 83 EC ? 4C 89 C3 48 89 D7 48 89 CE 48 8D 15` | 19 | ✅ | `0x387AB0` |
| **FField NamePrivate inline SIMD block** (PXOR + PSHUFB + PSLLW/PSRLW + POR + PXOR + ROL64) | `66 0F EF 05 ? ? ? ? 66 0F 6F C8 66 0F 71 D1 ? 66 0F 71 F0 ? 66 0F EB C1 66 49 0F 7E C0 49 C1 C0 ?` | 34 | ✅ | `0x387AE4` |
| **FBoolProperty init 0x01010001 store at [reg+0xE0]** | `C7 86 ? ? ? ? ? ? ? ? 48 89 F0 48 83 C4 ? 5E C3` | 25 | ✅ | `0x58E653` |

### Callers / xref anchors (fallback if a signature ever misses)

- `FProperty_SetupOffset_v908` has **30 direct callers**, all inside the constructor pipeline of individual `FXxxProperty` subclasses. The tightest small-caller cluster:
  - `sub_1403F80A0` (size 0x134) — likely `FIntProperty` ctor
  - `sub_14043A000` (size 0x112) — likely `FBoolProperty::SetupOffset` chain
  - `sub_140440410` (size 0x139)
  - `sub_140558700`, `sub_14055E800`, `sub_14055E920`, `sub_140568690`, `sub_14056CF10`, `sub_1405716F0`, `sub_14057DCA0` — the FXxxProperty ctor family. Landing on any one of these and following the call to `SetupOffset` is a bootstrap even without a signature.
- `FField NamePrivate XOR key` at RVA `0xD4DF960` has **50+ data xrefs** — it is inlined into every FField-name-decode site. If the wrapper `FField_GetFNameForScript_v908` is missed, use `find_bytes` for the 8-byte key `AF BB D2 0D 97 B9 58 0D` and take any caller that also references `0xD4DF950` (the PSHUFB mask) within 32 bytes.
- `FBoolProperty::SetBoolSize` inline store: pattern `01 00 01 01` inside a `C7 86 ?? ?? ?? ??`-prefixed `mov [reg+disp32], imm32` is present at exactly 6 sites in the whole binary. Only 1 (`0x58E653`) is followed by `48 89 F0 48 83 C4 ?? 5E C3` (the FBoolProperty prologue tail) — that's the anchor.

### Constants observed at `0x58E600 - 0x58E666` (FBoolProperty code fragment)

```
14058e600  mov     qword ptr [rsi+98h], 0            ; FField+0x98 = 0 (v908 sentinel)
14058e608  mov     rax, 100000001h                    ; PropertyFlags low = 0x00000001, high = 0x00000001
14058e612  mov     [rsi+0A0h], rax                   ; FProperty::PropertyFlags = 0x100000001
14058e619  mov     qword ptr [rsi+0B8h], 0           ; FProperty::???
14058e624  lea     rax, off_14D4DC010                 ; vtable
14058e62b  mov     [rsi], rax
14058e62e  mov     rax, 0FFFFFFEFBFFFFDFFh
14058e638  and     rax, [rsi+0A8h]
14058e63f  mov     rcx, 1000000000h
14058e649  or      rcx, rax
14058e64c  mov     [rsi+0A8h], rcx                   ; class-cast-flags-ish
14058e653  mov     dword ptr [rsi+0E0h], 1010001h    ; FieldSize=1,ByteOffset=0,ByteMask=1,FieldMask=1
14058e65d  mov     rax, rsi
14058e660  add     rsp, 20h
14058e664  pop     rsi
14058e665  retn
```

**Key finding**: FBoolProperty extended slot on v908 is at **`+0xE0`**, not `+0x118` as documented in `CLAUDE.md` for v818. Update the dumper's `FBoolProperty::FieldSize` offset if this ever gets exercised.

### FField / FProperty fallback playbook

If everything above breaks in one patch, in this order:

1. **FProperty::SetupOffset encode idiom** — the durable `0F B7 ?? ?? 35 ?? ?? ?? ?? 0F C8` pattern is 1-hit on all 13 builds tested. The `imm32` after `35` is the current-patch `PropertyOffsetXor`; the `disp32` in the following `mov [reg+disp32], r32` is `Offset_Internal`.
2. **FField NamePrivate XOR key** — the 8-byte constant sits in `.rdata`, always followed within 16 bytes by the `_mm_shuffle_epi8` mask (8 bytes, all values 0..7, no repeats — very distinctive shape). If the key value changed, scan for a `.rdata` qword whose next 8-byte neighbour is a permutation of `{0,1,2,3,4,5,6,7}`.
3. **FBoolProperty extended slot** — the `mov [reg+disp32], 0x01010001` store at the tail of the FBoolProperty ctor is the anchor. `disp32` is the current-patch FieldSize offset.

### Missing entries

- Standalone `FField_DecodeNamePrivate_v908` helper — the decode is inlined at 50+ call sites via the XOR key at `0xD4DF960`. There is no dedicated leaf function on v908; the one at `0x387AB0` is a wrapper that decodes + forwards. If a future patch factors the decode into a callable helper, look for a small (≤ 0x40 bytes) function that returns after the ROL64 stage.
- `FBoolProperty::SetBoolSize` as a distinct function — v908 inlines the four-byte init directly into the FBoolProperty constructor at `0x58E600`. There is no separate SetBoolSize routine to rename.
- The `PropertyBool.cpp` source-path string used as a v818 anchor is **absent** on v908 — either stripped by Theia or moved into the encrypted-at-rest region. Do not rely on that string on this build.



## Theia static / ConstructU*

### Theia_ConstructU_PRNG_v908
- RVA: `0x61E1E0`
- Purpose: PRNG stream loop that decrypts every `NameUTF8` in the `Z_Construct_*` descriptor tables. Seeded with zero, so identical across strings; only 5 bits of key reach each position.
- PRNG core @ RVA `0x61E35E` (inline inside the function):
    - `imul r32, r32, 0x1000193`
    - `add  r32, 0x400062AA`           (kAdd — was 0xA7A3FF6B on v818)
    - `rol  r32, 0x15`                 (rot — was 0x13 on v818)
    - byte tap `and reg, 0x1F` for the 5-bit key
- Wrap-byte prologue @ RVA `0x61E328` (inline):
    - `mov edx, -47 ; mov r8d, 47 ; mov r9d, 5 ; mov r10d, -13 ; mov r11d, 13 ; mov ebp, 209`
- Byte signatures:
    - PRNG core (unique): the sequence around `imul r,r,0x1000193 ; add r,imm32 ; rol r,imm8 ; and r,0x1F`
    - Wrap prologue (unique): the six back-to-back `mov reg,imm` with the exact constants above
- Fallback anchors when signatures drift:
    - FNV-32 prime `0x1000193` + `and reg, 0x1F` within 16 insns — 3 sites total, two of them inside `ConstructU_*` inlines
    - The wrap-byte cascade with the six range-correction constants — same six values in exact order
- Xref anchors: ~40 `Z_Construct_UPackage_*` trampolines call this or reach it through descriptor tables. Seven sampled during the walk (see the full agent output for the list).
- Notable constants (v818 → v908):
    | Field | v818 (CL-1341255) | v908 (CL-1372005) |
    |---|---|---|
    | kAdd  | `0xA7A3FF6B`      | `0x400062AA`      |
    | rot   | `0x13`            | `0x15`            |
    | key-mask | `0x1F`         | `0x1F`            |
    | wrap constants | `{-47, 47, 5, -13, 13, 209}` | same |

### Not present as standalone functions on v908
- `Theia_WrapByte_v908` — the wrap-byte cascade is fully inlined into `Theia_ConstructU_PRNG_v908`.
- `Theia_DecryptName_v908` — the 254-iteration decrypt loop is also inline in the same function.
- `Theia_Encrypt` — lives Python-side in `theia_static.h::SolveKeystream`, not in the binary.

### Recovery on next patch
1. Search `.text` for the six-move wrap-constant sequence — the pattern is distinctive enough to survive rekeying because the values are algorithmic, not cryptographic.
2. From any hit, walk backward to the enclosing function start — that's the ConstructU PRNG.
3. Read the `add r32, imm32` following the `imul r32,r32,0x1000193` inside the body: the imm32 is the new kAdd.
4. The `rol r32, imm8` immediately after gives the new rotate.
5. Everything else survives (key-mask 0x1F, wrap constants) unless Epic redesigns the alphabet — the alphabet is UE-source, not Theia, so it does not move on rekeys.


## Complete signature table for next-patch resolve

All entries verified with `mcp__ida-multi-mcp__generate_signature` against
IDA instance `pfoz` on 2026-09-12 — every signature marked `unique: true`
with exactly one hit inside the whole image at the recorded RVA.

Workflow on the next patch:

1. Open the new image in a fresh IDA instance.
2. For each function, sig-scan with the byte pattern in this table. If
   one hit — rename to the same v90N name (or v9NN for the new patch)
   and re-generate the signature to catch it up.
3. If no hit — the signature drifted. Read the "Xref fallback" column
   and follow it. Every entry has an xref anchor that survives because
   it either sits on a data reference (durable across recompiles) or on
   a durable UE-source string.
4. Once a function is re-located, its new address goes back into the
   dumper's compiled sheet (`arc_decrypt.h`) and its RVA into
   `arc_offsets.h` if any consumer reads it directly.

### FName pipeline

| Function | v908 RVA | Byte signature (IDA fmt) | Xref fallback |
|---|---|---|---|
| `FName_DecryptString_v908` | `0x2BF200` | `41 57 41 56 41 55 41 54 56 57 55 53 48 81 EC ? ? ? ? 48 89 D7 48 8B 05 ? ? ? ? 48 31 E0 48 89 84 24 ? ? ? ? 83 79 ? ? 74` | Xrefs to keystream RVA `0x1095926C`. Anchor on `and reg, 0x3F` + rip-lea into `.rdata` in the same body. |
| `FName_ResolverCore_v908` | `0x2DA260` | `41 56 56 57 53 48 83 EC ? 0F 29 74 24 ? 49 89 D6 41 0F B6 00` | `and r32, 0xFFFF00` (byte forms `25 00 FF FF 00`, `81 ?? 00 FF FF 00`, `41 81 ?? 00 FF FF 00`) — 4-6 hits total; the resolver family is where all of them cluster. |
| `FName_ResolverWrapper_v908` | `0x2DA4A0` | `41 56 41 55 56 57 53 48 81 EC ? ? ? ? 49 89 D6` | Called from `FName_ResolverCore_v908`; xref backwards. |

### UObject slot pipeline

| Function | v908 RVA | Byte signature | Xref fallback |
|---|---|---|---|
| `UObject_GetFName_v908` | `0x43AF90` | `41 56 56 57 53 48 81 EC ? ? ? ? 66 44 0F 7F 84 24 ? ? ? ? 66 0F 7F 7C 24 ? 0F 29 74 24 ? 44 89 CF` | Vtable slots at `.data` `0x14D4EC640` + `0x14D50D3B0`; slot-hash constant `0x993B3384` occurs 3× in the body. AngelScript binding string `"FName GetName() const"` in .rdata, 2 rip-refs. |

### FField / FProperty

| Function | v908 RVA | Byte signature | Xref fallback |
|---|---|---|---|
| `FField_GetFNameForScript_v908` | `0x387AB0` | `56 57 53 48 83 EC ? 4C 89 C3 48 89 D7 48 89 CE 48 8D 15` | Xrefs to `FField NamePrivate` key at RVA `0xD4DF960` (XOR const `0x0D58B9970DD2BBAF`); PSHUFB mask at `0xD4DF950`. |
| `FProperty_SetupOffset_v908` | `0x53E840` | (too long as full function — use encode idiom at `0x53ECC8` below) | The encode idiom is unique and 1-hit on every build tested. |
| SetupOffset encode idiom | `0x53ECC8` | `0F B7 47 ? 35 ? ? ? ? 0F C8` | Immediately after: `mov [reg+0xB0], eax`; imm32 is `0xC2CEEE92`. That triple is the 1-hit anchor. |

### GObjectArray / chunks_manager

| Function | v908 RVA | Byte signature | Xref fallback |
|---|---|---|---|
| `GObj_ProcessSubgraphRecursive_v908` | `0x37E850` | `41 57 41 56 41 55 41 54 56 57 55 53 48 83 EC ? 66 0F 7F 7C 24 ? 66 0F 7F 74 24 ? 48 89 D7 48 89 CE 48 8D 8A` | Xrefs to chunks_manager blob `0x10D853F0`. |
| `GObj_MarkObjectUnreachable_v908` | `0x3A57B7` | `48 83 EC ? 48 89 44 24 ? 56 57 48 83 EC ? 48 BF` | Same. |
| `GObj_IsMarkedUnreachable_v908` | `0x43D46A` | `48 8B CB 56 53 55 56` | Called by many GC sites; xref to the chunks_manager blob. |
| `GObj_ProcessGCPurgeList_v908` | `0x449130` | `41 57 41 56 41 55 41 54 56 57 53 48 81 EC ? ? ? ? 66 0F 7F B4 24 ? ? ? ? 41 89 C8` | Same. |
| `GObj_GC_GatherUnreachable_v908` | `0x44C7C0` | `41 57 41 56 56 57 53 48 81 EC ? ? ? ? 66 44 0F 7F 84 24 ? ? ? ? 66 0F 7F BC 24 ? ? ? ? 0F 29 B4 24 ? ? ? ? 89 CF` | Same. |

Additional anchor: chunk-decode SIMD fingerprint `66 0F 71 D1 03 66 0F 71 F0 0D` — a PSLLW+PSRLW pair that is the ROL16(13) step. Occurs at every chunks_manager access site.

### Theia static / ConstructU*

| Function | v908 RVA | Byte signature | Xref fallback |
|---|---|---|---|
| `Theia_ConstructU_PRNG_v908` | `0x61E1E0` | `41 57 41 56 41 55 41 54 56 57 55 53 48 81 EC ? ? ? ? 0F 29 BC 24 ? ? ? ? 66 0F 7F B4 24 ? ? ? ? 48 89 D6 48 89 CF` | Six-move wrap-constant prologue at RVA `0x61E328` (`mov edx,-47 ; mov r8d,47 ; mov r9d,5 ; mov r10d,-13 ; mov r11d,13 ; mov ebp,209`). ~40 `Z_Construct_UPackage_*` trampolines call this. |

### GWorld / world hashtable

| Function | v908 RVA | Byte signature | Xref fallback |
|---|---|---|---|
| `World_HashTableLookup_v908` | `0x3B62750` | `8B 05 ? ? ? ? 3B 05 ? ? ? ? 0F 84 ? ? ? ? 48 89 C8 48 C1 E8 ? 89 C2 C1 EA ? 31 C2 69 C2 ? ? ? ? 89 C2 C1 EA ? 31 C2 69 C2 ? ? ? ? 89 C2 C1 EA ? 31 C2 48 8B 05 ? ? ? ? 48 85 C0 4C 8D 05 ? ? ? ? 4C 0F 45 C0 8B 05 ? ? ? ? FF C8 21 D0 45 8B 04 80 41 83 F8 ? 74` | Xrefs to `g_WorldHT_Entries` RVA `0x10967B98`. |
| `World_WrapperCtor_v908` | `0x8C4E20` | `41 56 56 57 53 48 83 EC ? 0F 29 7C 24 ? 0F 29 74 24 ? 48 89 CE E8 ? ? ? ? 48 8D 05 ? ? ? ? 48 89 06 48 8D 05 ? ? ? ? 48 89 86 ? ? ? ? C6 86` | The only xref to wrapper vtable RVA `0xDD21510` is inside this ctor at `+0x1B`. |

### Global anchors (data references)

| Symbol | v908 RVA | What it is |
|---|---|---|
| `g_GNamePool` | `0x10AB5DC0` | FNamePool base |
| `g_Keystream` | `0x1095926C` | Keystream table start (decrypt window at `+0xF0` = u16 idx 120) |
| `g_ChunksManagerBlob` | `0x10D853F0` | Encrypted chunks_manager blob |
| `g_ChunksManagerKey_A` | `0xD4B22B0` | ROL16-XOR key |
| `g_ChunksManagerKey_B` | `0xD4BD610` | Auxiliary |
| `g_UWorldBase` | `0x10967B98` | World hashtable entries (UWORLD_BASE_RVA) |
| `g_WorldWrapperVtable` | `0xDD21510` | Intermediary wrapper vtable |
| FField NamePrivate XOR key | `0xD4DF960` | `0x0D58B9970DD2BBAF` |
| FField NamePrivate PSHUFB mask | `0xD4DF950` | `{5,6,1,4,3,7,2,0}` |


## Data-reference anchors (xrefs verified 2026-09-12)

Every named global that Dumper/ESP relies on, with a live count of its
xrefs and a note on how durable the anchor is. Use `mcp__ida-multi-mcp__
xrefs_to` on the RVA — walk any xref's function and you land inside the
family. The bigger the xref count, the more likely the anchor survives a
Theia rekey (each xref is a physical call site the compiler emitted).

| Global | RVA | Xrefs | Anchor durability |
|---|---|---|---|
| `g_ChunksManagerKey_A_v908` | `0xD4B22B0` | ~48+ | **STRONGEST** — the chunks_manager decrypt inlines everywhere, and the key ref is a durable rip-lea. All 5 GC accessors + ~40 other GObj sites touch it. |
| `g_FFieldNameKey_v908` | `0xD4DF960` | ~40+ | Very strong — every FField NamePrivate decode does a rip-relative PXOR against this. Fastest way to relocate the entire FField family. |
| `g_FFieldNamePshufb_v908` | `0xD4DF950` | ~40+ | Same as above; used together in the pshufb+pxor pair. |
| `g_WorldWrapperVtable_v908` | `0xDD21510` | **1** | Precise but fragile — the single xref (`World_WrapperCtor_v908`) is the wrapper install site. Perfect anchor while it exists; if Theia decides to isolate that ctor, we lose it. |
| `g_WorldHT_Entries_v908` | `0x10967B98` | ~7 | Strong — every world lookup rip-refs this. Also the hardcoded `UWORLD_BASE_RVA` in NewESP's `arc_offsets.h`. |
| `g_GNamePool_v908` | `0x10AB5DC0` | 0 (static) | Runtime-decrypted page — IDA cannot see xrefs to it. **Anchor via `and r32, 0xFFFF00`** in the FName resolver instead. |
| `g_Keystream_v908` | `0x1095926C` | 0 (static) | Same reason. Anchor via a rip-lea in `FName_DecryptString_v908` whose displacement points into `.rdata` here. |
| `g_ChunksManagerBlob_v908` | `0x10D853F0` | 0 (static) | Same. Anchor via the SIMD ROL16 fingerprint `66 0F 71 D1 03 66 0F 71 F0 0D` — every access site fingerprints it. |

The three zero-xref globals sit in `.data` pages that Theia decrypts at
load time. IDA's static analysis of the on-disk image cannot see the
runtime refs. That's the reason the doc leans on byte-signature scans
in those cases — no data-xref path exists to walk them.

## Immediate-value scans (durable — never rekeyed by Theia)

These constants are algorithmic requirements: an FNV32 needs its prime,
a slot hash needs its salt, an offset encode needs its XOR. Theia does
not rewrite them across patches — only Epic does, and only when the
underlying algorithm changes. So they are the last-resort anchor when
every string is gone and every rip-lea target has moved.

### Constants worth grepping on patch day

| Constant | Value (little-endian bytes) | Where it appears | Yield on v908 |
|---|---|---|---|
| FNV32 prime | `93 01 00 01` (imul imm32 form: `69 ?? 93 01 00 01`) | Every UObject slot hash, every shard hash | ~62k full-image hits; ~1500 accessor-shape functions after `and r32, 3` prefilter (see `auto_resolve908.h::FindGetFName908`) |
| FNV64 prime | `B3 01 00 00 00 01 00 00` (movabs form) | FNV64 fold inside FName resolver | ~2-4 hits per patch, all in the resolver family |
| Slot-hash ADD (v908) | `84 33 3B 99` (imm32 `0x993B3384`) | `UObject_GetFName_v908` body — 3 occurrences | 3 hits, all in one function. **Root-cause anchor for the v908 wide-string trap.** |
| Slot-idx ADD | `84 33 03 00` (imm32 `0x33384`) | Final `add r32, imm ; shr` fold in GetFName | 1 hit inside GetFName |
| Property offset XOR | `92 EE CE C2` (imm32 `0xC2CEEE92`) | `FProperty_SetupOffset_v908` encode idiom | 1 hit — the SetupOffset encode is 1-hit durable across all 13 tested builds |
| Chunks_mgr NumElements XOR | `A1 7A 49 BD` (imm32 `0xBD497AA1`) | Bswap+xor immediately after NumElements load | 1-2 hits, both in GObj family |
| FField NamePrivate XOR | `AF BB D2 0D 97 B9 58 0D` (imm64 `0x0D58B9970DD2BBAF`) | XOR key at RVA `0xD4DF960` — either as movabs load OR as rip-relative source | 0 movabs hits (it's a `.data` const), ~40+ rip-refs |
| Theia PRNG kAdd | `AA 62 00 40` (imm32 `0x400062AA`) | Inside `Theia_ConstructU_PRNG_v908`, part of `add r32, imm32 ; rol r32, 0x15` | 1 hit |
| Wrap constants (6-move prologue) | `mov edx,-47 ; mov r8d,47 ; mov r9d,5 ; mov r10d,-13 ; mov r11d,13 ; mov ebp,209` | Setup prologue in `Theia_ConstructU_PRNG_v908` | 1 hit (RVA `0x61E328`) |

### Practical procedure on patch day

1. Sig-scan for `93 01 00 01` (FNV32 prime). Take every hit; prefilter to
   functions carrying `and r32, 3` (`83 E0..E7 03`) within the next 256
   bytes. On v908 this reduces from ~62k raw hits to ~1500 candidates.
2. Within each candidate, look for a slot-hash `add r32, imm32` where
   `imm32` is the SUBTRACTIVE-form Theia constant — that's the new
   equivalent of `0x993B3384`. Read it off the disasm and update the
   compiled sheet.
3. Sig-scan for the SetupOffset idiom `0F B7 ? ? 35 ? ? ? ? 0F C8`. It
   is 1-hit durable; the imm32 after `35` is the new `FPROP_OFFSET_XOR`
   and the `mov [reg+disp32], r32` immediately after gives the new
   `FPROP_OFFSETINT_OFF`.
4. Sig-scan for the ROL16(13) fingerprint `66 0F 71 D1 03 66 0F 71 F0 0D`.
   Every hit is a chunks_manager decode site. Read the preceding
   `movdqa xmm, [rip+X]` — X is the new blob RVA. The following `pxor
   xmm, [rip+Y]` — Y is the new key RVA.
5. Sig-scan for the FField NamePrivate key's rip-relative use pattern
   `48 8D 05 ? ? ? ?` where the target sits in `.rdata` and gets XORed
   with an xmm value inside a function that also does `pshufb`. On
   v908, the target is `0xD4DF960`.
6. `Theia_ConstructU_PRNG_v908` is anchored by the wrap-constant
   prologue — search `.text` for the exact 24-byte sequence of six
   `mov reg, imm32` instructions.

Once all six anchors resolve, the compiled sheet in `arc_decrypt.h` +
`arc_offsets.h` (for NewESP) can be regenerated by hand from the
extracted values, and the sabotage-verify matrix from CLAUDE.md
proves the new sheet works before shipping.


## NewESP-side decrypt functions (game_utils)

Two runtime decrypt paths that NewESP relies on but the SDK dumper does
not touch. Documented here because the same signatures + xref pattern
help re-locate them on patch day.

### PlayerState_DecryptPlayerName_v908
- **RVA**: `0x44EBE60`  (VA `0x1444EBE60`)
- **What it does**: reads the FString at `APlayerState + 0x468` (u16
  buffer with a leading `count`), decodes each character through a
  Theia-style PRNG stream. This is `APlayerState::GetPlayerName` on the
  binary side.
- **PRNG shape** (matches NewESP's `arc_decrypt.h::DecryptPlayerName`):
  ```
  State = 16777619 * (State + ROL32(16777619 * State + 0x400062AA, 21))
  ```
  Constant `0x400062AA` is the **same** value as Theia's `ConstructU`
  PRNG kAdd on v908 — Epic recycled the additive constant, not the
  rotate (ConstructU rotates by 0x15, PlayerName rotates by 21 = 0x15
  also). The two use different mixing shapes though.
- **Constant drift v818 → v908**:
    | Patch | Additive | Rotate |
    |---|---|---|
    | v818 (CL-1341255) | `0xD351FEEC` | 28 |
    | v908 (CL-1372005) | `0x400062AA` | 21 |
- **Byte signature (IDA `generate_signature`, unique)**:
  ```
  41 57 41 56 41 54 56 57 55 53 48 83 EC ? 48 89 D6 80 B9
  ```
  Length 19, occurrences=1.
- **Xref fallback**: the additive constant `0x400062AA` byte-form
  `AA 62 00 40` appears in *both* this function and
  `Theia_ConstructU_PRNG_v908`. Filter by "which one reads from PlayerState
  offset `+0x468`" — the `80 B9` opcode prefix (cmp byte [rcx+disp32])
  seven bytes into the prologue is the distinguishing tail. Reads
  FString count at `+0x468`.
- **NewESP hardcoded RVA constant** to update: `arc_decrypt.h` line 268
  and 301 both carry the RVA `0x44EBE60` in comments. Bump those on
  every patch.

### BoneArray decrypt (inlined, no standalone function)
- **Status**: not renamed — the SIMD decode shape (`pxor xmm, key` →
  `ROL16(13)` → `pshuflw imm 0x1B` → `movq rax, xmm0`) is identical to
  the chunks_manager decode fingerprint. Every mesh's bone array uses
  the same primitive; Theia inlines it at each call site.
- **Constants** (from NewESP `arc_offsets.h::BoneArrayDecrypt`):
    | Field | v908 value | v818 value |
    |---|---|---|
    | Seed offset in mesh | `0x800` | `0x7B0` |
    | Selector offset | `0x854` | `0x7F8` (LOD_OFFSET) |
    | Selector mask | `0x1` | `SHR27 & 0xFFFFFFF0` |
    | Descriptor base | `0xA8` | `0x48` |
    | Descriptor stride | `0x10` | `0x10` |
    | XOR key lo64 | `0xD4A8B60E86179E4E` | `0xD4A8B60E86179E4E` (unchanged) |
    | ROL16 amount | `13` | `13` |
    | PSHUFLW imm | `0x1B` | `0x1B` |

  The XOR key `0xD4A8B60E86179E4E` is the **same** value stored at RVA
  `0xD4B22B0` (`g_ChunksManagerKey_A_v908`), and it also happens to be
  the same value at the bone-array key RVA. So the bone decrypt reuses
  the chunks_manager key. That means: **every xref to
  `g_ChunksManagerKey_A_v908` is potentially a bone-array decode site
  as well** — the two decode primitives are indistinguishable at the
  byte level, and the only way to tell them apart is by looking at the
  *source* the movdqa loads from (chunks_manager blob vs a mesh
  instance's `+0x800`).
- **Anchor for the bone-decrypt call site on patch day**:
    1. Xrefs to `g_ChunksManagerKey_A_v908` (RVA `0xD4B22B0`) — ~48+ hits.
    2. Filter for a function that reads `movdqa xmm, [reg + 0x800]` or
       `movdqa xmm, [reg + 0x7B0]` right before the decode chain.
       The mesh SEED_OFFSET is the distinguishing marker — GObjectArray
       accessors read the chunks_manager blob at a fixed rip-relative
       address, not a `[reg + disp32]` form.
    3. Also look for `[reg + 0x854]` (SELECTOR_OFFSET) load two
       instructions past the decode's `movq rax, xmm0` — that reads
       the selector dword that picks which of N descriptors gets used.
- **NewESP RVA to update**: none is currently hardcoded — the decode is
  fully inline in NewESP's `DecryptBoneArrayPointer` helper. On a patch,
  only the offsets change (SEED_OFFSET / SELECTOR_OFFSET / DESCRIPTOR_BASE),
  and those are marked with `// was 0xXXX` comments in `arc_offsets.h`
  for drift tracking.

### TEB_Decrypt_v908 (unified pointer decrypt)
- **Status**: not renamed — the RVA `0x322A820` recorded in NewESP's
  `arc_decrypt.h` comment is under a runtime-decrypted page and IDA
  does not disassemble it statically. Cannot rename or sig-scan without
  a live memory dump of that page.
- **Recovery**: dump the runtime page (via `/dev/memreader` or a memory
  snapshot of the game process) at RVA `0x322A820` for at least 0x200
  bytes, then re-import that region into IDA. Once the page is
  populated, sig-scan on the decode shape:
    1. `xor xmm, [rax + 0x1F8]` (TEB per-thread key, TEB offset `0x1F8`)
    2. `psrlw xmm, 1 ; psllw xmm, 15 ; por` (ROR16 by 1 per word)
    3. `pshufb xmm, [rip + mask]` with mask `{6,3,1,7,0,2,4,5}`
    4. Final `ror r64, 3`
    That's a very distinctive 4-stage chain — sig-scan it and rename.
