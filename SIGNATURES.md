# ARC Raiders – Signatures & Decrypt Reference (March 2026 Patch)

Module Base: `0x140000000`

---

## 1. Global Addresses (RVAs)

### GWorld
| RVA | Description |
|---|---|
| `0xDCB9AB8` | GWorld pointer |
| `0xDCB9AC0` | GWorld hash count |
| `0xDCB9AEC` | GWorld hash capacity |
| `0xDCB9AF8` | GWorld alt bucket |
| `0xDCB9B00` | GWorld bucket mask |

### GObjects (FChunkedFixedUObjectArray)
| RVA | Description |
|---|---|
| `0xDB4DD20` | GObjectArray encrypted data |
| `0xDB4DD24` | GObjectArray MaxChunks |
| XOR constant | `0xAB8F9C79978619C2` |

### FNamePool
| RVA | Description |
|---|---|
| `0xD8FD870` | GNames base (old, used in arc_decrypt.h) |
| `0xD892880` | GNames base (actual, used in fname_decrypt.h) |
| `0xD841864` | FName key table (old) |
| `0xD7D6804` | FName key table (actual) |

### SIMD Runtime Tables
| RVA | Description |
|---|---|
| `0xAAF4770` | UObject name/class shuffle_epi8 mask |
| `0xAAF74B0` | FField name shuffle_epi8 mask |
| `0xAAF4740` | NumElements andnot mask |
| `0xAAF4750` | NumElements and mask |
| `0xAAF4760` | NumElements shuffle_epi8 mask |
| `0xAAA18A0` | ObjectArray XOR key |
| `0xAAA18B0` | ObjectArray shuffle_epi8 mask |
| `0xAAF47C0` | GetClassSlot XOR mask |
| `0xAB2DE50` | ChunkPtr pxor key1 |
| `0xAB2DE60` | ChunkPtr pxor key2 |

---

## 2. Structure Offsets

### UObject (0xA0 total, 4 encrypted slots)
| Offset | Field | Notes |
|---|---|---|
| `+0x00` | VTable | |
| `+0x08` | InternalIndex | |
| `+0x20` | FieldsSlots[0..3] | 4 slots × 0x20 bytes (0x20–0x9F) |

Slot selection: FNV hash of (obj_base + 0x10), constants:
- HASH_PRIME = `16777619` (0x01000193)
- HASH_ADD = `1668103848` (0x636F6E28)
- SLOT_XOR = `0x2C158`
- Name slot: `(hash & 3) ^ 2`
- Class slot: `(hash & 3)` (no XOR)
- Outer slot: `(name_slot + 3) & 3`

### FField
| Offset | Field |
|---|---|
| `+0x00` | VTable |
| `+0x90` | Next (FField*) |
| `+0xB0` | NamePrivate (encrypted, 16 bytes) |
| `+0x130` | ClassPrivate (FFieldClass*) |

### FFieldClass
| Offset | Field |
|---|---|
| `+0x50` | NamePrivate |

### FProperty
| Offset | Field | Notes |
|---|---|---|
| `+0xC4` | Offset_Internal | Encrypted: `bswap32(raw ^ 0x46F1DEE5)` |
| `+0xC8` | ElementSize | |
| `+0xCC` | ArrayDim | |

### FBoolProperty (extends FProperty)
| Offset | Field | Notes |
|---|---|---|
| `+0x130` | FieldSize (u8) | 1=bitfield, 4=native bool |
| `+0x131` | ByteOffset (u8) | Offset within property byte |
| `+0x132` | ByteMask (u8) | Bitmask 0x01..0x80 |
| `+0x133` | FieldMask (u8) | = ByteMask for bitfields |

### FProperty Sub-Types (all shifted from old +0xD8 to +0x130/+0x138)
| Type | Offset | Field | Verified With |
|---|---|---|---|
| FStructProperty | `+0x130` | Struct (UScriptStruct*) | PrimaryActorTick→ActorTickFunction |
| FObjectProperty | `+0x130` | PropertyClass (UClass*) | Owner→Actor, Mesh→SkeletalMeshComponent |
| FEnumProperty | `+0x130` | Enum (UEnum*) | AutoPossessPlayer→EAutoReceiveInput |
| FArrayProperty | `+0x138` | Inner (FProperty*) | Children→ObjectProperty, Tags→NameProperty |
| FSetProperty | `+0x130` | ElementProp (FProperty*) | OnStateLeaveGameplayEffects |
| FSoftObjectProperty | `+0x130` | PropertyClass (UClass*) | |
| FMapProperty | `+0x130` | KeyProp (FProperty*) | Annotations TMap |
| FMapProperty | `+0x138` | ValueProp (FProperty*) | Labels TMap |
| FClassProperty | `+0x130` | PropertyClass + `+0x138` MetaClass | AIControllerClass→TSubclassOf |
| FInterfaceProperty | `+0x130` | InterfaceClass (UClass*) | |

### UStruct
| Offset | Field | Verified |
|---|---|---|
| `+0x0B0` | SuperStruct | |
| `+0x0C0` | MinAlignment | |
| `+0x0D0` | Children (UField* linked list) | |
| `+0x0D8` | ChildProperties (FField* chain) | |
| `+0x0E8` | PropertiesSize | Actor=0x3B0, ActorComponent=0x190 |

### UEnum
| Offset | Field |
|---|---|
| `+0xB0` | Names (TArray<TPair<FName,int64>>) |
| `+0xB8` | Names.Num (count) |

### UFunction
| Offset | Field |
|---|---|
| `+0x000` | VTable |
| `+0x098` | UField::Next |
| `+0x128` | FunctionFlags (TODO: verify) |
| `+0x1C8` | NativeFunc (TODO: verify) |

---

## 3. Decrypt Pipelines

### 3.1 UObject Slot Hash → Slot Index
```
addr = obj_base + 0x10
lo = (uint32_t)addr, hi = (uint32_t)(addr >> 32)
s0 = HASH_PRIME * ROL32(lo, 26) - HASH_ADD
s1 = ROL32(s0, 19)
s2 = hi + HASH_PRIME * s1 - HASH_ADD
s3 = ROL32(s2, 26)
s4 = HASH_PRIME * s3 - HASH_ADD
v  = HASH_PRIME * (s4 >> 13)
name_slot  = ((v & 0xFF) ^ ((SLOT_XOR + v) >> 16) & 0xFF) & 3) ^ 2
class_slot = ((v & 0xFF) ^ ((SLOT_XOR + v) >> 16) & 0xFF) & 3)
outer_slot = (name_slot + 3) & 3
```

### 3.2 UObject Name/Class Slot Decrypt → value
```
data = Read128(obj_base + 0x20 + slot * 0x20)
step1 = shufflelo_epi16(data, 27)        // pshuflw imm=0x1B
step2 = ROL16(step1, 13)                 // slli16(13) | srli16(3)
step3 = shuffle_epi8(step2, RUNTIME_ACTOR_SHUF_TABLE)
// For FName: ROL64(result, 32) → lo32 = comp_index
// For ClassPrivate: lo64 = UClass pointer
```

### 3.3 FField::NamePrivate Decrypt → comp_index
```
data = Read128(ff_addr + 0xB0)
step1 = shuffle_epi8(data, RUNTIME_FFIELD_SHUF_TABLE)
step2 = ROL64(step1, 15)                 // slli64(15) | srli64(49)
step3 = shufflelo_epi16(step2, 30)       // pshuflw imm=0x1E
result = ROL64(lo64(step3), 32) → lo32 = comp_index
```

### 3.4 FProperty Offset Decrypt
```
decrypted = bswap32(raw_u32 ^ 0x46F1DEE5)
```

### 3.5 GObjectArray Decrypt
```
data = Read128(MODULE_BASE + 0xDB4DD20 + 32)
step1 = XOR(data, SIMD_TABLE_0xAAA18A0)
step2 = ROL64(step1, 34)                 // per qword
step3 = shuffle_epi8(step2, SIMD_TABLE_0xAAA18B0)
result = lo64(step3) ^ 0xAB8F9C79978619C2
```

### 3.6 GObjectArray NumElements Decrypt
```
data = Read128(array_base + 9*16)        // offset 0x90
blended = (data & MASK1) | (~data & MASK2)  // SIMD and/andnot
shuffled = shuffle_epi8(blended, NUM_SHUF_MASK)
result = lo32(srli_epi64(shuffled, 5))
```

### 3.7 GObjectArray ChunkPtr Decrypt
```
data = Read64(array_base + 0x70)
step1 = XOR(data, KEY1_0xAB2DE50)
step2 = ROL64(step1, 43)
step3 = pshuflw(step2, 0x72)
step4 = XOR(step3, KEY2_0xAB2DE60)
step5 = XOR(step4, broadcast(PEB_ADDR + 0x72AC9D29))
// PEB: Wine PEB with ImageBaseAddress at +0x10 = 0x140000000
```

### 3.8 FNamePool → Name String

#### 3.8.1 comp_index → GNames Location (3-stage SIMD)
```
// Stage 1: shuffle_epi8(cvtsi32(ci), GIDX_SHUF1) → XOR(GIDX_XOR1) → ROL32(11)
// Stage 2: ROL32(21) → shuffle_epi32(0x44) → ROL32(11)
// Stage 3: ROL32(21) → shuffle_epi8(GIDX_EXTRACT_SHUF) → XOR(0x4689054B)
v5 = result
name_offset = 2 * (uint16_t)v5
chunk_off   = (v5 >> 8) & 0xFFFF00
```

SIMD constants:
```
GIDX_SHUF1 = 02 00 00 00 00 00 01 03 02 00 00 00 00 00 01 03
GIDX_XOR1  = 89 00 00 00 4B 00 05 46 89 00 00 00 4B 00 05 46
GIDX_EXTRACT_SHUF = 04 06 00 07 00 00 00 00 00 00 00 00 00 00 00 00
GIDX_EXTRACT_XOR  = 0x4689054B
```

#### 3.8.2 Block Index (FNV hash of chunk address)
```
seed = chunk_addr + 9472
lo = (uint32_t)seed, hi = (uint32_t)(seed >> 32)
h = lo >> 4
h = HASH_PRIME * h + 1133438190 (0x438FB4EE)
h = ROL32(h, 16)
h = HASH_PRIME * h + hi + 1133438190
h = ROL32(h, 28)
h = HASH_PRIME * h + 1133438190
v8 = ROL32(h, 16)
block_idx = (uint8_t)(-109 * v8 - 18) ^ (uint8_t)((HASH_PRIME * v8 + 1133438190) >> 16)
```

#### 3.8.3 Block Decrypt (per 128-bit block)
```
step1 = shufflelo_epi16(data, 57)        // pshuflw imm=0x39
step2 = ROL64(step1, 51)
step3 = shuffle_epi8(step2, BLOCK_SHUF)
step4 = XOR(step3, BLOCK_XOR_KEY)
result = lo64(step4)
```

Constants:
```
BLOCK_SHUF   = 01 04 06 07 05 02 03 00 (+ 8 zero bytes)
BLOCK_XOR    = A4 5B A9 EB 21 AE 9A 4F (+ 8 zero bytes)
```

#### 3.8.4 FNV Fold + Pointer Fixup
```
fnv = FNV_PRIME * ROL64(block1_dec, 38) + 0x5BD41B159509682E
fnv = FNV_PRIME * ROL64(fnv, 31) + 0x5BD41B159509682E
R = block1_dec + (block2_dec ^ fnv) + name_offset

// Pointer fixup:
a = bswap64(R ^ 0x9B7E4246)
b = a ^ 0x5C76BDF000000000
name_ptr = bswap64(b ^ 0x1A34C36B00000000)
```

FNV_PRIME = `0x100000001B3`

#### 3.8.5 Name String Decrypt
```
header = Read16(name_ptr)
isWide = header & 1
length = (header >> 1) & 0x3FF
buf = Read(name_ptr + 2, length)

key = length - 81
for i in 0..length step 2:
    if narrow: buf[i] ^= key_table[key & 0x3F] >> 3
               buf[i+1] ^= key_table[(81*key + 124) & 0x3F] >> 3
    if wide:   buf[i] ^= key_table[key & 0x3F]
               buf[i+1] ^= key_table[(81*key + 124) & 0x3F]
    key = -95 * key - 72
```

Key table: 64 × uint16_t at RVA `0xD7D6804`

---

## 4. FUObjectItem Layout
```
+0x00 [8]  Object (UObject*)     — NOT encrypted
+0x08 [4]  Flags
+0x0C [4]  ClusterRootIndex
+0x10 [4]  SerialNumber
Total: 20 bytes per item, 65536 items per chunk
chunk_index = index >> 16
item_index  = index & 0xFFFF
```

---

## 5. VTable RVAs (Runtime, March 2026)

Known FProperty sub-type vtable RVAs:
| RVA | Type |
|---|---|
| `0x0AB25100` | FUInt32Property |
| `0x0AB36150` | FObjectProperty |
| `0x0AB1F030` | FMapProperty |
| `0x0AB27290` | FSetProperty |
| `0x0AB24CA0` | FStrProperty |
| `0x0AB25330` | FDoubleProperty |
| `0x0AB37270` | FInt64Property |
| `0x0AB25A20` | FMulticastInlineDelegateProperty |
| `0x0AB35060` | FEnumProperty |

Note: These are **runtime** vtable addresses (VMProtect decrypted). They will NOT appear in static IDA analysis.

---

## 6. Key Functions (IDA RVAs)

| RVA | Function |
|---|---|
| `0x2C9515` | UObject::GetNamePrivate (SIMD) |
| `0x343D00` | UObject::GetClassAndName |
| `0x33B310` | FProperty::ExportTextItem |
| `0x33FC6B` | FField::GetNamePrivate |
| `0x367C40` | UStruct::FindPropertyByFName |
| `0x3595A0` | UStruct::CompareScriptStruct |
| `0x35CF10` | UStruct::Link |
| `0x3652C0` | FUObjectArray::CreateObjectIterator |
| `0x4B5640` | FUObjectArray::FreeObjectAtIndex |
| `0x229680` | FName::ToString |
| `0x4B93F0` | FName::AppendString |
| `0x374B10` | FField_or_UObject::GetName |
| `0x37C7C0` | FField_or_UObject::GetFName |
| `0x3F12C9` | UObject::ConditionalBeginDestroy |
| `0x4CC6F0` | UObject::Destructor |
| `0x2E65AC5` | UWorld::FindActorByHash |
| `0x2E71FC9` | GWorld::ResetHashTable |
| `0x2E883D0` | GWorld::LookupByAddress |
