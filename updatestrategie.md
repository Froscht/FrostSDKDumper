# Patch-Update-Strategie für FrostSDKDumper

Basiert auf Erfahrungen aus 6 Patches (CL-1177146 → CL-1315578) und der vollständigen Offset-Drift-Historie.

---

## 1. Was sich bei jedem Patch ändert

### Immer (100% Wahrscheinlichkeit)
- **FField/FProperty Struct-Offsets** — Theia randomisiert die Layouts per Build (nicht per Session!)
  - NamePrivate, Next, Owner, ClassPrivate, ChildProperties
  - Offset_Internal, ElementSize, ArrayDim
  - SubPointer (FStructProperty::Struct, FObjectProperty::PropertyClass, etc.)
  - SuperStruct, PropertiesSize
- **PropertyOffsetXor** — XOR-Key für `bswap(offset ^ key)` ändert sich
- **FField NamePrivate Decrypt-Konstanten** — PSHUFB mask, XOR key, ROL-Amounts
- **UObject Slot Decrypt** — PSHUFLW/ROL32/ROL64/HashADD Konstanten
- **FName Pipeline-Konstanten** — ShardHashAdd, FnvAdd, FnvXor, Keytable-RVA
- **GUObjectArray SIMD-Tabellen** — per-Session randomisiert (RVAs UND Inhalte)

### Meistens (>80%)
- **FFieldClass Name-Decrypt** — xor_lo64, pshuflw, rol32 ändern sich
- **FName String-Decrypt Header-Bitmasks** — length/wide Bit-Positionen im Header
- **Engine-Vtable RVAs** — UClass, UScriptStruct, UFunction, UEnum verschieben sich
- **AS-Type Vtable RVAs** — ASClass, ASStruct sind per-Session randomisiert

### Selten (<20%)
- **FName Pipeline-Architektur** — neuer Decode-Pfad (passierte v20260519 → v20260709)
- **GUObjectArray Chunk-Layout** — stride, NumElements-Offset
- **Komplett neue Theia-Obfuskierungen** — z.B. ROL32 statt PSHUFB (CL-1299607)

---

## 2. Was automatisch überlebt (Zero-Touch)

| Komponente | Auto-Discovery Phase | Vertrauenslevel |
|------------|---------------------|-----------------|
| PE Module Bounds | Phase 0 (PE Header) | ★★★★★ |
| FField Layout (NamePrivate/Next/ChildProperties) | Phase 2c (Binary Code Extraction) | ★★★★★ |
| FProperty Layout (Offset_Internal/ElementSize/ArrayDim) | Phase 2d (Binary Code Extraction) | ★★★★★ |
| PropertyOffsetXor | Phase 2d + Phase 3 (sig `35 ?? ?? ?? ?? 0F C8`) | ★★★★★ |
| FField NamePrivate Decrypt (XOR/PSHUFB/ROL) | Phase 2c (MOVDQA/MOVQ extraction) | ★★★★☆ |
| FProperty SubPointer Offset | Phase 2c.6 (Live Probe) | ★★★★☆ |
| SuperStruct/PropertiesSize/Owner/ClassPrivate | Live Structure Probe (auto_offsets.h) | ★★★★☆ |
| Engine Vtable RVAs | Phase 1 + Config-Merge | ★★★☆☆ |
| FName Decrypt Entry Function | Phase 5 (Caller-Frame Anchor) | ★★★☆☆ |
| GNamePool Base | Phase 6 (Call-Chain LEA Walk) | ★★★☆☆ |
| FFieldClass Globals | Phase 8 (5-arg Constructor Pattern) | ★★☆☆☆ |
| GUObjectArray Chunks | Heap-Scan Fallback | ★★☆☆☆ |

---

## 3. Patch-Day Checkliste

### Schritt 1: Spiel starten, PID ermitteln
```bash
steam steam://rungameid/1808500
# Warten bis RSS > 4GB
pgrep -af "PioneerGame"
```

### Schritt 2: Dump starten, Log prüfen
```bash
sudo ./FrostDumper <PID> 2>&1 | tee /tmp/dump_new_patch.log
```

### Schritt 3: Log-Analyse — Was ist kaputt?

| Symptom | Ursache | Fix |
|---------|---------|-----|
| "PSHUFB mask invalid" | UObject Slot Decrypt geändert | Phase 4 Auto-Discovery prüfen, V7xx Konstanten in arc_decrypt.h updaten |
| "GObjectArray direct init failed" | Chunk-Layout geändert | Heap-Scan Fallback sollte greifen; sonst NumElements-Offset proben |
| 0 FName resolutions | FName Pipeline-Architektur geändert | Keytable-RVA prüfen, `fname_decrypt.h` Pipeline-Selektion anpassen |
| Alle Properties "FProperty_Unknown" | FFieldClass-Map leer oder falsch | Phase 8 FFieldClass Globals + Live-FClass-Map prüfen |
| Structs/Enums = 0 | Engine Vtables falsch | decrypt_export.json vtables aktualisieren |
| "ChildProperties sig not found" | Phase 2c AOB-Pattern veraltet | Neue Sig in IDA generieren (siehe Abschnitt 5) |
| Naming rate < 90% | FField NamePrivate Decode-Konstanten falsch | Phase 2c Binary-Extraction prüfen |
| Properties mit Garbage-Namen | SubPointer Offset falsch | Phase 2c.6 Probe-Ergebnisse prüfen |

### Schritt 4: Config aktualisieren
Wenn der Dump funktioniert, schreibt `auto_export.h` automatisch `decrypt_export.json`.
Bei Vtable-Änderungen manuell die `autodiscovery.vtables` Sektion anpassen:
```json
{
  "autodiscovery": {
    "vtables": {
      "script_struct_rva": "0x...",
      "class_native_rva": "0x...",
      "function_rva": "0x...",
      "enum_rva": "0x...",
      "package_rva": "0x...",
      "bpgc_rva": "0x..."
    }
  }
}
```

### Schritt 5: Targets verifizieren

| Metrik | Minimum-Target |
|--------|---------------|
| Classes | ≥ 14969 |
| Structs | ≥ 47135 |
| Enums | ≥ 2938 |
| Functions | ≥ 36939 |
| Properties | ≥ 164035 |
| FProperty_Unknown | 0% |
| Naming Rate | ≥ 99% |

---

## 4. Offset-Drift-Historie (Referenz)

| Field | CL-1177146 | CL-1177678 | CL-1201801 | CL-1233465 | CL-1299607 | CL-1315578 |
|-------|-----------|-----------|-----------|-----------|-----------|-----------|
| FField::NamePrivate | +0x70 | +0x30 | +0x40 | +0x90 | +0x40 | +0xA0 |
| FField::Next | +0x80 | +0x48 | +0x50 | +0xB0 | +0x60 | +0x78 |
| FField::Owner | +0x10 | +0x10 | +0x70 | +0xA8 | +0x58 | +0x80 |
| FField::ClassPrivate | +0x90 | +0x50 | +0x60 | +0xC0 | +0x70 | +0xB8 |
| UStruct::ChildProperties | +0x168 | +0xB0 | +0x108 | +0x118 | +0xC8 | +0xF0 |
| UStruct::SuperStruct | — | — | +0x60 | — | +0x60 | +0xB0 |
| UStruct::PropertiesSize | — | — | +0x110 | +0xE0 | +0x90 | +0xD0 |
| FProperty::Offset_Internal | +0xC4 | +0x88 | +0x94 | +0xE4 | +0x94 | +0xE4 |
| FProperty::ElementSize | — | — | +0xC8 | +0x118 | +0x7C | +0xD0 |
| FProperty::ArrayDim | — | — | +0xC0 | +0x110 | +0xC0 | +0x110 |
| SubPointer (Struct/Obj/etc.) | +0x108 | +0xC8 | +0xE8 | +0x130 | +0xE8 | +0x138 |
| FBoolProperty::FieldSize | — | — | +0xF0 | +0x138 | +0xE8 | +0x138 |
| PropertyOffsetXor | — | — | 0xBAB939DB | 0xEAABEC11 | 0x057F15E5 | 0xA271DBC5 |

**Beobachtung:** Offsets springen ±0x10..±0x60 pro Patch, ohne erkennbares Muster. Auto-Discovery aus dem Binary ist die einzig zuverlässige Methode.

---

## 5. IDA Pro Signaturen (CL-1315578, generiert mit ida-multi-mcp)

Alle Signaturen mit `wildcard_operands=true` generiert — operand-Bytes sind wildcarded für Cross-Patch-Stabilität.

### 5.1 FNamePool::FindOrStore (sub_23F285)
Entry-Point für FName-Auflösung. Enthält SHARD_HASH_ADD, Keytable-Zugriffe.
```
RVA: 0x23F285 (CL-1315578)
Vorherige RVAs: 0x231FA0 (CL-1201801)
Größe: 0xAE

Prologue-Sig (unique):
48 8B 44 24 ? 48 8B 4C 24 ? 56 41 54

Inner-Sig (unique, ab +0xB offset):
41 54 56 57 53 48 83 EC ? 48 89 D6 48 8B 05 ? ? ? ? 48 31 E0 48 89 44 24 ? 66 0F 6E 01 66 0F 6F C8 66 0F 73 F1 ? 66 0F 73 F0 ? 66 0F 73 D1 ? 66 0F EB C8 F2 0F 70 C1 ? 66 0F 7F 44 24 ? 48 8D 44 24 ? 48 89 44 24 ? 48 8D 4C 24 ? 48 8D 54 24 ? 4C 8D 44 24 ? E8 ? ? ? ? 48 BF ? ? ? ? ? ? ? ? 48 33 7C 24 ? 48 0F CF 48 89 F9
```

### 5.2 FField NamePrivate Decode (sub_3B05A0)
Dekodiert FField::NamePrivate zu CompIndex. Enthält PSHUFB-Mask, XOR-Key, ROL-Amounts.
```
RVA: 0x3B05A0 (CL-1315578)
Vorherige RVAs: 0x3B8A70 (CL-1201801)
Größe: 0x27A

Sig (unique):
41 57 41 56 41 54 56 57 53 48 81 EC ? ? ? ? 66 44 0F 7F 84 24 ? ? ? ? 66 0F 7F BC 24 ? ? ? ? 66 0F 7F B4 24 ? ? ? ? 4C 89 C6
```
**Hinweis:** Diese Sig hat 6 Matches auf CL-1315578. Disambiguierung über den letzten Opcode `4C 89 C6` (MOV RSI, R8).

### 5.3 ChildProperties / FField Layout Accessor (@ 0x3868BE)
Enthält ChildProperties-Offset, NamePrivate-Offset, SIMD-Konstanten-RVAs. Phase 2c nutzt diese Funktion.
```
RVA: 0x3868BE (CL-1315578)
Kein Vorgänger — neues Discovery-Target

Sig (unique):
48 89 44 24 ? 48 8B 80 ? ? ? ? 48 89 44 24 ? C7 44 24 ? ? ? ? ? 66 C7 44 24 ? ? ? C6 44 24 ? ? 48 8D 4C 24 ? E8 ? ? ? ? 48 8B 44 24 ? 48 85 C0 74 ? F3 0F 7E 35 ? ? ? ? F3 0F 7E 3D ? ? ? ? 48 8D 7C 24 ? 0F 1F 40

AOB in auto_discovery.h (Phase 2c):
- ChildProperties = MOV-Offset aus `48 8B 80 [offset]` (4 Bytes)
- NamePrivate = MOVDQA-Offset bei sig+0x52
- XOR Key = MOVQ #1 bei sig+0x39 (→ .rdata Adresse)
- PSHUFB Mask = MOVQ #2 bei sig+0x41 (→ .rdata Adresse)
- ROL-Amount = PSRLW bei sig+0x62
- Next = MOV-Offset bei sig+0x83
```

### 5.4 FProperty Offset Encode (@ 0x42D13B)
Das `xor eax, imm32; bswap eax`-Pattern. Enthält PropertyOffsetXor.
```
RVA: 0x42D13B (CL-1315578)
Vorherige RVAs: Variiert stark

Sig (unique):
35 ? ? ? ? 0F C8 89 83 ? ? ? ? 35 ? ? ? ? 0F C8 8B 8B ? ? ? ? 0F AF 8B ? ? ? ? 01 C1 81 F9 ? ? ? ? 0F 83 ? ? ? ? 48 8B 9E

Pattern für alle Instanzen (15 Treffer auf CL-1315578):
35 ? ? ? ? 0F C8
```

### 5.5 FProperty Base Constructor (sub_438E50)
Initialisiert alle FProperty-Felder. Enthält Offset_Internal XOR-Key, ArrayDim/ElementSize Init-Offsets.
```
RVA: 0x438E50 (CL-1315578)
Vorherige RVAs: 0x433460 (CL-1201801)
Größe: 0x444

Sig (unique):
41 57 41 56 41 55 41 54 56 57 55 53 48 81 EC ? ? ? ? 4C 89 CB 4C 89 C7 49 89 D6 48 89 CE 48 8B 05 ? ? ? ? 48 31 E0 48 89 84 24 ? ? ? ? 83 BC 24
```

### 5.6 FProperty Offset Fixup (sub_42DF20)
Setzt Offset_Internal nach Reclassification. Enthält ebenfalls XOR+bswap.
```
RVA: 0x42DF20 (CL-1315578)
Größe: 0x149

Sig (unique):
56 57 48 83 EC ? 48 89 CE 48 8D B9 ? ? ? ? E8 ? ? ? ? 48 89 F9 48 89 C2 E8 ? ? ? ? 48 8B 8E
```

### 5.7 GNamePool Shard-Lookup (sub_2344C9)
Enthält LEA zum GNamePool-Base (0xE4F2A00). Für Phase 6 Discovery.
```
RVA: 0x2344C9 (CL-1315578)
Größe: 0x12F

Sig (unique):
48 83 EC ? 48 89 01 56 57 55 53 48 83 EC ? 48 8B 05
```

### 5.8 Generische AOB-Patterns (Cross-Patch stabil)

| Pattern | Zweck | Extrahierte Werte |
|---------|-------|-------------------|
| `35 ?? ?? ?? ?? 0F C8` | FProperty Offset XOR+bswap | imm32 = PropertyOffsetXor |
| `F2 0F 70 C8 ?? 66 0F 38 00` | UObject Slot PSHUFLW+PSHUFB | imm8 = PSHUFLW shuffle |
| `48 8D 1D ?? ?? ?? ?? 48 8D 3C 1E 48 81 C7 C0 00 00 00` | Legacy FFieldClass Anchor | LEA target = FFieldClass array |
| `66 0F 7E 35 ?? ?? ?? ?? 66 0F 7E 3D` | FField NamePrivate SIMD loads | RIP-rel targets = XOR key + PSHUFB mask |

---

## 6. Reihenfolge bei manuellem Update

Wenn die Auto-Discovery fehlschlägt und manuelles IDA-Reverse-Engineering nötig ist:

1. **FName Pipeline** (höchste Priorität)
   - Keytable-RVA finden (Sig 5.1 → callees durchgehen)
   - ShardHashAdd/FnvAdd/FnvXor aus dem Shard-Hash-Code extrahieren
   - Header-Bitmasks (length/wide) aus String-Decrypt-Funktion lesen
   - **Ohne funktionierende FNames ist der Rest unmöglich**

2. **FField Layout** (zweithöchste Priorität)
   - Sig 5.3 finden → ChildProperties/NamePrivate/Next/XOR/PSHUFB/ROL extrahieren
   - Oder: FProperty Ctor (Sig 5.5) decompilen → Offsets aus Feldzuweisungen ablesen

3. **FProperty Offsets**
   - Sig 5.4 (`35 ?? ?? ?? ?? 0F C8`) → PropertyOffsetXor
   - FProperty Ctor (Sig 5.5) → ElementSize, ArrayDim, Offset_Internal Positionen

4. **Engine Vtables**
   - GUObjectArray walker starten → Top-20 Vtables nach Häufigkeit
   - Bekannte Cluster-Sizes nutzen (Package ~36K, Function ~20K, ScriptStruct ~6K, Class ~6K)
   - In decrypt_export.json eintragen

5. **GUObjectArray**
   - Heap-Scan Fallback greift meistens
   - Wenn nicht: NumElements-Offset proben (+0x20..+0x17C als u32, Range [10000,2M])
   - SIMD-Chunk-Decrypt Konstanten über Unicorn-Emulation (auto_chunks_emu.h)

---

## 7. decrypt_export.json Template

Minimale Felder die nach einem Patch-Update gesetzt sein müssen:

```json
{
  "patch_id": "imgsize-0x...",
  "timestamp": "2026-xx-xxT00:00:00Z",
  "anchors": {
    "gworld_rva": "0x...",
    "gnames_rva": "0x...",
    "gobjectarray_rva": "0x..."
  },
  "autodiscovery": {
    "vtables": {
      "script_struct_rva": "0x...",
      "class_native_rva": "0x...",
      "function_rva": "0x...",
      "enum_rva": "0x...",
      "package_rva": "0x...",
      "bpgc_rva": "0x..."
    }
  }
}
```

Alle anderen Felder werden automatisch durch Auto-Discovery und Auto-Export gefüllt.

---

## 8. Bekannte Fallstricke

1. **Config-Vtables werden von Phase 1 überschrieben** — daher existiert der Config-Merge in main.cpp. Engine-Vtables (Class, Function, Enum, Package, BPGC) aus Config behalten, AS-Types (ASClass, ASStruct) von Live-Discovery.

2. **IDA Decompiler zeigt falschen SHARD_HASH_ADD** — IDA trunciert manchmal FNV32 Mix-Formeln. Immer den Live-Wert aus dem Memory verifizieren.

3. **GUObjectArray SIMD-Pfad ist per-Session** — die PSHUFB/PXOR/ROL-Tabellen werden bei jedem Spielstart neu randomisiert. Heap-Scan-Fallback ist zuverlässiger als gespeicherte SIMD-Werte.

4. **Nie 2+ parallele Agents auf /dev/memreader** — Kernel-Rate-Limit Overflow → System-Hang.

5. **Struct-Duplikate nie droppen** — `struct_is_empty` muss für `!is_class` immer `false` returnen, sonst fallen ~12K Structs weg.

6. **ASStruct/ASClass Vtables sind per-Session** — können nicht in Config gecacht werden. Die Auto-Klassifikation via vtpre-id Sample-Namen (`Default__ASStruct`, `Default__ASClass`) erkennt sie automatisch.

7. **decrypt_export.json und arc_decrypt.h müssen synchron sein** — Config überschreibt arc_decrypt.h-Fallbacks. Bei Patch-Update beide aktualisieren.

---

## 9. Validierung nach Update

```bash
# Quick-Check: Naming Rate und Property Count
grep "Naming rate" /tmp/dump_new_patch.log
grep "FProperty_Unknown" /tmp/dump_new_patch.log
grep "\[+\]   Classes:" /tmp/dump_new_patch.log
grep "\[+\]   Structs:" /tmp/dump_new_patch.log
grep "\[+\]   Enums:" /tmp/dump_new_patch.log
grep "\[+\]   Functions:" /tmp/dump_new_patch.log
grep "\[+\]   Properties:" /tmp/dump_new_patch.log

# Diff gegen vorherigen SDK-Output
diff <(grep "^class " old_sdk/SDK_Output.txt | wc -l) <(grep "^class " sdk/SDK_Output.txt | wc -l)
```
