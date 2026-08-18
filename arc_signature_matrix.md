# Signaturmatrix — Function/Offset x Build

`JA` = mit dieser Signatur auf diesem Build aufgeloest. `NEIN` = nicht.

| Function/Offset | Art | Signatur | 02.04.2026 | 09.04.2026 | 14.04.2026 | 21.04.2026 | 28.04.2026 | 30.04.2026 | 05.05.2026 | 19.05.2026 | 16.06.2026 | 07.07.2026 | 09.07.2026 | 08.08.2026 | 11.08.2026 | 18.08.2026 | 18.08 live | gueltig |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| FProperty::SetupOffset (fn) | fn | `0F B7 ?? ?? 35 ?? ?? ?? ?? 0F C8 89 ?? ?? ?? ?? ??` | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | **15/15** |
| FProperty::Offset_Internal | offset | `0F B7 ?? ?? 35 ?? ?? ?? ?? 0F C8 89 ?? ?? ?? ?? ??` | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | **15/15** |
| FProperty::Offset_XOR | const | `0F B7 ?? ?? 35 ?? ?? ?? ?? 0F C8 89 ?? ?? ?? ?? ??` | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | **15/15** |
| FName resolver (fn) | fn | `81 ?? 00 FF FF 00  /  25 00 FF FF 00` | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | NEIN | **14/15** |
| GNamePool | global | `81 ?? 00 FF FF 00  /  25 00 FF FF 00  + rip-lea .data + FNV32` | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | NEIN | **14/15** |
| FName shard seed off | offset | `81 ?? 00 FF FF 00  /  25 00 FF FF 00` | JA | NEIN | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | NEIN | **13/15** |
| FName block base off | offset | `81 ?? 00 FF FF 00  /  25 00 FF FF 00` | JA | NEIN | NEIN | NEIN | JA | JA | JA | NEIN | JA | JA | JA | NEIN | JA | JA | NEIN | **9/15** |
| FName FNV64 add | const | `81 ?? 00 FF FF 00  /  25 00 FF FF 00  + B3 01 00 00 00 01 00 00` | JA | NEIN | JA | JA | NEIN | JA | JA | JA | JA | JA | JA | NEIN | JA | JA | NEIN | **11/15** |
| FName FNV64 rol1/rol2 | const | `81 ?? 00 FF FF 00  /  25 00 FF FF 00  + B3 01 00 00 00 01 00 00` | JA | NEIN | NEIN | NEIN | NEIN | NEIN | NEIN | NEIN | NEIN | NEIN | NEIN | JA | NEIN | NEIN | NEIN | **2/15** |
| FName KEY_INIT_ADD | const | `81 ?? 00 FF FF 00  /  25 00 FF FF 00` | NEIN | NEIN | NEIN | JA | NEIN | NEIN | NEIN | NEIN | NEIN | JA | NEIN | JA | JA | NEIN | NEIN | **4/15** |
| FNameEntry len mask | const | `81 ?? 00 FF FF 00  /  25 00 FF FF 00` | JA | JA | NEIN | NEIN | JA | JA | NEIN | NEIN | NEIN | NEIN | NEIN | JA | JA | NEIN | NEIN | **6/15** |
| chunks_manager global | global | `[48-4F] 8D [04|0C|14|1C|24|2C|34|3C] [80|89|92|9B|AD|B6|BF]  + vote 66 0F 6F 05` | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | NEIN | **14/15** |
| chunks_manager votes | stat | `[48-4F] 8D [04|0C|14|1C|24|2C|34|3C] [80|89|92|9B|AD|B6|BF]` | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | NEIN | **14/15** |
| stride-20 sites | stat | `[48-4F] 8D [04|0C|14|1C|24|2C|34|3C] [80|89|92|9B|AD|B6|BF]` | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | **15/15** |
| anchor "FName GetName() const" | anchor | `str "FName GetName() const" -> rip-ref -> lea` | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | NEIN | **14/15** |
| UObject::GetFName | fn | `str "FName GetName() const" -> rip-ref -> lea  + FNV32 & 83 E? 03` | JA | NEIN | NEIN | NEIN | NEIN | NEIN | JA | JA | NEIN | NEIN | JA | NEIN | JA | JA | NEIN | **6/15** |
| GetFName seed off | offset | `str "FName GetName() const" -> rip-ref -> lea` | JA | NEIN | NEIN | NEIN | NEIN | NEIN | JA | JA | NEIN | NEIN | JA | NEIN | JA | JA | NEIN | **6/15** |
| GetFName slot base | offset | `str "FName GetName() const" -> rip-ref -> lea` | JA | NEIN | NEIN | NEIN | NEIN | NEIN | NEIN | NEIN | NEIN | NEIN | JA | NEIN | JA | JA | NEIN | **4/15** |
| GetFName slot stride | offset | `str "FName GetName() const" -> rip-ref -> lea` | JA | NEIN | NEIN | NEIN | NEIN | NEIN | JA | JA | NEIN | NEIN | JA | NEIN | JA | JA | NEIN | **6/15** |
| GetFName slot xor | const | `str "FName GetName() const" -> rip-ref -> lea` | NEIN | NEIN | NEIN | NEIN | NEIN | NEIN | JA | NEIN | NEIN | NEIN | JA | NEIN | JA | JA | NEIN | **4/15** |
| GetFName hash add | const | `str "FName GetName() const" -> rip-ref -> lea` | JA | NEIN | NEIN | NEIN | NEIN | NEIN | JA | JA | NEIN | NEIN | JA | NEIN | JA | JA | NEIN | **6/15** |
| GetFName final rol | const | `str "FName GetName() const" -> rip-ref -> lea` | JA | NEIN | NEIN | NEIN | NEIN | NEIN | JA | JA | NEIN | NEIN | JA | NEIN | JA | JA | NEIN | **6/15** |
| GetFName slot consts | const | `str "FName GetName() const" -> rip-ref -> lea` | JA | NEIN | NEIN | NEIN | NEIN | NEIN | NEIN | JA | NEIN | NEIN | NEIN | NEIN | JA | JA | NEIN | **4/15** |
| GetFName slot shape | shape | `str "FName GetName() const" -> rip-ref -> lea` | JA | NEIN | NEIN | NEIN | NEIN | NEIN | JA | JA | NEIN | NEIN | JA | NEIN | JA | JA | NEIN | **6/15** |
| anchor PropertyBool.cpp | anchor | `str ".\\Runtime/CoreUObject/Private/UObject/PropertyBool.cpp"` | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | NEIN | **14/15** |
| PropertyBool.cpp refs | stat | `str ".\\Runtime/CoreUObject/Private/UObject/PropertyBool.cpp"` | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | NEIN | **14/15** |
| FBoolProperty::GetCPPType | fn | `str ".\\Runtime/CoreUObject/Private/UObject/PropertyBool.cpp"` | JA | JA | NEIN | NEIN | JA | JA | JA | NEIN | NEIN | JA | JA | JA | NEIN | JA | NEIN | **9/15** |
| FField::NamePrivate | offset | `str ".\\Runtime/CoreUObject/Private/UObject/PropertyBool.cpp"` | JA | JA | NEIN | NEIN | JA | JA | JA | NEIN | NEIN | JA | JA | JA | NEIN | JA | NEIN | **9/15** |
| FField name key1 | global | `str ".\\Runtime/CoreUObject/Private/UObject/PropertyBool.cpp"` | NEIN | NEIN | NEIN | NEIN | JA | NEIN | JA | NEIN | NEIN | JA | JA | JA | NEIN | JA | NEIN | **6/15** |
| FField name key2 | global | `str ".\\Runtime/CoreUObject/Private/UObject/PropertyBool.cpp"` | NEIN | NEIN | NEIN | NEIN | NEIN | NEIN | NEIN | NEIN | NEIN | NEIN | NEIN | NEIN | NEIN | JA | NEIN | **1/15** |
| FField name rot | const | `str ".\\Runtime/CoreUObject/Private/UObject/PropertyBool.cpp"` | JA | JA | NEIN | NEIN | JA | JA | JA | NEIN | NEIN | NEIN | JA | JA | NEIN | JA | NEIN | **8/15** |
| FField name shape | shape | `str ".\\Runtime/CoreUObject/Private/UObject/PropertyBool.cpp"` | JA | JA | NEIN | NEIN | JA | JA | JA | NEIN | NEIN | JA | JA | JA | NEIN | JA | NEIN | **9/15** |
| sizeof(FProperty) | offset | `str ".\\Runtime/CoreUObject/Private/UObject/PropertyBool.cpp"  + cmp byte [r+d], -1` | JA | JA | NEIN | NEIN | JA | NEIN | NEIN | NEIN | NEIN | NEIN | NEIN | NEIN | NEIN | JA | NEIN | **4/15** |

## Lesehilfe

`JA` = mit dieser Signatur auf diesem Build aufgeloest, `NEIN` = nicht.

Drei Dinge, ohne die die Spalten falsch gelesen werden:

- **Die letzte Spalte ist ein reines `.text`-Abbild** (kein `.rdata`, kein
  `.data`). Alles, was ein Global oder einen String braucht, kann dort nicht
  gehen - das liegt am Image, nicht an der Signatur. Ihre einzigen `JA` sind
  genau die drei Items, die nur `.text` brauchen.
- **`NEIN` heisst nicht "gibt es nicht"**, sondern "mit diesem Anker auf diesem
  Build nicht aufloesbar". Die Anker-Zeilen zeigen, dass der Einstiegspunkt fast
  ueberall sitzt; was darunter ausfaellt, ist der Extraktor, der die Form dieses
  Builds nicht kennt.
- **`UObject::GetFName` ist absichtlich unvollstaendig.** Theia liefert viele
  identische Klone aus, die RVA traegt also keine Information; nur die
  Konstanten daneben zaehlen.

Die drei Signaturen mit `JA` durchgaengig - der SetupOffset-Encode, die
ChunkOff-Maske und das stride-20-Idiom - beschreiben alle etwas, das die
**Engine** braucht. Die schwachen Zeilen beschreiben eine **Form, die Theia
besitzt**, und die wechselt pro Patch.


## Builds

| Spalte | Patch | Datei |
|---|---|---|
| 02.04.2026 | ? | Arc_Raiders_Binary_20260402_180339.exe |
| 09.04.2026 | ? | Arc_Raiders_Binary_20260409_145708.exe |
| 14.04.2026 | ? | Arc_Raiders_Binary_Steam_2026_04_14.exe |
| 21.04.2026 | ? | Arc_Raiders_Binary_20260421_213315.exe |
| 28.04.2026 | CL-1169740 | pioneer_steam_1.26.x-CL-1169740_2026_04_29__23_00_83pct.exe |
| 30.04.2026 | CL-1177146 | pioneer_steam_1.26.x-CL-1177146_2026_04_30__11_29_82pct.exe |
| 05.05.2026 | ? | ARC_RAIDERS_STEAM_MERGED_20260505_120058_77PagesDecrypted.exe |
| 19.05.2026 | CL-1195482 | pioneer_steam_1.29.x-CL-1195482_2026_05_19__18_05_77pct-merged.exe |
| 16.06.2026 | CL-1233465* | PioneerGame-d_300449_1781790403_fixed.bin |
| 07.07.2026 | CL-1299607 | pioneer_steam_1.36.x-CL-1299607_2026_07_07__15_35_82pct.exe |
| 09.07.2026 | CL-1315578 | pioneer_steam_1.36.x-CL-1315578_2026_07_09__16_35_83pct.exe |
| 08.08.2026 | CL-1325322 | pioneer_steam_1.39.x-CL-1325322_2026_08_08__22_23_83pct.exe |
| 11.08.2026 | 24653108 | pioneer_steam_1.39.x-CL-1335610_2026_08_11__13_45_81pct.exe |
| 18.08.2026 | CL-1341255 | pioneer_steam_1.42.x-CL-1341255_2026_08_18__11_32_82pct.exe |
| 18.08 live | 24653108* (Capture) | PioneerGame_dumped.exe |
