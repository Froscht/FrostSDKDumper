# ARC Raiders — Offsets und Funktionen über alle Builds

Statisch aus jedem Image extrahiert (kein Live-Zugriff). Leere Zelle = auf diesem Build nicht aufloesbar.

| Item | Art | 02.04.2026 | 09.04.2026 | 14.04.2026 | 21.04.2026 | 28.04.2026 | 30.04.2026 | 05.05.2026 | 19.05.2026 | 16.06.2026 | 07.07.2026 | 09.07.2026 | 08.08.2026 | 11.08.2026 | 18.08.2026 | 18.08 | Gueltig | n |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| image size | meta | 0xE891000 | 0xE8B6000 | 0xE9AF000 | 0xE97E000 | 0xE9D0000 | 0xEA2F000 | 0xEA60000 | 0xF0F5000 | 0x1179C000 | 0x117B4000 | 0x117E1000 | 0x11853000 | 0x117E9000 | 0x116E7000 | 0xB3E7000 | JA | 15/15 |
| .text | meta | 0x1000..0xABD7000 | 0x1000..0xAC20000 | 0x1000..0xAD24000 | 0x1000..0xACB4000 | 0x1000..0xAD04000 | 0x1000..0xAD35000 | 0x1000..0xAD8C000 | 0x1000..0xB2EC000 | 0x1000..0xB3DD000 | 0x1000..0xB4B7000 | 0x1000..0xB516000 | 0x1000..0xB47D000 | 0x1000..0xB3E7000 | 0x1000..0xB378000 | 0x1000..0xB3E7000 | JA | 15/15 |
| FName resolver (fn) | fn | 0x235AA3 | 0x23D505 | 0x248483 | 0x242FB4 | 0x23CF8C | 0x24046C | 0x245886 | 0x23A0A0 | 0x2402BA | 0x247956 | 0x24123A | 0x2487B8 | 0x23EC33 | 0x249489 | — | TEILWEISE | 14/15 |
| UObject::GetFName | fn | 0x2CD0A86 | — | — | — | — | — | 0x3591E0 | 0x2CF8AAF | — | — | 0x3589D2 | — | 0x3507E0 | 0x36477D | — | TEILWEISE | 6/15 |
| FBoolProperty::GetCPPType | fn | 0x41D253 | 0x420D67 | — | — | 0x44D2F3 | 0x430AD3 | 0x4249CF | — | — | 0x438F50 | 0x429EDF | 0x447870 | — | 0x42B690 | — | TEILWEISE | 9/15 |
| FProperty::SetupOffset (fn) | fn | 0x441073 | 0x425883 | 0x43CC58 | 0x44EB87 | 0x43A75F | 0x42F050 | 0x455B81 | 0x4383DF | 0x4438B5 | 0x452B78 | 0x438E50 | 0x448422 | 0x43011B | 0x432990 | 0x42F31B | JA | 15/15 |
| GNamePool | global | 0xDA26E00 | 0xDA4FE00 | 0xDB48E80 | 0xDB0FE00 | 0xDB5BE80 | 0xDBB3F80 | 0xDBE9E80 | 0xE23DA00 | 0xE376A80 | 0xE4A3A00 | 0xE4F2A00 | 0xE431980 | 0xE38FA00 | 0xE35AB00 | — | TEILWEISE | 14/15 |
| chunks_manager global | global | 0xDCE2440 | 0xDD0B5D0 | 0xDB0F530 | 0xDDCB420 | 0xDE17450 | 0xDB7A630 | 0xDBB0530 | 0xE4F9070 | 0xE632330 | 0xE75F240 | 0xE7ADFF0 | 0xE6ED2A0 | 0xE64B260 | 0xE616340 | — | TEILWEISE | 14/15 |
| FField name key1 | global | — | — | — | — | 0xC8727080CA112779 | — | 0x4882C8C849A43F3B | — | — | 0x2BC795817F5A4D23 | 0x8FFAB191C340B792 | 0x09DCB521A13AC4BC | — | 0xFDF20AE0DF1B2EFB | — | TEILWEISE | 6/15 |
| FField name key2 | global | — | — | — | — | — | — | — | — | — | — | — | — | — | 0x020DF52020E4D105 | — | TEILWEISE | 1/15 |
| FProperty::Offset_Internal | offset | +0x64 | +0xE0 | +0xEC | +0xC0 | +0xB4 | +0xC4 | +0x8C | +0x64 | +0xE4 | +0x94 | +0xE4 | +0xB4 | +0xC4 | +0xA4 | +0xC4 | JA | 15/15 |
| FProperty::Offset_XOR | const | 0xC43565C9 | 0xAD9FCB8C | 0xD63FB02A | 0x59B8C401 | 0x34605D14 | 0x48742740 | 0xBBACCCCC | 0xD632B3E9 | 0xEAABEC11 | 0x057F15E5 | 0xA271DBC5 | 0x76C317A2 | 0xEE0CA1CB | 0x7BDAAA72 | 0xEE0CA1CB | JA | 15/15 |
| FField::NamePrivate | offset | +0x50 | +0xA0 | — | — | +0x70 | +0x70 | +0x30 | — | — | +0x40 | +0xA0 | +0x60 | — | +0x50 | — | TEILWEISE | 9/15 |
| sizeof(FProperty) | offset | 0xD0 | 0x150 | — | — | 0x108 | — | — | — | — | — | — | — | — | 0x100 | — | TEILWEISE | 4/15 |
| FField name rot | const | ROL32(26) | ROL32(23) | — | — | ROL64(21) | ROL32(13) | ROL64(55) | — | — | — | ROL16(12) | ROL32(9) | — | ROL32(29) | — | TEILWEISE | 8/15 |
| FField name shape | shape | pshufb psrld pslld por rol | psrld pslld por pshufb psrld pslld por rol | — | — | psrlq psllq por pxor psrlw psllw por rol | psrld pslld por rol | psrlq psllq por pshufb pxor rol | — | — | pshufb pxor rol | pxor psrlw psllw por pshufb rol | pandn pand por pshuflw pxor psrld pslld por rol | — | pxor psrld pslld por paddd rol | — | TEILWEISE | 9/15 |
| GetFName seed off | offset | +0x20 | — | — | — | — | — | +0x10 | +0x20 | — | — | +0x10 | — | +0x10 | +0x10 | — | TEILWEISE | 6/15 |
| GetFName slot base | offset | +0x90 | — | — | — | — | — | — | — | — | — | +0x20 | — | +0x20 | +0x20 | — | TEILWEISE | 4/15 |
| GetFName slot stride | offset | 0x20 | — | — | — | — | — | 0x20 | 0x20 | — | — | 0x20 | — | 0x20 | 0x20 | — | TEILWEISE | 6/15 |
| GetFName slot xor | const | — | — | — | — | — | — | 2 | — | — | — | 2 | — | 2 | 2 | — | TEILWEISE | 4/15 |
| GetFName hash add | const | 0x786727F9 | — | — | — | — | — | 0x98689957 | 0x119DDFD0 | — | — | 0xF3D8DA36 | — | 0x21B21773 | 0xD4C2DB3A | — | TEILWEISE | 6/15 |
| GetFName final rol | const | 15 | — | — | — | — | — | 32 | 17 | — | — | 32 | — | 24 | 32 | — | TEILWEISE | 6/15 |
| GetFName slot consts | const | 0x7C3784BD4ECB382 | — | — | — | — | — | — | 0x890EF320D7E2DC4C / 0xB982F16865A5F21 | — | — | — | — | 0x1554577E835E9F4 / 0x1554577E835E9F4 | 0x8FA21A13D9179A47 / 0xB6641A64F1B214D | — | TEILWEISE | 4/15 |
| GetFName slot shape | shape | call call shr rol rol rol shr shr pshuflw rol | — | — | — | — | — | shr rol rol shr shr shr pshuflw psrld pslld por | call call call shr rol rol rol rol shr pshuflw | — | — | shr rol rol rol rol shr psrlq psllq por pshuflw | — | call shr rol shr shr shr shr pshufb psrlw psllw | shr rol rol rol rol shr call rol call call | — | TEILWEISE | 6/15 |
| FName shard seed off | offset | +0x7080 | — | +0x4150 | +0x6570 | +0x7090 | +0x7050 | +0x7000 | +0x70D0 | +0xC50 | +0x6FD0 | +0x2F90 | +0x4C90 | +0x6550 | +0x6FD0 | — | TEILWEISE | 13/15 |
| FName block base off | offset | +0x7090 | — | — | — | +0x70A0 | +0x7060 | +0x7010 | — | +0xC60 | +0x6FE0 | +0x2FA0 | — | +0x6560 | +0x6FE0 | — | TEILWEISE | 9/15 |
| FName FNV64 add | const | 0x6BB5C341DE05D8A6 | — | 0x2AE2DE663CDF7F3A | 0xA369D63928ACD6A2 | — | 0xFCB1912DDB61B963 | 0x9861E39DEBEE5306 | 0x61E912C25C5F0996 | 0x124CB31365185276 | 0xEB1E82D44384D6E6 | 0x10F3A73711CE0312 | — | 0x323C186F5D5C1B15 | 0x6463CD794F959557 | — | TEILWEISE | 11/15 |
| FName FNV64 rol1/rol2 | const | 38/3 | — | — | — | — | — | — | — | — | — | — | 55/57 | — | — | — | TEILWEISE | 2/15 |
| FName KEY_INIT_ADD | const | — | — | — | 0x2068 | — | — | — | — | — | 0x2098 | — | 0x6C22 | 0x7216 | — | — | TEILWEISE | 4/15 |
| FNameEntry len mask | const | 0x3FF | 0x3FF | — | — | 0x3F | 0x3F | — | — | — | — | — | 0x3FF | 0x3F | — | — | TEILWEISE | 6/15 |
| stride-20 sites | stat | 9391 | 8522 | 14957 | 12618 | 15879 | 15556 | 13597 | 13933 | 13341 | 15435 | 13917 | 13502 | 14954 | 13881 | 9166 | JA | 15/15 |
| chunks_manager votes | stat | 1250 | 1250 | 11 | 1475 | 79 | 13 | 8 | 1631 | 1499 | 1563 | 1429 | 1494 | 89 | 1956 | — | TEILWEISE | 14/15 |
| anchor "FName GetName() const" | anchor | 0xB7DCA95 | 0xB81B415 | 0xB9239B5 | 0xB8C00A5 | 0xB8FF675 | 0xB943D25 | 0xB9912C5 | 0xBEFBAD5 | 0xBFE86E5 | 0xC0C0BA5 | 0xC122E25 | 0xC084885 | 0xBFE9CC5 | 0xBF7BD95 | — | TEILWEISE | 14/15 |
| anchor PropertyBool.cpp | anchor | 0xAC5F90C | 0xACA80AC | 0xADAC224 | 0xAD3C6FC | 0xAD8C86C | 0xADBE2AC | 0xAE148DC | 0xB37518C | 0xB4671FC | 0xB541274 | 0xB5A028C | 0xB506FEC | 0xB47096C | 0xB40215C | — | TEILWEISE | 14/15 |
| PropertyBool.cpp refs | stat | 3 | 3 | 3 | 3 | 3 | 3 | 3 | 3 | 3 | 3 | 3 | 3 | 3 | 3 | — | TEILWEISE | 14/15 |

## Builds

| Ordner | Patch | Datei |
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
| 08.08.2026 ca | CL-1325322 | pioneer_steam_1.39.x-CL-1325322_2026_08_08__22_23_83pct.exe |
| 11.08.2026 | 24653108 | pioneer_steam_1.39.x-CL-1335610_2026_08_11__13_45_81pct.exe |
| 18.08.2026 | CL-1341255 | pioneer_steam_1.42.x-CL-1341255_2026_08_18__11_32_82pct.exe |
| 18.08 live | 24653108* (Capture) | PioneerGame_dumped.exe |

## Lesehilfe

- **Gueltig JA** = auf allen 15 Images aufloesbar. **TEILWEISE** = nur auf den
  Builds, deren Shape der Extraktor kennt. **NEIN** = nirgends.
- Ein leeres Feld heisst NICHT "existiert nicht", sondern "mit diesem Anker auf
  diesem Build nicht aufloesbar".
- `UObject::GetFName` ist absichtlich nur TEILWEISE: Theia liefert viele
  identische Klone aus, die RVA traegt also keine Information. Was zaehlt sind
  die extrahierten Konstanten daneben.
- Zwei Builds wurden ueber ihre Werte IDENTIFIZIERT, nicht ueber den Ordnernamen:
  16.06.2026 traegt CL-1233465s dokumentiertes Paar (+0xE4 / 0xEAABEC11), und der
  Capture in EasyDump/captures ist auf 18.08 datiert, traegt aber 24653108s Paar
  (+0xC4 / 0xEE0CA1CB) - also ein aelteres Prozessabbild als sein Datum suggeriert.
  Mit `*` markiert.
- Gegen CLAUDE.md geprueft und exakt: Offset_Internal und XOR auf 6 Builds,
  GNamePool auf 5, FField::NamePrivate auf 6, chunks_manager auf 4, und die
  Shard-Seed-Offsets +0x6FD0 / +0x2F90 / +0x4C90 / +0x6550 auf 4.
