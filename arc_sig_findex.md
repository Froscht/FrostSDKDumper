# Ersatz-Signatur fuer `Dec_FIndex` (FName-Index-Decrypt)

## Warum die alte nicht geht

`48 C7 07 00 00 00 00 48 83` liefert 10–20 Treffer pro Build und landet auf
**keinem** von ihnen auf einer FName-Funktion. Geprueft auf CL-1341255 (17
Treffer, 17 Funktionen), auf 05.05.2026 (19/19) und auf CL-1315578 (15/15) —
in keinem Fall ist der bekannte Accessor darunter. Die Signatur matcht
`mov qword [rdi], 0` gefolgt von `48 83`, also ein Nullen eines Out-Parameters;
das kommt im Bild hundertfach vor und hat mit FName nichts zu tun.

## Die neue

```
48 8D 4? ?? 48 89 C2 48 C1 EA 20 C1 ?? ?? 69 ?? 93 01 00 01 05
```

Das ist der Kopf des FName-Accessors, Stueck fuer Stueck:

```
48 8D 4? ??           lea  rax, [rcx + SeedOff]       Seed = Objekt + Off
48 89 C2              mov  rdx, rax
48 C1 EA 20           shr  rdx, 0x20                  Hi-Dword abspalten
C1 ?? ??              rol/shr eax, N                  erster Hash-Schritt
69 ?? 93 01 00 01     imul eax, eax, 0x1000193        FNV-32-Prime
05                    add  eax, imm32                 Hash-Konstante
```

**Bestaetigung (Name-Rolle):** ab dem Treffer innerhalb 0x80 Bytes ein
`83 E? 03` (`and r32, 3`) suchen; steht direkt dahinter ein `83 F? ??`
(`xor r32, imm8`), ist es der Name-Slot. Ohne das xor sind es die Class- und
Outer-Accessoren, die dieselbe Hash-Kette teilen.

**Danach:** vom Treffer rueckwaerts bis zum `0xCC`-Padding laufen — das ist der
Funktionsanfang.

## Messung ueber 14 Builds

| build | Patch | Treffer | davon Name-Rolle | Konsens seed/slot | erste Fundstelle |
|---|---|---|---|---|---|
| 02.04.2026 | ? | 398 | 28 | +0x10 | 0x346696 |
| 09.04.2026 | ? | 230 | 22 | +0x10 / +0x20 | 0x3404CB |
| 14.04.2026 | ? | 355 | 38 | +0x10 / +0x20 | 0x34FBF4 |
| 21.04.2026 | ? | 394 | 31 | +0x10 | 0x33F857 |
| 28.04.2026 | CL-1169740 | 213 | 20 | +0x10 / +0x20 | 0x35E3CA |
| 30.04.2026 | CL-1177146 | 437 | 32 | +0x10 / +0x20 | 0x349252 |
| 05.05.2026 | ? | 317 | 33 | +0x10 | 0x3511C3 |
| 19.05.2026 | CL-1195482 | 324 | 35 | +0x10 | 0x349314 |
| 16.06.2026 | CL-1233465 | 307 | 10 | +0x10 / +0x20 | 0x3558D7 |
| 07.07.2026 | CL-1299607 | 509 | 43 | +0x10 / +0x20 | 0x35FE30 |
| 09.07.2026 | CL-1315578 | 375 | 40 | +0x10 / +0x20 | 0x3408D4 |
| 08.08.2026 | CL-1325322 | 297 | 29 | +0x10 | 0x3534C5 |
| 11.08.2026 | 24653108 | 266 | 33 | +0x10 / +0x20 | 0x41E506 |
| 18.08.2026 | CL-1341255 | 297 | 32 | +0x10 / +0x20 | **0x36477D** |

**Nie null, auf keinem Build.** Der Seed-Offset kommt auf allen 14 als `+0x10`
heraus, der Slot-Base auf 9 von 14 als `+0x20` (die restlichen nutzen eine
Adressierungsform ohne Index-Register, der Wert steht dort trotzdem im Code).

## Verifikation gegen bekannte Werte

Auf CL-1341255 ist die erste Fundstelle **0x36477D** — exakt das in CLAUDE.md
live-verifizierte `UObject::GetFName`. Von den 31 gefundenen Funktionen liefern
19 exakt die dokumentierten Konstanten:

```
seed  +0x10      slot base +0x20
K1    0x0B6641A64F1B214D
K2    0x8FA21A13D9179A47
```

## Warum es dutzende Treffer gibt und das richtig so ist

Theia dupliziert den Accessor. Die 10–43 Name-Rollen-Treffer sind aequivalente
Klone derselben Funktion — welcher zuerst gefunden wird, traegt keine
Information, alle dekodieren identisch. Nimm irgendeinen.

## Was NICHT portabel ist

Der Rumpf hinter dem Kopf. Die Slot-Auswahl ist auf CL-1325322 als
`((((~S | 0x565AFC0) & 0x565AFC1) | (S & 2)) ^ 0x565AFC3) & 3` verschleiert
statt als schlichtes `and 3`, weshalb eine Signatur auf das Ende
(`89 C2 C1 EA 10 31 C2 83 E2 03 …`) je nach Build zwischen 5 und 1125 Treffern
schwankt. Der Kopf haelt, weil die FNV-Kette etwas ist, das die Engine braucht;
das Ende haelt nicht, weil die Slot-Algebra etwas ist, das Theia besitzt.
