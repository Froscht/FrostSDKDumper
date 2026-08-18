# `Dec_FIndex` — Ersatz fuer den FName-Index-Decrypt

## Die alte ist falsch

`48 C7 07 00 00 00 00 48 83` = `mov qword [rdi], 0` gefolgt von `48 83`, also ein
genulltes Out-Parameter. Das kommt hundertfach vor. Geprueft auf CL-1341255
(17 Treffer / 17 Funktionen), 05.05.2026 (19/19) und CL-1315578 (15/15): der
bekannte Accessor ist in **keiner** davon.

## Weg 1 — reine Byte-Signatur (Scan)

Zwei zulaessige Formen, weil der Compiler das High-Dword mal sofort abspaltet und
mal in einem Register haelt:

```
Form A   48 8D [41|49|51|59|61|69|71|79] ?? 4? 89 ?? 4? C1 E? 20 C1 ?? ?? 69 ?? 93 01 00 01
Form B   48 8D [41|49|51|59|61|69|71|79] ?? 4? 89 ??             C1 ?? ?? 69 ?? 93 01 00 01
```

```
48 8D [..] ??          lea  r64, [rcx + SeedOff]     Seed = Objekt + Off
4? 89 ??               mov  r64, r64                 Kopie fuer das High-Dword
4? C1 E? 20            shr  r64, 0x20                (nur Form A)
C1 ?? ??               rol/shr r32, imm8             erster Hash-Schritt
69 ?? 93 01 00 01      imul r32, r32, 0x1000193      FNV-32-Prime
```

**Name-Rolle bestaetigen:** ab dem Treffer innerhalb 0x80 ein `83 E? 03`
(`and r32,3`) suchen; folgt direkt ein `83 F? ??` (`xor r32,imm8`), ist es der
Name-Slot. Ohne xor sind es Class und Outer, die dieselbe Hash-Kette teilen.
Dann rueckwaerts bis `0xCC` = Funktionsanfang.

Treffer (Form A allein, ueber 14 Builds): **505–793, nie null.** Alle sind echte
Accessor-Koepfe — Verlaengern der Signatur um die zweite FNV-Runde aendert die
Zahl nicht. Die Breite ist Theias Duplikation, kein Rauschen; alle Klone
dekodieren identisch, nimm irgendeinen.

## Weg 2 — genau EINE Funktion (empfohlen)

Wenn du den kanonischen Accessor willst statt irgendeinen Klon, kombiniere den
AngelScript-String mit der Kopfform:

```
1. String ".FName GetName() const" in .rdata suchen
2. rip-relative Referenzen darauf in .text (meist 2)
3. ab jeder Referenz bis 200 Bytes rueckwaerts nach `48/4C 8D 05 disp32` suchen
4. Ziel behalten, wenn Form A oder B innerhalb 0x100 Bytes darauf passt
5. rueckwaerts bis 0xCC = Funktionsanfang
```

| build | Patch | Kandidaten | Ziel | Funktionsanfang | seed |
|---|---|---|---|---|---|
| 02.04.2026 | ? | 1 | 0x355D90 | 0x355C47 | +0x10 |
| 09.04.2026 | ? | **0** | — | — | — |
| 14.04.2026 | ? | 1 | 0x344330 | 0x3442F9 | +0x10 |
| 21.04.2026 | ? | 2 | 0x353CD0 | 0x353C31 | +0x10 |
| 28.04.2026 | CL-1169740 | 1 | 0x35EB60 | 0x35EB0F | +0x10 |
| 30.04.2026 | CL-1177146 | 1 | 0x3465D0 | 0x3464BB | +0x10 |
| 05.05.2026 | ? | 1 | 0x3591F0 | 0x3591E0 | +0x10 |
| 19.05.2026 | CL-1195482 | 1 | 0x346360 | 0x3462B3 | +0x10 |
| 16.06.2026 | CL-1233465 | 1 | 0x362F80 | 0x362E67 | +0x10 |
| 07.07.2026 | CL-1299607 | 1 | 0x360DC0 | 0x360D94 | +0x10 |
| 09.07.2026 | CL-1315578 | 1 | 0x3589E0 | 0x3589D2 | +0x10 |
| 08.08.2026 | CL-1325322 | 1 | 0x343950 | 0x343942 | +0x10 |
| 11.08.2026 | 24653108 | 1 | 0x350800 | 0x3507E0 | +0x10 |
| 18.08.2026 | CL-1341255 | 1 | 0x364780 | **0x36477D** | +0x10 |

**13 von 14, fast immer genau ein Kandidat.** Gegen CLAUDE.md geprueft:
CL-1325322 liefert `0x343950` und CL-1341255 `0x36477D` — beide exakt die
live-verifizierten Adressen. Der Seed-Offset kommt auf allen 13 als `+0x10`
heraus. Einziger Ausfall ist 09.04.2026, dessen Registrierung nur eine Referenz
hat und einen anderen Aufbau nutzt.

## Was ich beim ersten Anlauf falsch hatte

Meine erste Fassung war
`48 8D 4? ?? 48 89 C2 48 C1 EA 20 C1 ?? ?? 69 ?? 93 01 00 01 05`.
Die traf zwar auf allen Builds etwas, aber `48 89 C2` (`mov rdx,rax`) und `05`
(`add eax,imm32`) sind die Registerbelegung von CL-1341255. CL-1325322 nutzt
`49 89 D0` und `81 C2`, CL-1169740 laesst das `shr` ganz weg. Sie fand dort also
andere Klone, nie den kanonischen. Die Formen A/B oben decken alle drei
Belegungen ab — sichtbar daran, dass Weg 2 damit von 1/14 auf 13/14 springt.

## Was NICHT portabel ist

Das Ende des Accessors. Eine Signatur auf die Slot-Auswahl
(`89 C2 C1 EA 10 31 C2 83 E2 03 ...`) schwankt zwischen 5 und 1125 Treffern, weil
CL-1325322 sie als `((((~S | 0x565AFC0) & 0x565AFC1) | (S & 2)) ^ 0x565AFC3) & 3`
verschleiert. Der Kopf haelt, weil die FNV-Kette etwas ist, das die Engine
braucht; die Slot-Algebra gehoert Theia.
