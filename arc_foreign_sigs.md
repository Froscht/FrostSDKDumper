# Fremd-Signaturen — geprueft ueber 15 Builds

`JA` = genau ein Treffer in `.text`. `NEIN` = keiner. `N x` = mehrdeutig.

| Signatur-Name | Pattern | 02.04 (?) | 09.04 (?) | 14.04 (?) | 21.04 (?) | 28.04 (CL-1169740) | 30.04 (CL-1177146) | 05.05 (?) | 19.05 (CL-1195482) | 16.06 (CL-1233465*) | 07.07 (CL-1299607) | 09.07 (CL-1315578) | 08.08 (CL-1325322) | 11.08 (24653108) | 18.08 (CL-1341255) | 18.08 live (24653108* (Capture)) | eindeutig | Hinweis |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| APlayerState::DecryptPlayerName | `41 57 41 56 41 54 56 57 55 53 48 83 EC ?? 48 89 D6 80 B9` | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | **15/15** | eindeutig auf allen; auf CL-1341255 @0x3731030, sauberer Prolog |
| Dec_BoneArray (lang) | `49 8D 6D 60 BB 01 00 00 00 45 31 F6 66 45 0F 57 D2 F2 44 0F 10 0D` | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | NEIN | **14/15** | CL-1341255 @0x2FD46B0; Miss nur im .text-Teilabbild |
| Dec_BoneArray (kurz) | `49 8D 6D ?? BB` | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | NEIN | **14/15** | identisch zur langen Form - kuerzer, gleich eindeutig |
| UWorld | `48 8B 05 ?? ?? ?? ?? 4C 8D 3D ?? ?? ?? ?? 89 F1 EB ?? 44 01 CB FF C3 BD ?? ?? ?? ?? 66 0F 1F 84 00` | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | **15/15** | MATCHT ueberall, ZEIGT aber auf CL-1341255 nicht auf GWorld (0xE825368 statt 0xE782D78) |
| Dec_GWorld | `E8 ?? ?? ?? ?? F6 ?? ?? ?? 01 0F 85 ?? ?? 00 00 8B 05` | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | **15/15** | eindeutig auf allen; Call-Ziel CL-1341255 0x40FDB0 |
| Dec_FIndex | `48 C7 07 00 00 00 00 48 83` | 11 x | 13 x | 17 x | 15 x | 18 x | 20 x | 19 x | 18 x | 17 x | 16 x | 15 x | 16 x | 17 x | 17 x | 10 x | **0/15** | nie eindeutig (10-20 Treffer) - als Kandidatengenerator gedacht, nicht als Locator |
| Dec_GName_Index2Name | `48 8D 4C 24 28 48 8D 94 24 30 08 00 00 E8 ?? ?? ?? ?? 89 C6 48 8D 4C 24 20 48 8D 54 24 30 E8` | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | NEIN | JA | **14/15** | bricht genau auf CL-1341255; Stack-Displacements maskieren repariert es |
| Dec_GName_Index2Name RELAXED | `48 8D 4C 24 ?? 48 8D 94 24 ?? ?? 00 00 E8 ?? ?? ?? ?? 89 C6 48 8D 4C 24 ?? 48 8D 54 24 ?? E8` | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | JA | **15/15** | eindeutig auf allen 15 - empfohlene Ersatzform |
| Dec_PlayerNamePrivate | `48 89 ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 54 ?? ?? 48 89 F1 E8 ?? ?? ?? ?? 83 7C` | JA | JA | JA | NEIN | JA | JA | JA | JA | NEIN | NEIN | NEIN | NEIN | NEIN | NEIN | NEIN | **7/15** | DIESELBE Funktion wie DecryptPlayerName (7/7 geprueft), nur ueber eine Aufrufstelle. Bricht ab 07.07 - direkte Signatur nehmen |

## Befunde

1. **Drei Signaturen sind auf allen 15 Builds eindeutig**: `DecryptPlayerName`,
   `Dec_GWorld` und die `UWorld`-Maske. `Dec_BoneArray` in beiden Formen auf
   14/15 - der eine Miss ist ein reines `.text`-Teilabbild, kein Signaturfehler.

2. **`Dec_GName_Index2Name` bricht genau auf dem aktuellen Patch** und sonst
   nirgends. Ursache sind die einkodierten Stack-Displacements (`24 28`,
   `24 30 08 00 00`, `24 20`, `24 30`). Maskiert man sie, ist die Signatur auf
   allen 15 Builds wieder eindeutig. Die RELAXED-Zeile ist die Ersatzform.

3. **`Dec_PlayerNamePrivate` und `APlayerState::DecryptPlayerName` finden
   DIESELBE Funktion.** Auf allen 7 Builds, auf denen beide greifen, landet das
   `E8` hinter `48 89 F1` exakt auf der Adresse, die die direkte Signatur
   liefert (02.04 0x37339E0, 09.04 0x37588D0, 14.04 0x37753D0, 28.04 0x374EA50,
   30.04 0x372A800, 05.05 0x374D410, 19.05 0x3745690).

   Der Unterschied ist nur der Weg: die eine matcht eine AUFRUFSTELLE, die
   andere den PROLOG. Die Aufrufstelle ist ab 07.07 tot und laesst sich nicht
   relaxieren - jede Lockerung bringt 15-18 Treffer. Die direkte Signatur ist
   15/15. Ergo: `Dec_PlayerNamePrivate` ersatzlos streichen.

4. **`Dec_FIndex` war nie eindeutig** (10-20 Treffer pro Build). Passt zur
   Anmerkung des Autors "you need to move up i think to find it": gedacht als
   Kandidatengenerator, nicht als Locator.

5. **Die `UWorld`-Signatur matcht ueberall und ist trotzdem falsch.** Auf
   CL-1341255 loest sie `.data 0xE825368` auf; live dereferenziert liegt dort
   Muell. Der verifizierte GWorld ist `0xE782D78` -> Wrapper `0xED53CAC0` ->
   `0xE75930D0` "MainMenu". Beide Wrapper liegen 0x300 auseinander, die Signatur
   greift also einen Nachbarslot. Ein Treffer ist kein Beweis - was zaehlt ist,
   was am Ziel steht.

