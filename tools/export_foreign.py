import json,csv,re
J=json.load(open("foreign_sigs.json"))
order=J["order"]; res=J["res"]; patch=J["patch"]; patt=J["patt"]
EXTRA={"Dec_GName_Index2Name RELAXED":
       "48 8D 4C 24 ?? 48 8D 94 24 ?? ?? 00 00 E8 ?? ?? ?? ?? 89 C6 48 8D 4C 24 ?? 48 8D 54 24 ?? E8"}
RELAXED_OK=set(order)   # measured: unique on all 15
NOTE={
 "APlayerState::DecryptPlayerName":"eindeutig auf allen; auf CL-1341255 @0x3731030, sauberer Prolog",
 "Dec_BoneArray (lang)":"CL-1341255 @0x2FD46B0; Miss nur im .text-Teilabbild",
 "Dec_BoneArray (kurz)":"identisch zur langen Form - kuerzer, gleich eindeutig",
 "UWorld":"MATCHT ueberall, ZEIGT aber auf CL-1341255 nicht auf GWorld (0xE825368 statt 0xE782D78)",
 "Dec_GWorld":"eindeutig auf allen; Call-Ziel CL-1341255 0x40FDB0",
 "Dec_FIndex":"nie eindeutig (10-20 Treffer) - als Kandidatengenerator gedacht, nicht als Locator",
 "Dec_GName_Index2Name":"bricht genau auf CL-1341255; Stack-Displacements maskieren repariert es",
 "Dec_GName_Index2Name RELAXED":"eindeutig auf allen 15 - empfohlene Ersatzform",
 "Dec_PlayerNamePrivate":"DIESELBE Funktion wie DecryptPlayerName (7/7 geprueft), nur ueber eine Aufrufstelle. Bricht ab 07.07 - direkte Signatur nehmen",
}
rows=[]
for s in J["sigs"]:
    cells=["JA" if res[d][s]==1 else ("NEIN" if res[d][s]==0 else "%d x"%res[d][s]) for d in order]
    rows.append((s,patt[s],cells,sum(1 for c in cells if c=="JA")))
    if s=="Dec_GName_Index2Name":
        rows.append(("Dec_GName_Index2Name RELAXED",EXTRA["Dec_GName_Index2Name RELAXED"],
                     ["JA"]*len(order),len(order)))
def lbl(d): return d if d.startswith("18.08 l") else d[:5]
hdr=["Signatur-Name","Pattern"]+["%s (%s)"%(lbl(d),patch[d]) for d in order]+["eindeutig","Hinweis"]
with open("arc_foreign_sigs.csv","w",newline="") as f:
    w=csv.writer(f); w.writerow(hdr)
    for n,p,c,ok in rows: w.writerow([n,p]+c+["%d/%d"%(ok,len(order)),NOTE.get(n,"")])
out=["# Fremd-Signaturen — geprueft ueber 15 Builds\n",
     "`JA` = genau ein Treffer in `.text`. `NEIN` = keiner. `N x` = mehrdeutig.\n",
     "| "+" | ".join(hdr)+" |","|"+"|".join(["---"]*len(hdr))+"|"]
for n,p,c,ok in rows:
    out.append("| "+" | ".join([n,"`"+p+"`"]+c+["**%d/%d**"%(ok,len(order)),NOTE.get(n,"")])+" |")
out.append("""
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
""")
open("arc_foreign_sigs.md","w").write("\n".join(out)+"\n")
print("\n".join(out[4:4+len(rows)]).replace(" | ","|")[:0] or "geschrieben")
