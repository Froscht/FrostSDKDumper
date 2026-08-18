import json,csv,re
J=json.load(open("allbuilds.json")); rows=J["rows"]
def key(d):
    m=re.match(r"(\d\d)\.(\d\d)\.(\d{4})",d)
    return (m.group(3),m.group(2),m.group(1),d) if m else ("9999","","",d)
order=sorted(J["order"],key=key)

SIG_SETUP  = "0F B7 ?? ?? 35 ?? ?? ?? ?? 0F C8 89 ?? ?? ?? ?? ??"
SIG_CHUNKOFF="81 ?? 00 FF FF 00  /  25 00 FF FF 00"
SIG_STRIDE = "[48-4F] 8D [04|0C|14|1C|24|2C|34|3C] [80|89|92|9B|AD|B6|BF]"
SIG_GETNAME= 'str "FName GetName() const" -> rip-ref -> lea'
SIG_PROPBOOL='str ".\\\\Runtime/CoreUObject/Private/UObject/PropertyBool.cpp"'

ITEMS=[
 ("FProperty::SetupOffset (fn)","fn",     SIG_SETUP),
 ("FProperty::Offset_Internal","offset",  SIG_SETUP),
 ("FProperty::Offset_XOR","const",        SIG_SETUP),
 ("FName resolver (fn)","fn",             SIG_CHUNKOFF),
 ("GNamePool","global",                   SIG_CHUNKOFF+"  + rip-lea .data + FNV32"),
 ("FName shard seed off","offset",        SIG_CHUNKOFF),
 ("FName block base off","offset",        SIG_CHUNKOFF),
 ("FName FNV64 add","const",              SIG_CHUNKOFF+"  + B3 01 00 00 00 01 00 00"),
 ("FName FNV64 rol1/rol2","const",        SIG_CHUNKOFF+"  + B3 01 00 00 00 01 00 00"),
 ("FName KEY_INIT_ADD","const",           SIG_CHUNKOFF),
 ("FNameEntry len mask","const",          SIG_CHUNKOFF),
 ("chunks_manager global","global",       SIG_STRIDE+"  + vote 66 0F 6F 05"),
 ("chunks_manager votes","stat",          SIG_STRIDE),
 ("stride-20 sites","stat",               SIG_STRIDE),
 ('anchor "FName GetName() const"',"anchor", SIG_GETNAME),
 ("UObject::GetFName","fn",               SIG_GETNAME+"  + FNV32 & 83 E? 03"),
 ("GetFName seed off","offset",           SIG_GETNAME),
 ("GetFName slot base","offset",          SIG_GETNAME),
 ("GetFName slot stride","offset",        SIG_GETNAME),
 ("GetFName slot xor","const",            SIG_GETNAME),
 ("GetFName hash add","const",            SIG_GETNAME),
 ("GetFName final rol","const",           SIG_GETNAME),
 ("GetFName slot consts","const",         SIG_GETNAME),
 ("GetFName slot shape","shape",          SIG_GETNAME),
 ("anchor PropertyBool.cpp","anchor",     SIG_PROPBOOL),
 ("PropertyBool.cpp refs","stat",         SIG_PROPBOOL),
 ("FBoolProperty::GetCPPType","fn",       SIG_PROPBOOL),
 ("FField::NamePrivate","offset",         SIG_PROPBOOL),
 ("FField name key1","global",            SIG_PROPBOOL),
 ("FField name key2","global",            SIG_PROPBOOL),
 ("FField name rot","const",              SIG_PROPBOOL),
 ("FField name shape","shape",            SIG_PROPBOOL),
 ("sizeof(FProperty)","offset",           SIG_PROPBOOL+"  + cmp byte [r+d], -1"),
]
def lbl(d): return d.split()[0] if " " in d and not d.startswith("18.08 l") else d
hdr=["Function/Offset","Art","Signatur"]+[lbl(d) for d in order]+["gueltig"]
with open("arc_signature_matrix.csv","w",newline="") as f:
    w=csv.writer(f); w.writerow(hdr)
    for name,kind,sig in ITEMS:
        cells=["JA" if rows[d].get(name) else "NEIN" for d in order]
        w.writerow([name,kind,sig]+cells+["%d/%d"%(cells.count("JA"),len(order))])
out=[]
out.append("# Signaturmatrix — Function/Offset x Build\n")
out.append("`JA` = mit dieser Signatur auf diesem Build aufgeloest. `NEIN` = nicht.\n")
out.append("| "+" | ".join(hdr)+" |")
out.append("|"+"|".join(["---"]*len(hdr))+"|")
for name,kind,sig in ITEMS:
    cells=["JA" if rows[d].get(name) else "NEIN" for d in order]
    out.append("| "+" | ".join([name,kind,"`"+sig+"`"]+cells+["**%d/%d**"%(cells.count("JA"),len(order))])+" |")
out.append("""
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
""")
out.append("\n## Builds\n")
out.append("| Spalte | Patch | Datei |"); out.append("|---|---|---|")
for d in order: out.append("| %s | %s | %s |"%(lbl(d),rows[d].get("__patch","?"),rows[d].get("__file","")))
open("arc_signature_matrix.md","w").write("\n".join(out)+"\n")
# console
print("%-30s %-38s %s"%("Function/Offset","Signatur",  " ".join("%-5s"%lbl(d)[:5] for d in order)))
print("-"*(30+38+6*len(order)))
for name,kind,sig in ITEMS:
    cells=["JA " if rows[d].get(name) else "-- " for d in order]
    print("%-30s %-38s %s"%(name[:30],sig[:38]," ".join("%-5s"%c for c in cells)))
