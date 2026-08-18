import json,csv,os
J=json.load(open("allbuilds.json"))
order=J["order"]; rows=J["rows"]
# chronological
import re
def key(d):
    m=re.match(r"(\d\d)\.(\d\d)\.(\d{4})",d)
    return (m.group(3),m.group(2),m.group(1),d) if m else ("9999","","",d)
order=sorted(order,key=key)

FIELDS=[
 ("image size","meta"),(".text","meta"),
 ("FName resolver (fn)","fn"),("UObject::GetFName","fn"),
 ("FBoolProperty::GetCPPType","fn"),("FProperty::SetupOffset (fn)","fn"),
 ("GNamePool","global"),("chunks_manager global","global"),
 ("FField name key1","global"),("FField name key2","global"),
 ("FProperty::Offset_Internal","offset"),("FProperty::Offset_XOR","const"),
 ("FField::NamePrivate","offset"),("sizeof(FProperty)","offset"),
 ("FField name rot","const"),
 ("FField name shape","shape"),
 ("GetFName seed off","offset"),("GetFName slot base","offset"),
 ("GetFName slot stride","offset"),("GetFName slot xor","const"),
 ("GetFName hash add","const"),("GetFName final rol","const"),
 ("GetFName slot consts","const"),
 ("GetFName slot shape","shape"),
 ("FName shard seed off","offset"),("FName block base off","offset"),
 ("FName FNV64 add","const"),("FName FNV64 rol1/rol2","const"),
 ("FName KEY_INIT_ADD","const"),("FNameEntry len mask","const"),
 ("stride-20 sites","stat"),("chunks_manager votes","stat"),
 ('anchor "FName GetName() const"',"anchor"),("anchor PropertyBool.cpp","anchor"),
 ("PropertyBool.cpp refs","stat"),
]
# CSV
with open("arc_offsets_all_builds.csv","w",newline="") as f:
    w=csv.writer(f)
    w.writerow(["item","kind"]+[ "%s (%s)"%(d,rows[d].get("__patch","?")) for d in order]+["valid","builds ok"])
    for name,kind in FIELDS:
        vals=[rows[d].get(name,"") for d in order]
        ok=sum(1 for v in vals if v)
        w.writerow([name,kind]+vals+["JA" if ok==len(order) else ("TEILWEISE" if ok else "NEIN"), "%d/%d"%(ok,len(order))])
# Markdown
def md():
    out=[]
    out.append("# ARC Raiders — Offsets und Funktionen über alle Builds\n")
    out.append("Statisch aus jedem Image extrahiert (kein Live-Zugriff). Leere Zelle = auf diesem Build nicht aufloesbar.\n")
    hdr=["Item","Art"]+[d.split()[0] for d in order]+["Gueltig","n"]
    out.append("| "+" | ".join(hdr)+" |")
    out.append("|"+"|".join(["---"]*len(hdr))+"|")
    for name,kind in FIELDS:
        vals=[rows[d].get(name,"") or "—" for d in order]
        ok=sum(1 for d in order if rows[d].get(name))
        v="JA" if ok==len(order) else ("TEILWEISE" if ok else "NEIN")
        out.append("| "+" | ".join([name,kind]+vals+[v,"%d/%d"%(ok,len(order))])+" |")
    out.append("\n## Builds\n")
    out.append("| Ordner | Patch | Datei |")
    out.append("|---|---|---|")
    for d in order:
        out.append("| %s | %s | %s |"%(d,rows[d].get("__patch","?"),rows[d].get("__file","")))
    return "\n".join(out)+"\n"
open("arc_offsets_all_builds.md","w").write(md())
print(md()[:200])
