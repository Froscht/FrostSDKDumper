exec(open('extract_all.py').read())
import glob,os,re,json
SIGS=[
 ("APlayerState::DecryptPlayerName","41 57 41 56 41 54 56 57 55 53 48 83 EC ?? 48 89 D6 80 B9"),
 ("Dec_BoneArray (lang)","49 8D 6D 60 BB 01 00 00 00 45 31 F6 66 45 0F 57 D2 F2 44 0F 10 0D"),
 ("Dec_BoneArray (kurz)","49 8D 6D ?? BB"),
 ("UWorld","48 8B 05 ?? ?? ?? ?? 4C 8D 3D ?? ?? ?? ?? 89 F1 EB ?? 44 01 CB FF C3 BD ?? ?? ?? ?? 66 0F 1F 84 00"),
 ("Dec_GWorld","E8 ?? ?? ?? ?? F6 ?? ?? ?? 01 0F 85 ?? ?? 00 00 8B 05"),
 ("Dec_FIndex","48 C7 07 00 00 00 00 48 83"),
 ("Dec_GName_Index2Name","48 8D 4C 24 28 48 8D 94 24 30 08 00 00 E8 ?? ?? ?? ?? 89 C6 48 8D 4C 24 20 48 8D 54 24 30 E8"),
 ("Dec_PlayerNamePrivate","48 89 ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 54 ?? ?? 48 89 F1 E8 ?? ?? ?? ?? 83 7C"),
]
def cnt(I,pat):
    lo,hi=I.text
    rx=b""
    for t in pat.split():
        rx += b"." if t.startswith("?") else re.escape(bytes([int(t,16)]))
    return [m.start()+lo for m in re.finditer(rx,I.D[lo:hi],re.S)]
ROOT="/media/frost/Coding Stuf/ArcBinaryDumps/Steam"
J=json.load(open("allbuilds.json"))
def key(d):
    m=re.match(r"(\d\d)\.(\d\d)\.(\d{4})",d)
    return (m.group(3),m.group(2),m.group(1),d) if m else ("9999","","",d)
order=[d for d in sorted(J["order"],key=key)]
paths={}
for d in os.listdir(ROOT):
    fs=[x for x in glob.glob(os.path.join(ROOT,d,"*.exe"))+glob.glob(os.path.join(ROOT,d,"*.bin"))
        if os.path.getsize(x)>100*1024*1024 and "ks_applied" not in x]
    if fs: paths[d]=max(fs,key=os.path.getsize)
paths["18.08 live"]="/media/frost/Coding Stuf/Linux/EasyDump/captures/PioneerGame_dumped.exe"
res={}
for d in order:
    if d not in paths: continue
    I=Img(paths[d]); res[d]={}
    for lab,p in SIGS: res[d][lab]=len(cnt(I,p))
    del I
    print("done",d,flush=True)
json.dump({"order":[d for d in order if d in res],"res":res,"sigs":[s[0] for s in SIGS],
           "patt":{a:b for a,b in SIGS},"patch":{d:J["rows"][d].get("__patch","?") for d in order}},
          open("foreign_sigs.json","w"),indent=1)
