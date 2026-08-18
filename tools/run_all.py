exec(open('extractors.py').read())
ROOT="/media/frost/Coding Stuf/ArcBinaryDumps/Steam"
EXTRA=[("18.08 live","/media/frost/Coding Stuf/Linux/EasyDump/captures/PioneerGame_dumped.exe")]
PATCH={"02.04.2026":"?","05.05.2026":"?","07.07.2026":"CL-1299607","08.08.2026 ca":"CL-1325322",
 "09.04.2026":"?","09.07.2026":"CL-1315578","11.08.2026":"24653108","14.04.2026":"?",
 "16.06.2026":"?","18.08.2026":"CL-1341255","19.05.2026":"CL-1195482","21.04.2026":"?",
 "28.04.2026":"CL-1169740","30.04.2026":"CL-1177146"}
builds=[]
for d in sorted(os.listdir(ROOT)):
    fs=glob.glob(os.path.join(ROOT,d,"*.exe"))+glob.glob(os.path.join(ROOT,d,"*.bin"))
    # Largest image wins. Folders hold derived artifacts too (ks_applied,
    # partial captures); picking alphabetically grabs those instead of the
    # build, and they parse fine while answering for a different binary.
    fs=[x for x in fs if os.path.getsize(x)>100*1024*1024 and "ks_applied" not in x]
    if fs: builds.append((d,max(fs,key=os.path.getsize)))
builds+= [(k,v) for k,v in EXTRA if os.path.exists(v)]
rows={}
order=[]
for d,f in builds:
    I=Img(f)
    R={"__file":os.path.basename(f),"__patch":PATCH.get(d,"?")}
    if I.ok:
        R["image size"]="0x%X"%I.size
        R[".text"]="0x%X..0x%X"%I.text
        for fn in EXTRACTORS:
            try: fn(I,R)
            except Exception as e: R.setdefault("__err","")
    else:
        R["__err"]="PE parse failed"
    rows[d]=R; order.append(d)
    del I
    print("done",d,flush=True)
json.dump({"order":order,"rows":rows},open("allbuilds.json","w"),indent=1)
