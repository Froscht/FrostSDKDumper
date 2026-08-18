exec(open('extract_all.py').read())

def ex_setup_offset(I,R):
    hits=[]
    for h in scan(I,"0F B7 ?? ?? 35 ?? ?? ?? ?? 0F C8"):
        xor=I.u32(h+5)
        i=h+11
        if (I.D[i]&0xF0)==0x40: i+=1
        if I.D[i]!=0x89: continue
        m=I.D[i+1]; mod=(m>>6)&3; rm=m&7
        j=i+2+(1 if rm==4 else 0)
        d = I.D[j] if mod==1 else (I.u32(j) if mod==2 else (0 if mod==0 else None))
        if d is None or not (0x40<=d<=0x400): continue
        hits.append((h,xor,d))
    if len(hits)!=1: return
    h,xor,d=hits[0]
    R["FProperty::SetupOffset (fn)"]="0x%X"%(func_start(I,h) or h)
    R["FProperty::Offset_Internal"]="+0x%X"%d
    R["FProperty::Offset_XOR"]="0x%08X"%xor

def ex_fname(I,R):
    cands=[]
    for form,n in (("81 ?? 00 FF FF 00",6),("25 00 FF FF 00",5)):
        for h in scan(I,form):
            w=I.D[h+n:h+n+48]
            for k in range(len(w)-7):
                if w[k] in (0x48,0x4C) and w[k+1]==0x8D and (w[k+2]&0xC7)==0x05:
                    t=h+n+k+7+struct.unpack_from("<i",w,k+3)[0]
                    if I.inseg(t,I.data) and bytes.fromhex("93010001") in I.D[h:h+0x140]:
                        cands.append((h,t)); break
    uniq={t:h for h,t in cands}
    if len(uniq)!=1: return
    t,h=list(uniq.items())[0]
    R["FName resolver (fn)"]="0x%X"%(func_start(I,h) or h)
    R["GNamePool"]="0x%X"%t
    ins=dis(I,h,0x400)
    # seed offset: first add r,imm32 in [0x100,0x40000] after the pool lea
    seen_lea=False
    for x in ins:
        if x.mnemonic=="lea" and "rip" in x.op_str: seen_lea=True; continue
        if seen_lea and x.mnemonic=="add" and len(x.operands)==2 and x.operands[1].type==capstone.x86.X86_OP_IMM:
            v=x.operands[1].imm
            if 0x100<=v<0x40000: R["FName shard seed off"]="+0x%X"%v; break
    # block base: movdqa xmm,[base+idx+disp] with disp>=0x100
    for x in ins:
        if x.mnemonic in ("movdqa","movdqu") and x.operands and x.operands[1].type==capstone.x86.X86_OP_MEM:
            m=x.operands[1].mem
            if m.base and m.index and m.disp>=0x100:
                R["FName block base off"]="+0x%X"%m.disp; break
    # FNV-64 add + rotates
    rols=[]
    add64=None
    for i,x in enumerate(ins):
        if x.mnemonic=="movabs" and x.operands[1].imm==0x100000001B3:
            for y in ins[i:i+30]:
                if y.mnemonic=="rol" and y.operands[1].type==capstone.x86.X86_OP_IMM:
                    rols.append(y.operands[1].imm)
                if y.mnemonic=="movabs" and y.operands[1].imm not in (0x100000001B3,) and add64 is None:
                    add64=y.operands[1].imm & 0xFFFFFFFFFFFFFFFF
            break
    if add64 is not None: R["FName FNV64 add"]="0x%016X"%add64
    if len(rols)>=2: R["FName FNV64 rol1/rol2"]="%d/%d"%(rols[0],rols[1])
    # KEY_INIT_ADD: lea r32,[r + imm] with imm in [0x1000,0xFFFF]
    for x in ins:
        if x.mnemonic=="lea" and x.operands[1].type==capstone.x86.X86_OP_MEM:
            m=x.operands[1].mem
            if m.base and not m.index and 0x1000<=m.disp<=0xFFFF:
                R["FName KEY_INIT_ADD"]="0x%X"%m.disp; break
    # header length mask
    for x in ins:
        if x.mnemonic=="and" and x.operands[1].type==capstone.x86.X86_OP_IMM:
            v=x.operands[1].imm
            if v in (0x3F,0x3FF,0x7FF,0xFFF,0x1FF): R["FNameEntry len mask"]="0x%X"%v; break

def ex_getfname(I,R):
    s=strstart(I,b"FName GetName() const")
    if s is None: return
    R['anchor "FName GetName() const"']="0x%X"%s
    refs=riprefs(I,s)
    if not refs: return
    # For each reference, collect EVERY rip-lea into .text in the preceding
    # window and keep the ones that land on (or one instruction into) a
    # function start. The registration site loads the native function pointer
    # next to the signature string; taking only the nearest lea misses it
    # whenever the compiler interleaves other arguments.
    cands=[]
    for r in refs:
        for back in range(7,140):
            a=r-back
            if a<I.text[0]: break
            if I.D[a] in (0x48,0x4C) and I.D[a+1]==0x8D and (I.D[a+2]&0xC7)==0x05:
                t=a+7+struct.unpack_from("<i",I.D,a+3)[0]
                if not I.inseg(t,I.text): continue
                fs=func_start(I,t)
                if fs is not None and 0<=t-fs<=0x20: cands.append(t)
    if not cands: return
    # Pick by CONTENT, not by position: the real accessor carries the FNV-32
    # prime and an `and r32, 3` slot select within its first bytes. Both are
    # engine-required and present on every build; taking whichever candidate
    # came last picks a neighbouring registration thunk instead.
    def looks_like_accessor(t):
        w=I.D[t:t+0x300]
        if bytes.fromhex("93010001") not in w: return False
        for k in range(len(w)-3):
            if w[k]==0x83 and (w[k+1]&0xC0)==0xC0 and ((w[k+1]>>3)&7)==4 and w[k+2]==3:
                return True
        return False
    good=[t for t in cands if looks_like_accessor(t)]
    if not good: return
    fn=func_start(I,good[0]) or good[0]
    R["UObject::GetFName"]="0x%X"%fn
    ins=dis(I,fn,0x200)
    for x in ins:
        if x.mnemonic=="lea" and len(x.operands)>1 and x.operands[1].type==capstone.x86.X86_OP_MEM:
            m=x.operands[1].mem
            if m.base and not m.index and 0<m.disp<=0x40:
                R["GetFName seed off"]="+0x%X"%m.disp; break
    for x in ins:
        if x.mnemonic=="add" and len(x.operands)>1 and x.operands[1].type==capstone.x86.X86_OP_IMM:
            v=x.operands[1].imm & 0xFFFFFFFF
            if v>0xFFFF: R["GetFName hash add"]="0x%08X"%v; break
    for i,x in enumerate(ins):
        if x.mnemonic=="and" and len(x.operands)>1 and x.operands[1].type==capstone.x86.X86_OP_IMM and x.operands[1].imm==3:
            for y in ins[i:i+5]:
                if y.mnemonic=="xor" and len(y.operands)>1 and y.operands[1].type==capstone.x86.X86_OP_IMM:
                    R["GetFName slot xor"]="%d"%y.operands[1].imm
                if y.mnemonic=="shl" and len(y.operands)>1 and y.operands[1].type==capstone.x86.X86_OP_IMM:
                    R["GetFName slot stride"]="0x%X"%(1<<y.operands[1].imm)
            break
    for x in ins:
        if x.mnemonic in ("movdqa","movdqu") and len(x.operands)>1 and x.operands[1].type==capstone.x86.X86_OP_MEM:
            m=x.operands[1].mem
            if m.base and 0<m.disp<=0x100:
                R["GetFName slot base"]="+0x%X"%m.disp; break
    ops=[x.mnemonic for x in ins if x.mnemonic in
         ("pxor","paddd","pshuflw","pshufb","pshufd","psrld","pslld","psrlq",
          "psllq","psrlw","psllw","por","pand","pandn","pclmulqdq","rol","shr","call")]
    R["GetFName slot shape"]=" ".join(ops[:10])
    ks=[x.operands[1].imm & 0xFFFFFFFFFFFFFFFF for x in ins if x.mnemonic=="movabs" and len(x.operands)>1]
    if ks: R["GetFName slot consts"]=" / ".join("0x%X"%k for k in ks[:2])
    rr=[x.operands[1].imm for x in ins if x.mnemonic=="rol" and len(x.operands)>1
        and x.operands[1].type==capstone.x86.X86_OP_IMM]
    if rr: R["GetFName final rol"]="%d"%rr[-1]

def ex_boolprop(I,R):
    s=strstart(I,b"PropertyBool.cpp")
    if s is None: return
    R['anchor PropertyBool.cpp']="0x%X"%s
    refs=riprefs(I,s)
    R["PropertyBool.cpp refs"]=str(len(refs))
    votes=collections.Counter(); shapes=collections.Counter()
    picked=None
    for r in refs:
        fn=func_start(I,r)
        if not fn: continue
        ins=dis(I,fn,min(r-fn+64,0x600))
        md=[x for x in ins if x.mnemonic in ("movdqa","movdqu")
            and x.operands and len(x.operands)>1
            and x.operands[1].type==capstone.x86.X86_OP_MEM
            and x.operands[1].mem.base and not x.operands[1].mem.index
            and 0x20<=x.operands[1].mem.disp<=0x300]
        if not md: continue
        votes[md[0].operands[1].mem.disp]+=1
        ops=[x.mnemonic for x in ins if x.mnemonic in
             ("pxor","paddd","paddw","pshuflw","pshufb","pshufd","psrld","pslld",
              "psrlq","psllq","psrlw","psllw","por","pand","pandn","rol","pclmulqdq")]
        # collapse shift pairs into their rotate meaning, keep order
        shapes[" ".join(ops[:10])]+=1
        if picked is None: picked=(fn,ins)
    if not votes: return
    off,_=votes.most_common(1)[0]
    R["FField::NamePrivate"]="+0x%X"%off
    R["FField name shape"]=shapes.most_common(1)[0][0] if shapes else ""
    fn,ins=picked
    R["FBoolProperty::GetCPPType"]="0x%X"%fn
    ks=[]
    for x in ins:
        if x.mnemonic in ("pxor","paddd") and len(x.operands)>1 and \
           x.operands[1].type==capstone.x86.X86_OP_MEM and \
           x.operands[1].mem.base==capstone.x86.X86_REG_RIP:
            t=x.address-BASE+x.size+x.operands[1].mem.disp
            if I.inseg(t,I.rdata) or I.inseg(t,I.text):
                ks.append(I.u64(t))
    for x in ins:
        if x.mnemonic in ("pslld","psllw","psllq") and len(x.operands)>1 and \
           x.operands[1].type==capstone.x86.X86_OP_IMM:
            R["FField name rot"]="%s(%d)"%({"pslld":"ROL32","psllw":"ROL16","psllq":"ROL64"}[x.mnemonic],
                                           x.operands[1].imm); break
    if len(ks)>0: R["FField name key1"]="0x%016X"%ks[0]
    if len(ks)>1: R["FField name key2"]="0x%016X"%ks[1]
    for x in ins:
        if x.mnemonic=="cmp" and len(x.operands)>1 and \
           x.operands[0].type==capstone.x86.X86_OP_MEM and \
           x.operands[1].type==capstone.x86.X86_OP_IMM and \
           x.operands[1].imm in (-1,0xFF) and 0x40<=x.operands[0].mem.disp<=0x400:
            R["sizeof(FProperty)"]="0x%X"%(x.operands[0].mem.disp-3); break

MODRM=bytes([0x04,0x0C,0x14,0x1C,0x24,0x2C,0x34,0x3C])
SIB  =bytes([0x80,0x89,0x92,0x9B,0xAD,0xB6,0xBF])
LEA20=re.compile(b"[\x48-\x4f]\x8d["+re.escape(MODRM)+b"]["+re.escape(SIB)+b"]",re.S)
def ex_chunkmgr(I,R):
    lo,hi=I.text; seg=I.D[lo:hi]
    votes=collections.Counter(); n=0
    for m in LEA20.finditer(seg):
        i=m.start(); n+=1
        s=max(0,i-0x200); w=seg[s:i+0x200]; base=lo+s
        for mm in re.finditer(rb"\x66\x0f\x6f\x05",w):
            k=mm.start()
            if k+8>len(w): continue
            t=base+k+8+struct.unpack_from("<i",w,k+4)[0]
            if I.inseg(t,I.data): votes[t]+=1
    R["stride-20 sites"]=str(n)
    if votes:
        top=votes.most_common(1)[0]
        R["chunks_manager global"]="0x%X"%top[0]
        R["chunks_manager votes"]=str(top[1])

EXTRACTORS=[ex_setup_offset,ex_fname,ex_getfname,ex_boolprop,ex_chunkmgr]
