import re,struct,os,glob,sys,collections,json
import capstone
BASE=0x140000000

def sections(D):
    if D[:2]!=b'MZ': return None
    pe=struct.unpack_from("<I",D,0x3C)[0]
    if D[pe:pe+4]!=b'PE\0\0': return None
    nsec=struct.unpack_from("<H",D,pe+6)[0]
    optsz=struct.unpack_from("<H",D,pe+20)[0]
    sizeofimage=struct.unpack_from("<I",D,pe+24+56)[0]
    st=pe+24+optsz; sec={}
    for i in range(nsec):
        o=st+i*40
        nm=D[o:o+8].rstrip(b'\0').decode('ascii','replace')
        vs,va,rs,pr=struct.unpack_from("<IIII",D,o+8)
        sec.setdefault(nm,(va,vs,pr,rs))
    flat = len(D) >= sizeofimage*0.9
    return sec,flat,sizeofimage

class Img:
    def __init__(self,path):
        self.D=open(path,'rb').read()
        s=sections(self.D)
        self.ok = s is not None
        if not self.ok: return
        sec,flat,si=s
        self.flat=flat; self.size=si
        def rng(n):
            if n not in sec: return None
            va,vs,pr,rs=sec[n]
            return (va,va+vs) if flat else (pr,pr+rs)
        self.text=rng(".text"); self.rdata=rng(".rdata"); self.data=rng(".data")
        self.ok = self.text is not None
    def at(self,rva,n=16):
        return self.D[rva:rva+n]
    def u32(self,rva): return struct.unpack_from("<I",self.D,rva)[0]
    def u64(self,rva): return struct.unpack_from("<Q",self.D,rva)[0]
    def inseg(self,rva,seg): return seg and seg[0]<=rva<seg[1]

def scan(I,pat,seg=None):
    lo,hi = seg or I.text
    rx=b""
    for t in pat.split():
        if t.startswith("?"): rx+=b"."
        else: rx+=re.escape(bytes([int(t,16)])) if len(t)==2 and t[1]!="?" else b"."
    return [m.start()+lo for m in re.finditer(rx,I.D[lo:hi],re.S)]

def func_start(I,rva,limit=0x2000):
    lo=max(I.text[0], rva-limit)
    a=rva-1
    while a>lo:
        if I.D[a]==0xCC:
            s=a+1
            while s<rva and I.D[s]==0xCC: s+=1
            return s
        a-=1
    return None

MD=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
MD.detail=True
def dis(I,rva,n=0x200):
    return list(MD.disasm(I.D[rva:rva+n], BASE+rva))

def strstart(I,needle):
    i=I.D.find(needle)
    if i<0: return None
    s=i
    while s>0 and 32<=I.D[s-1]<127: s-=1
    return s

def riprefs(I,target):
    lo,hi=I.text; out=[]
    seg=I.D[lo:hi]
    for m in re.finditer(rb"[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]",seg):
        i=m.start()
        if i+7>len(seg): continue
        if lo+i+7+struct.unpack_from("<i",seg,i+3)[0]==target: out.append(lo+i)
    return out
