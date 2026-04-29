"""For each known-UFunction object, verify that qword @ +0xB0 fits the pattern:
   low 8 bits = NumParms (small u8), high 56 bits = 0.
"""
import os, sys, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from memreader import MemReader, find_pid

DUMP_PATH = "/media/frost/Coding Stuf/Linux/FrostSDKDumper/dump_objects.txt"
KNOWN_UFUNC_VTABLES = {0x14AD6D980, 0x14AD6CB80}

def parse_dump():
    objs=[]
    with open(DUMP_PATH) as f:
        for line in f:
            line=line.strip()
            if not line.startswith("["): continue
            try:
                rb=line.index("]"); idx=int(line[1:rb])
                rest=line[rb+1:].strip(); pipe=rest.index("|")
                addr=int(rest[:pipe].strip(),16); name=rest[pipe+1:].strip()
                objs.append((idx,addr,name))
            except: pass
    return objs

def main():
    pid=find_pid()
    objs=parse_dump()

    real_b0_pat = []   # qword @ +0xB0 for known-UFunc-vtable
    fake_b0_pat = []   # for non-known
    real_count = 0
    real_high_zero = 0
    real_high_nonzero_examples = []
    with MemReader(pid) as mr:
        for idx,addr,name in objs:
            try: buf=mr.read(addr,0x180)
            except OSError: continue
            vt=struct.unpack_from('<Q',buf,0)[0]
            if vt in KNOWN_UFUNC_VTABLES:
                q=struct.unpack_from('<Q',buf,0xB0)[0]
                real_count += 1
                low = q & 0xFF
                high = q >> 8
                if high == 0:
                    real_high_zero += 1
                else:
                    if len(real_high_nonzero_examples) < 10:
                        real_high_nonzero_examples.append((idx,addr,name,q))

    print(f"Known UFunc vtable objects: {real_count}")
    print(f"  qword@+0xB0 has high 56 bits = 0:  {real_high_zero} ({100*real_high_zero/real_count:.2f}%)")
    print(f"  qword@+0xB0 has high 56 bits != 0: {real_count - real_high_zero}")
    print("Examples of non-zero high 56 bits:")
    for ex in real_high_nonzero_examples:
        print(f"  [{ex[0]:6d}] {ex[1]:#x} | {ex[2][:30]:<30} q@+B0={ex[3]:#x}")

if __name__=='__main__': main()
