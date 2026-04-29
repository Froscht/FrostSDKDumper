"""Find UFunctions with vt=0x14AD6D980 but NativeFunc != ProcessInternal."""

import os, sys, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from memreader import MemReader, find_pid

DUMP_PATH = "/media/frost/Coding Stuf/Linux/FrostSDKDumper/dump_objects.txt"
KNOWN_UFUNC_VTABLES = {0x14AD6D980, 0x14AD6CB80}
PROC_INT = 0x14049AE10

def parse_dump():
    objs = []
    with open(DUMP_PATH) as f:
        for line in f:
            line = line.strip()
            if not line.startswith("["):
                continue
            try:
                rb = line.index("]")
                idx = int(line[1:rb])
                rest = line[rb+1:].strip()
                pipe = rest.index("|")
                addr = int(rest[:pipe].strip(), 16)
                name = rest[pipe+1:].strip()
                objs.append((idx, addr, name))
            except Exception: pass
    return objs

def main():
    pid = find_pid()
    print(f"PID={pid}")
    objs = parse_dump()

    # Cross-classify: (vt_known?, ff_passes?, nf_in_text?, nf_is_proc_int?)
    # Goal: understand exactly which combinations lead to FPs.

    cells = {}
    sample_per_cell = {}
    with MemReader(pid) as mr:
        for idx, addr, name in objs:
            try:
                buf = mr.read(addr, 0x180)
            except OSError:
                continue
            vt = struct.unpack_from('<Q', buf, 0)[0]
            ff = struct.unpack_from('<I', buf, 0x120)[0]
            nf = struct.unpack_from('<Q', buf, 0x148)[0]

            vt_ok = vt in KNOWN_UFUNC_VTABLES
            ff_ok = (0 < ff <= 0x10000000)
            if nf == PROC_INT:
                nf_cls = 'PI'
            elif 0x140000000 <= nf < 0x150000000:
                nf_cls = 'TXT'
            elif nf == 0:
                nf_cls = 'ZRO'
            else:
                nf_cls = 'JNK'

            key = (vt_ok, ff_ok, nf_cls)
            cells[key] = cells.get(key,0)+1
            if key not in sample_per_cell:
                sample_per_cell[key] = []
            if len(sample_per_cell[key]) < 4 and name and not name.startswith('/'):
                sample_per_cell[key].append((idx,addr,name,vt,ff,nf))

    # Print cross-tab
    print(f"\n{'vt_known':<10}{'ff_pass':<10}{'nf_class':<10}{'count':<10}examples")
    for key in sorted(cells.keys(), key=lambda k: -cells[k]):
        vt_ok, ff_ok, nf_cls = key
        cnt = cells[key]
        ex = sample_per_cell.get(key, [])
        ex_s = "; ".join(f"{n[:30]}@{a:#x}" for _,a,n,_,_,_ in ex[:2])
        print(f"  {str(vt_ok):<8}{str(ff_ok):<10}{nf_cls:<10}{cnt:<10}{ex_s}")

if __name__ == '__main__':
    main()
