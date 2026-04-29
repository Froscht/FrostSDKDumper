"""Walk outer chains for problem objects, classifying each link."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from memreader import MemReader, find_pid
from fname_pipeline import MASK32, slot_decrypt, slot_picker, LiveResolver

UPACKAGE_VTABLE = 0x14AD8AE70
META_CLASS_ADDR = 0x2A40E800
MODULE_LO = 0x140000000
MODULE_HI = 0x150000000

def slots_with_pointers(mr, obj):
    """Return dict slot_idx → (ptr, vtable, name_resolver_input)."""
    out = {}
    for slot in range(4):
        addr = obj + 0x20 + slot * 0x20
        try:
            enc = mr.read(addr, 16)
        except OSError:
            continue
        dec = slot_decrypt(enc)
        if dec == 0:
            continue
        lo, hi = dec & MASK32, (dec >> 32) & MASK32
        if hi < 0x10000:
            continue
        ptr = (lo << 32) | hi
        if ptr < 0x100000 or ptr >= 0x800000000000:
            continue
        try:
            vt = int.from_bytes(mr.read(ptr, 8), "little")
        except OSError:
            continue
        out[slot] = (ptr, vt)
    return out

def name_of(rv, mr, obj):
    for slot in range(4):
        addr = obj + 0x20 + slot * 0x20
        try:
            enc = mr.read(addr, 16)
        except OSError:
            continue
        dec = slot_decrypt(enc)
        for v in (dec & MASK32, (dec >> 32) & MASK32):
            if 0 < v < 0x2000000:
                p = rv.resolve_name_ptr(v)
                if p:
                    n = rv.decrypt_name_string(p)
                    if n:
                        return n
    return ""

def walk(mr, rv, obj, max_depth=12):
    print(f"\n  start obj=0x{obj:X} name={name_of(rv,mr,obj)!r}")
    for d in range(max_depth):
        slots = slots_with_pointers(mr, obj)
        # pick best slot: upackage > non-meta module-vtable > anything
        best = None
        # Prefer upackage:
        for s, (p, vt) in slots.items():
            if vt == UPACKAGE_VTABLE:
                best = s; break
        if best is None:
            for s, (p, vt) in slots.items():
                if p == META_CLASS_ADDR:
                    continue
                # also reject targets whose vtable equals our own vtable's "Class"
                if MODULE_LO <= vt < MODULE_HI:
                    best = s; break
        if best is None:
            print(f"  d={d} dead-end on 0x{obj:X}; slots={ {s:hex(p) for s,(p,_) in slots.items()} }")
            return
        ptr, vt = slots[best]
        n = name_of(rv, mr, ptr)
        kind = "UPackage" if vt == UPACKAGE_VTABLE else "Other"
        print(f"  d={d} slot{best} → 0x{ptr:X}  vt=0x{vt:X}  kind={kind}  name={n!r}")
        if vt == UPACKAGE_VTABLE:
            return
        obj = ptr

PROBLEM = [
    (0x17e3a3340, "StaticMeshActor_167"),
    (0xdeafd0c0, "PaddedOverlay_1"),
    (0xdee7af00, "SizeBox_30"),
    (0x175298040, "VOIPStatus_1"),
    (0x174741200, "WidgetTree_17"),
]

def main():
    pid = find_pid()
    print(f"PID = {pid}")
    with MemReader(pid) as mr:
        rv = LiveResolver(mr)
        for obj, name in PROBLEM:
            print(f"\n=== {name} ===")
            walk(mr, rv, obj)

if __name__ == "__main__":
    sys.exit(main() or 0)
