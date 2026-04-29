"""Probe slot layout for KNOWN-GOOD classes (correct package)."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from memreader import MemReader, find_pid
from fname_pipeline import MODULE_BASE, MASK32, slot_decrypt, slot_picker, LiveResolver

UPACKAGE_VTABLE = 0x14AD8AE70
META_CLASS_ADDR = 0x2A40E800

GOOD = [
    (0x75132e00, "AIAsyncTaskBlueprintProxy", "AIModule"),
    (0x75150400, "AIBlueprintHelperLibrary", "AIModule"),
    (0x7513ac00, "AIController", "AIModule"),
    (0x7515c100, "AIDataProvider_Random", "AIModule"),
    (0x750e5b00, "AIPerceptionComponent", "AIModule"),
    (0x175981750, "ABO_SmartObject_Guard_Monolith_C", "ABO_SmartObject_Guard_Monolith"),
    (0xd1f9a4c0, "ABO_SmartObject_MoveAround_TrackObject_Fast_Alert_C", "ABO_..."),
]

def main():
    pid = find_pid()
    print(f"PID = {pid}")
    with MemReader(pid) as mr:
        rv = LiveResolver(mr)
        for obj, name, pkg in GOOD:
            v7, hash_idx = slot_picker(obj)
            print(f"\n--- {name}  obj=0x{obj:X}  hash_slot={hash_idx}  expected_pkg={pkg} ---")
            try:
                vt = int.from_bytes(mr.read(obj, 8), "little")
                print(f"    *(obj) vtable = 0x{vt:X}")
            except OSError:
                continue
            for slot in range(4):
                addr = obj + 0x20 + slot * 0x20
                try:
                    enc = mr.read(addr, 16)
                except OSError:
                    print(f"    slot {slot}: READ_FAIL")
                    continue
                dec = slot_decrypt(enc)
                lo, hi = dec & MASK32, (dec >> 32) & MASK32
                if hi < 0x10000:
                    # FName-shaped
                    nm = ""
                    if 0 < lo < 0x2000000:
                        p = rv.resolve_name_ptr(lo)
                        if p:
                            nm = rv.decrypt_name_string(p) or ""
                    print(f"    slot {slot}: dec=0x{dec:X}  fname ci={lo} hi={hi} name={nm!r}")
                    continue
                ptr = (lo << 32) | hi
                if ptr < 0x100000 or ptr >= 0x800000000000:
                    print(f"    slot {slot}: dec=0x{dec:X}  invalid_ptr lo=0x{lo:X} hi=0x{hi:X}")
                    continue
                try:
                    pvt = int.from_bytes(mr.read(ptr, 8), "little")
                except OSError:
                    pvt = 0
                kind = "upackage" if pvt == UPACKAGE_VTABLE else ("meta_class" if ptr == META_CLASS_ADDR else "other")
                # try resolve name via inner slots
                pname = ""
                for s2 in range(4):
                    a2 = ptr + 0x20 + s2 * 0x20
                    try:
                        e2 = mr.read(a2, 16)
                    except OSError:
                        continue
                    d2 = slot_decrypt(e2)
                    for v in (d2 & MASK32, (d2 >> 32) & MASK32):
                        if 0 < v < 0x2000000:
                            pp = rv.resolve_name_ptr(v)
                            if pp:
                                nn = rv.decrypt_name_string(pp) or ""
                                if nn:
                                    pname = nn
                                    break
                    if pname:
                        break
                print(f"    slot {slot}: ptr=0x{ptr:X}  vt=0x{pvt:X}  kind={kind}  name={pname!r}")

if __name__ == "__main__":
    sys.exit(main() or 0)
