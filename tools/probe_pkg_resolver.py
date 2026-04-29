"""Probe Package resolver for /Script/Class.X bucket bug.

Reads ~20 sample classes flagged as /Script/Class.X in SDK_Output, walks
all 4 obj+0x20+i*0x20 slots, decodes pointer-shape candidates, classifies
each as: metaclass-Class / UPackage / UStruct / Other.

Goal: pick the slot heuristic that prefers UPackage (vtable=0x14AD8AE70)
over the metaclass UClass at 0x2a40e800.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from memreader import MemReader, find_pid  # noqa: E402
from fname_pipeline import (  # noqa: E402
    MODULE_BASE, MASK32, slot_decrypt, slot_picker, LiveResolver,
)

UPACKAGE_VTABLE = 0x14AD8AE70
META_CLASS_ADDR = 0x2A40E800  # named "Class" — the UClass metaclass
GUOBJECT_RVA   = 0xDE173A0


# --- Sample classes flagged with /Script/Class.X bucket
# (extracted from SDK_Output.txt earlier)
SAMPLES = [
    (0x2afea600, "ABBHighCompressedLocalTransformMixinLibrary"),
    (0x74e41900, 'AnimationDataSourceRegistry'),
    (0xcc1609a0, 'BP_Item_Recipe_Recipe_StableStock_02_C'),
    (0x7513cd00, 'BTDecorator_ConeCheck'),
    (0x8b815390, 'BreachableDoorActor'),
    (0x8ba3c990, 'CommonRadialWheelWidget'),
    (0x8c4b52c0, 'Default__SalvageExtractionPoint_Minor'),
    (0x2b001300, 'EmbarkDestructionRuntimeRegisterSubsystem'),
    (0x8b9d5730, 'ExpeditionController'),
    (0x74ee2500, 'GameViewportSubsystem'),
    (0x8b86f000, 'HurtBoxComponent'),
    (0x8ba7f640, 'ItemEffectUpgradeInfoWidget'),
    (0x8bb074b0, 'MLModuleWidgetBase'),
    (0x38264300, 'MeshDescriptionCommitter'),
    (0x8bb00970, 'NavigationQueryFilter_Test'),
    (0xdeafd0c0, 'PaddedOverlay_1'),
    (0x8b8a4a40, 'PioneerNpxIsUINavOpenCondition'),
    (0x798cf100, 'PushRoundCompleted4'),
    (0x8ba17e70, 'RoundedBoxTextured'),
    (0xdee7af00, 'SizeBox_30'),
    (0x798d2b00, 'StartSpawnSequenceProxy'),
    (0x17e3a3340, 'StaticMeshActor_167'),
    (0x18aab5aa0, 'StaticMeshActor_343'),
    (0xc2622b60, 'StaticMeshActor_519'),
    (0x17e4b5e90, 'StaticMeshActor_695'),
    (0xdee6ccd0, 'StaticMeshActor_871'),
    (0x17e3b0400, 'StaticMeshActor_1047'),
    (0x199245740, 'TextSizeBox_5'),
    (0x175298040, 'VOIPStatus_1'),
    (0x174741200, 'WidgetTree_17'),
    (0x8b68b060, 'WorldItemEffectCue_Actor_ReusableReplicated2'),
]


def slot_pointer_candidates(mr, obj):
    """Return list of (slot_idx, ptr, raw_dec) for pointer-shape decryptions."""
    out = []
    for slot in range(4):
        addr = obj + 0x20 + slot * 0x20
        try:
            enc = mr.read(addr, 16)
        except OSError:
            continue
        dec = slot_decrypt(enc)
        if dec == 0:
            continue
        lo = dec & MASK32
        hi = (dec >> 32) & MASK32
        if hi < 0x10000:
            # FName-shaped (Number=0 in hi)
            out.append((slot, None, dec, ("fname", lo, hi)))
            continue
        # Pointer encoding: result.hi32 = ptr.lo32, result.lo32 = ptr.hi32
        ptr = (lo << 32) | hi
        if ptr < 0x100000 or ptr >= 0x800000000000:
            out.append((slot, None, dec, ("invalid_ptr", lo, hi)))
            continue
        out.append((slot, ptr, dec, ("ptr",)))
    return out


def classify_ptr(mr, ptr):
    """Look at *ptr's vtable and return ('upackage'|'meta_class'|'uobject'|'unknown', vtable)."""
    if not ptr:
        return ("none", 0)
    try:
        vt = int.from_bytes(mr.read(ptr, 8), "little")
    except OSError:
        return ("read_fail", 0)
    if vt == UPACKAGE_VTABLE:
        return ("upackage", vt)
    if ptr == META_CLASS_ADDR:
        return ("meta_class", vt)
    return ("other", vt)


def resolve_name_for_obj(mr, rv, obj):
    """Try to decode a printable name string by trying both halves of each slot."""
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
                    if n and 1 <= len(n) <= 256:
                        printable = sum(1 for c in n if 32 <= ord(c) < 127)
                        if printable >= 0.8 * len(n):
                            return n
    return ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, default=0)
    args = ap.parse_args()

    pid = args.pid or find_pid()
    if not pid:
        print("could not find game PID", file=sys.stderr)
        return 1
    print(f"[+] PID = {pid}")

    with MemReader(pid) as mr:
        rv = LiveResolver(mr)
        print(f"[+] meta-class 'Class' addr = 0x{META_CLASS_ADDR:X}")
        print(f"[+] UPackage vtable = 0x{UPACKAGE_VTABLE:X}")
        # sanity: meta-class object's vtable
        try:
            v = int.from_bytes(mr.read(META_CLASS_ADDR, 8), "little")
            print(f"[+] *(0x{META_CLASS_ADDR:X}) = 0x{v:X}  (meta-class vtable)")
        except OSError as e:
            print(f"[!] could not read meta-class addr: {e}")
            return 1

        # Per-sample stats
        slot_pkg_count = [0]*4
        hash_pkg_count = 0
        first_pkg_after_meta_count = 0
        no_pkg_count = 0

        for obj, expected_name in SAMPLES:
            v7, hash_idx = slot_picker(obj)
            cands = slot_pointer_candidates(mr, obj)
            print(f"\n--- {expected_name}  obj=0x{obj:X}  hash_slot={hash_idx} ---")
            try:
                vt = int.from_bytes(mr.read(obj, 8), "little")
                print(f"    *(obj) vtable = 0x{vt:X}")
            except OSError:
                pass

            ptr_slots = []  # (slot, ptr, kind, name)
            for slot, ptr, dec, kind_info in cands:
                kind = kind_info[0]
                if kind == "ptr":
                    cls, vt = classify_ptr(mr, ptr)
                    nm = ""
                    if cls in ("upackage", "other", "meta_class"):
                        # Try to decode name of this object
                        try:
                            nm = resolve_name_for_obj(mr, rv, ptr)
                        except Exception:
                            nm = "<err>"
                    print(f"    slot {slot}: ptr=0x{ptr:X}  vtable=0x{vt:X}  kind={cls}  name={nm!r}")
                    ptr_slots.append((slot, ptr, cls, nm, vt))
                else:
                    print(f"    slot {slot}: dec=0x{dec:X}  kind={kind}  raw={kind_info}")

            # Find which slot is the UPackage
            pkg_slot = None
            for slot, ptr, cls, nm, vt in ptr_slots:
                if cls == "upackage":
                    pkg_slot = (slot, ptr, nm)
                    break
            if pkg_slot:
                slot_pkg_count[pkg_slot[0]] += 1
                print(f"    >> UPackage at slot {pkg_slot[0]} = 0x{pkg_slot[1]:X}  pkg={pkg_slot[2]!r}")
                if hash_idx == pkg_slot[0]:
                    hash_pkg_count += 1
                else:
                    # Walk the outer chain emulating GetOuterPtr fallback.
                    # current GetOuterPtr returns the FIRST non-class ptr.
                    # If hash_idx points to meta-class — bad.
                    pass
            else:
                no_pkg_count += 1
                print("    >> no UPackage among slots")

        print("\n=== SUMMARY ===")
        print(f"  samples with no UPackage slot found: {no_pkg_count}/{len(SAMPLES)}")
        print(f"  samples where hash_idx == upackage_slot: {hash_pkg_count}/{len(SAMPLES)}")
        print(f"  UPackage slot distribution: slot0={slot_pkg_count[0]} "
              f"slot1={slot_pkg_count[1]} slot2={slot_pkg_count[2]} slot3={slot_pkg_count[3]}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
