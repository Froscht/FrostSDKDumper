"""Probe FStructProperty.Struct offset using known UClass addresses from dump_objects.txt.

For each candidate UClass, walk its ChildProperties chain (FField list).
Each FField might be an FStructProperty — identify them by the heuristic
that +0x108 (or some nearby offset) holds a heap pointer to a UObject
whose name decodes to a UScriptStruct-like name (or whose ClassPrivate
matches a known UScriptStruct metaclass).

We don't try to identify FStructProperty up-front via FFieldClass name
(which is often ClassPrivate=0 on patch 20260428). Instead we report,
for each FField in the chain, the bytes at every offset 0xD0..0x140
that look like heap pointers to UObjects, and let the caller see the
distribution.

Usage:
    sudo python3 -u tools/probe_struct_offset.py
"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from memreader import MemReader, find_pid
from fname_pipeline import LiveResolver, slot_decrypt, MODULE_BASE

# Patch 20260428 offsets
FF_VTABLE        = 0x00
FF_CLASSPRIVATE  = 0x20
FF_NEXT          = 0x48
FF_OWNER         = 0x50
FF_NAMEPRIVATE   = 0x70
FF_SALT          = 0x78
EXPECTED_SALT    = 0x893BCE4393840650

US_CHILDPROPERTIES = 0xD0

def in_module(p, base=MODULE_BASE):
    return base <= p < base + 0x10000000

def is_heap(p):
    return 0x100000 < p < 0x800000000000

def _read(mr, addr, size):
    try:
        return mr.read(addr, size)
    except Exception:
        return b"\x00" * size

def _u64(mr, addr):
    return int.from_bytes(_read(mr, addr, 8), "little")

def get_obj_name(mr, rv, obj):
    """Try all 4 slots to recover object name."""
    if not is_heap(obj):
        return ""
    for slot in range(4):
        addr = obj + 0x20 + slot * 0x20
        enc = _read(mr, addr, 16)
        if not any(enc):
            continue
        try:
            dec = slot_decrypt(enc)
            ci = dec & 0xFFFFFFFF
            if 0 < ci < 0x2000000:
                ptr = rv.resolve_name_ptr(ci)
                if ptr:
                    name = rv.decrypt_name_string(ptr)
                    if name and all(0x20 <= ord(c) < 0x7F for c in name):
                        return name
        except Exception:
            pass
    return ""

def parse_dump_for_classes():
    """Pull the known UClass addresses + names from dump_objects.txt."""
    classes = {}  # short_name -> [addrs]
    DUMP = "/media/frost/Coding Stuf/Linux/FrostSDKDumper/dump_objects.txt"
    with open(DUMP) as f:
        for line in f:
            # [N] 0xADDR | name
            if not line.startswith("["):
                continue
            try:
                pipe = line.index("|")
            except ValueError:
                continue
            left = line[:pipe]
            name = line[pipe+1:].strip()
            # extract addr
            i = left.find("0x")
            if i < 0:
                continue
            addr_str = left[i:].strip()
            try:
                addr = int(addr_str, 16)
            except Exception:
                continue
            classes.setdefault(name, []).append(addr)
    return classes

def walk_chain(mr, head, max_props=200):
    """Walk an FField linked list, return [(ff_addr, salt_ok)]."""
    out = []
    visited = set()
    ff = head
    while ff and len(visited) < max_props:
        if ff in visited:
            break
        visited.add(ff)
        if not is_heap(ff):
            break
        salt = _u64(mr, ff + FF_SALT)
        if salt != EXPECTED_SALT:
            break
        out.append(ff)
        ff = _u64(mr, ff + FF_NEXT)
    return out

def classify_offset(mr, rv, ptr):
    """Decide if a value looks like it points to a UObject (->UScriptStruct candidate).
       Returns (kind, name_or_descr).
       kind in {ZERO, NONHEAP, HEAP_NONOBJ, OBJ, OBJ_NAMED}
    """
    if ptr == 0:
        return "ZERO", ""
    if not is_heap(ptr):
        return "NONHEAP", f"0x{ptr:X}"
    vt = _u64(mr, ptr)
    if not in_module(vt):
        return "HEAP_NONOBJ", f"vt=0x{vt:X}"
    # Try to get its name
    name = get_obj_name(mr, rv, ptr)
    if name:
        return "OBJ_NAMED", name
    return "OBJ", f"vt=0x{vt:X}"

def main():
    pid = find_pid()
    if not pid:
        print("can't find game PID", flush=True)
        return 1
    print(f"[+] PID = {pid}", flush=True)
    classes = parse_dump_for_classes()
    print(f"[+] parsed {sum(len(v) for v in classes.values())} obj entries"
          f" across {len(classes)} unique names", flush=True)

    # Pick a diverse set of class-like things
    targets = []
    PRIORITY_NAMES = [
        "EmbarkPlayerController", "Pawn", "Actor", "Character", "PlayerController",
        "PlayerState", "GameMode", "GameState", "ActorComponent",
        "SceneComponent", "PrimitiveComponent", "MovementComponent",
        "HealthComponent", "InventoryComponent", "InteractionComponent",
        "Weapon", "Inventory", "Item", "PickupActor",
        # FStructProperty-rich classes:
        "PlayerCameraManager", "WorldSettings", "GameInstance", "GameUserSettings",
        "EmbarkGameMode", "EmbarkGameState", "EmbarkPlayerState",
    ]
    # Hardcoded FFieldClass globals from arc_decrypt's seeded map (patch 20260428):
    KNOWN_TYPE_GLOBALS = {
        0xDE15E50: "FStructProperty",
        0xDE15740: "FObjectProperty",
        0xDE157C0: "FObjectProperty",
        0xDE15ED0: "FWeakObjectProperty",
        0xDE15D20: "FSoftObjectProperty",
        0xDE15030: "FLazyObjectProperty",
        0xDE14E60: "FClassProperty",
        0xDE15CB0: "FSoftClassProperty",
        0xDE14FC0: "FInterfaceProperty",
        0xDE0CF70: "FEnumProperty",
        0xDE14CA0: "FArrayProperty",
        0xDE15C40: "FSetProperty",
        0xDE150A0: "FMapProperty",
        0xDE14F40: "FDelegateProperty",
        0xDE15120: "FMulticastDelegateProperty",
        0xDE15190: "FMulticastInlineDelegateProperty",
        0xDE15200: "FMulticastSparseDelegateProperty",
        0xDE15270: "FNameProperty",
        0xDE15430: "FIntProperty",
        0xDE15660: "FFloatProperty",
        0xDE156D0: "FDoubleProperty",
        0xDE14D80: "FBoolProperty",
        0xDE14DF0: "FByteProperty",
        0xDE15DE0: "FStrProperty",
        0xDE17200: "FTextProperty",
    }
    for n in PRIORITY_NAMES:
        if n in classes:
            for a in classes[n][:3]:
                targets.append((n, a))
    # Add any other names that look like classes (CamelCase, no '/', no '.')
    for n, addrs in classes.items():
        if len(targets) >= 30:
            break
        if "/" in n or "." in n or "_" in n:
            continue
        if not n[:1].isupper():
            continue
        if n in PRIORITY_NAMES:
            continue
        targets.append((n, addrs[0]))

    print(f"[+] picked {len(targets)} candidate addrs", flush=True)
    with MemReader(pid) as mr:
        rv = LiveResolver(mr)

        # Aggregate: per offset, count distribution
        # offset_dist[off] = { ZERO, NONHEAP, HEAP_NONOBJ, OBJ, OBJ_NAMED }
        from collections import Counter, defaultdict
        offset_dist = defaultdict(Counter)
        # Per FField row, record offset -> ptr+kind+name
        per_field_rows = []
        # Also: for each FField, remember whether ANY offset in the range
        # gives an OBJ_NAMED that looks struct-like (CamelCase, distinct from FField name).
        struct_named_offsets = Counter()

        offsets_to_check = list(range(0xD0, 0x148, 8))

        ff_count = 0
        struct_candidate_count = 0
        for owner_name, owner_addr in targets:
            head = _u64(mr, owner_addr + US_CHILDPROPERTIES)
            if not is_heap(head):
                continue
            # quick salt check on head
            chain = walk_chain(mr, head, max_props=400)
            if not chain:
                continue
            print(f"\n[*] {owner_name} @ 0x{owner_addr:X}: chain len = {len(chain)}", flush=True)
            for ff in chain:
                ff_count += 1
                # FField name
                enc = _read(mr, ff + FF_NAMEPRIVATE, 16)
                ff_name = ""
                try:
                    dec = slot_decrypt(enc)
                    ci = dec & 0xFFFFFFFF
                    if 0 < ci < 0x2000000:
                        ptr = rv.resolve_name_ptr(ci)
                        if ptr:
                            n = rv.decrypt_name_string(ptr)
                            if n and all(0x20 <= ord(c) < 0x7F for c in n):
                                ff_name = n
                except Exception:
                    pass
                # Identify type via FField+0x88 (FFieldClass-like global)
                ftype_global = _u64(mr, ff + 0x88)
                ftype_rva = (ftype_global - MODULE_BASE) if in_module(ftype_global) else 0
                ftype_name = KNOWN_TYPE_GLOBALS.get(ftype_rva, f"unknown_0x{ftype_rva:X}")
                # Check each offset
                row = {"ff": ff, "owner": owner_name, "name": ff_name, "ftype": ftype_name, "offsets": {}}
                any_struct_like = False
                for off in offsets_to_check:
                    val = _u64(mr, ff + off)
                    kind, descr = classify_offset(mr, rv, val)
                    offset_dist[off][kind] += 1
                    row["offsets"][off] = (val, kind, descr)
                    if kind == "OBJ_NAMED":
                        # Check if it's distinct from owner/ff_name
                        if descr and descr != ff_name and descr != owner_name:
                            struct_named_offsets[off] += 1
                            any_struct_like = True
                if any_struct_like:
                    struct_candidate_count += 1
                per_field_rows.append(row)

        print(f"\n[=] Summary: {ff_count} FFields, {struct_candidate_count} have at least one OBJ_NAMED ptr in 0xD0..0x140")

        # Per-FFieldClass-type breakdown
        from collections import Counter as _Cnt
        type_breakdown = _Cnt()
        for r in per_field_rows:
            type_breakdown[r["ftype"]] += 1
        print("\n=== FField type breakdown (via FField+0x88 → FFieldClass global) ===")
        for t, c in type_breakdown.most_common():
            print(f"  {c:4d}  {t}")

        print("\n=== Per-offset distribution (across all FFields) ===")
        for off in offsets_to_check:
            d = offset_dist[off]
            total = sum(d.values())
            print(f"  +0x{off:03X}: ZERO={d['ZERO']:4d}  NONHEAP={d['NONHEAP']:4d}  "
                  f"HEAP_NONOBJ={d['HEAP_NONOBJ']:4d}  OBJ={d['OBJ']:4d}  "
                  f"OBJ_NAMED={d['OBJ_NAMED']:4d}  (total {total})")

        print("\n=== Offsets where the named UObject ptr looks STRUCT-LIKE (≠ owner/ff_name) ===")
        for off, n in struct_named_offsets.most_common():
            print(f"  +0x{off:03X}: {n} occurrences")

        # Simulate the OLD broad-scan logic: scan +0xD0..+0x118 step 8,
        # take FIRST heap-pointer with module-range vtable.
        print("\n=== OLD broad-scan simulation (+0xD0..+0x118 step 8, first heap+module-vt) ===")
        old_scan_picks = Counter()
        old_scan_offsets = Counter()
        old_scan_examples = defaultdict(list)
        for r in per_field_rows:
            if r["ftype"] != "FStructProperty":
                continue
            picked = None
            picked_off = None
            for off in range(0xD0, 0x118 + 8, 8):
                val, kind, descr = r["offsets"][off]
                if kind in ("OBJ", "OBJ_NAMED"):
                    picked = (val, kind, descr)
                    picked_off = off
                    break
            if picked is None:
                continue
            old_scan_offsets[picked_off] += 1
            kind = picked[1]
            descr = picked[2]
            if kind == "OBJ_NAMED":
                old_scan_picks[("named", descr)] += 1
            else:
                old_scan_picks[("unnamed", descr)] += 1
            if len(old_scan_examples[picked_off]) < 5:
                old_scan_examples[picked_off].append(
                    f"{r['owner']}.{r['name']} -> [{kind}] {descr}")
        print(f"  Picked offset histogram (which offset OLD code would have picked):")
        for off, n in old_scan_offsets.most_common():
            print(f"    +0x{off:03X}: {n} picks")
            for ex in old_scan_examples[off]:
                print(f"        {ex}")
        # NEW (strict +0x108) summary
        print("\n=== NEW strict +0x108 read summary ===")
        new_picks = 0
        new_named = 0
        for r in per_field_rows:
            if r["ftype"] != "FStructProperty":
                continue
            val, kind, descr = r["offsets"][0x108]
            if kind != "ZERO" and kind != "NONHEAP":
                new_picks += 1
                if kind == "OBJ_NAMED":
                    new_named += 1
        print(f"  +0x108: {new_picks} non-zero/non-trash, {new_named} resolved to UObject name")

        # Show only FStructProperty FFields and where their Struct ptr lives
        print("\n=== ONLY FStructProperty FFields (filtered via FField+0x88) ===")
        struct_fields = [r for r in per_field_rows if r["ftype"] == "FStructProperty"]
        print(f"  total FStructProperty FFields: {len(struct_fields)}")
        # Per-offset distribution among FStructProperty FFields
        sp_offset_dist = defaultdict(Counter)
        for r in struct_fields:
            for off, (val, kind, descr) in r["offsets"].items():
                sp_offset_dist[off][kind] += 1
        print("  Per-offset distribution (FStructProperty only):")
        for off in offsets_to_check:
            d = sp_offset_dist[off]
            total = sum(d.values())
            print(f"    +0x{off:03X}: ZERO={d['ZERO']:3d} NONHEAP={d['NONHEAP']:3d} "
                  f"HEAP_NONOBJ={d['HEAP_NONOBJ']:3d} OBJ={d['OBJ']:3d} "
                  f"OBJ_NAMED={d['OBJ_NAMED']:3d}  (total {total})")
        for r in struct_fields[:30]:
            print(f"\n  {r['owner']}.{r['name']} @ 0x{r['ff']:X}")
            for off, (val, kind, descr) in r["offsets"].items():
                if kind in ("OBJ_NAMED", "OBJ"):
                    print(f"     +0x{off:03X} = 0x{val:016X}  [{kind}] {descr}")
    return 0

if __name__ == "__main__":
    sys.exit(main() or 0)
