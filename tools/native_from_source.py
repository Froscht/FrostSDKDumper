#!/usr/bin/env python3
import argparse
import os
import re
import sys
from pathlib import Path

UE_ROOT = Path("/media/frost/Coding Stuf/Linux/UnrealEngine/Engine/Source")

EDITOR_GUARDS = {
    "WITH_EDITOR", "WITH_EDITORONLY_DATA", "WITH_EDITOR_STORAGE",
    "UE_EDITOR", "WITH_LIVE_CODING", "WITH_METADATA",
    "!UE_BUILD_SHIPPING", "!UE_BUILD_TEST", "WITH_DEV_AUTOMATION_TESTS",
}

TYPE_SIZE = {
    "bool": 1, "uint8": 1, "int8": 1,
    "uint16": 2, "int16": 2, "uint32": 4, "int32": 4,
    "uint64": 8, "int64": 8, "float": 4, "double": 8,
    "FName": 8, "FString": 16, "FText": 24,
    "FVector": 12, "FVector2D": 8, "FVector4": 16, "FVector_NetQuantize": 12,
    "FRotator": 12, "FQuat": 16, "FTransform": 96,
    "FGuid": 16, "FColor": 4, "FLinearColor": 16,
    "FScriptDelegate": 20, "FMulticastScriptDelegate": 16, "FSparseDelegate": 1,
    "ENetRole": 1, "ENetDormancy": 1, "EAutoReceiveInput": 1,
    "ESpawnActorCollisionHandlingMethod": 1, "EPhysicsReplicationMode": 1,
    "EActorUpdateOverlapsMethod": 1,
    "TObjectPtr": 8, "TWeakObjectPtr": 8, "TSoftObjectPtr": 40,
    "TSubclassOf": 8, "TSoftClassPtr": 40,
    "TArray": 16, "TMap": 80, "TSet": 80,
    "FActorTickFunction": 64,
    "FRepAttachment": 96, "FRepMovement": 112,
}

class Field:
    __slots__ = ("Line", "TypeName", "Name", "BitfieldWidth", "IsReflected", "ArrayDim")
    def __init__(self, line, typename, name, bitfield_width=0, is_reflected=False, array_dim=1):
        self.Line = line
        self.TypeName = typename
        self.Name = name
        self.BitfieldWidth = bitfield_width
        self.IsReflected = is_reflected
        self.ArrayDim = array_dim
    def __repr__(self):
        r = "R" if self.IsReflected else " "
        bf = f":{self.BitfieldWidth}" if self.BitfieldWidth else ""
        ad = f"[{self.ArrayDim}]" if self.ArrayDim > 1 else ""
        return f"[{r}] {self.TypeName} {self.Name}{bf}{ad}  (line {self.Line})"

def StripBlockComments(src):
    return re.sub(r"/\*.*?\*/", "", src, flags=re.DOTALL)

def StripLineComments(line):
    idx = line.find("//")
    if idx >= 0:
        return line[:idx]
    return line

def ParseHeader(path, class_name):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        raw = f.read()
    raw = StripBlockComments(raw)

    lines = raw.splitlines()
    guard_stack = []
    editor_depth = 0
    pending_reflected = False
    fields = []
    in_class = False
    class_brace_depth = 0

    cls_prefixed = class_name
    if not cls_prefixed.startswith(("A", "U", "F", "T", "S", "I", "E")):
        cls_prefixed = "A" + cls_prefixed
    cpp_candidates = [class_name, "A" + class_name, "U" + class_name, "F" + class_name]
    seen = set()
    cpp_names = []
    for n in cpp_candidates:
        if n not in seen:
            seen.add(n)
            cpp_names.append(n)
    cls_alt = "|".join(re.escape(n) for n in cpp_names)
    class_re = re.compile(
        r"\bclass\s+(?:[A-Z_]+_API\s+)?(?:" + cls_alt + r")\b\s*(?![;])(?=\s*[:{])"
    )
    field_re = re.compile(
        r"^\s*"
        r"(?P<type>[A-Za-z_][\w:]*(?:\s*<[^;]*>)?(?:\s*\*)?)"
        r"\s+(?P<name>[A-Za-z_]\w*)"
        r"(?:\s*:\s*(?P<bf>\d+))?"
        r"(?:\s*\[(?P<arr>[^\]]+)\])?"
        r"\s*(?:=[^;]*)?"
        r";"
    )

    for lnum, raw_line in enumerate(lines, 1):
        line = StripLineComments(raw_line).rstrip()
        stripped = line.strip()
        if not stripped:
            continue

        if stripped.startswith("#if"):
            cond = stripped[3:].lstrip()
            if cond.startswith("def "):
                cond = cond[4:].strip()
            elif cond.startswith("ndef "):
                cond = "!" + cond[5:].strip()
            tokens = re.findall(r"[!A-Za-z_][\w!]*", cond)
            enters_editor = any(t in EDITOR_GUARDS for t in tokens)
            guard_stack.append(enters_editor)
            if enters_editor:
                editor_depth += 1
            continue
        if stripped.startswith("#else") or stripped.startswith("#elif"):
            if guard_stack:
                was = guard_stack[-1]
                if was:
                    editor_depth -= 1
                    guard_stack[-1] = False
            continue
        if stripped.startswith("#endif"):
            if guard_stack:
                was = guard_stack.pop()
                if was:
                    editor_depth -= 1
            continue

        if not in_class:
            if class_re.search(line):
                in_class = True
                for ch in line:
                    if ch == "{":
                        class_brace_depth += 1
            continue

        for ch in line:
            if ch == "{":
                class_brace_depth += 1
            elif ch == "}":
                class_brace_depth -= 1
                if class_brace_depth <= 0:
                    in_class = False
                    return fields

        if editor_depth > 0:
            continue

        if "UPROPERTY(" in stripped or stripped.startswith("UPROPERTY"):
            pending_reflected = True
            continue
        if stripped.startswith("UFUNCTION") or stripped.startswith("GENERATED_BODY") \
                or stripped.startswith("DECLARE_") or stripped.startswith("public:") \
                or stripped.startswith("private:") or stripped.startswith("protected:") \
                or stripped.startswith("friend "):
            pending_reflected = False
            continue

        m = field_re.match(line)
        if not m:
            if pending_reflected and stripped.endswith(";") is False:
                pass
            continue

        typename = m.group("type").strip()
        name = m.group("name")
        bf = int(m.group("bf")) if m.group("bf") else 0
        arr = m.group("arr")
        array_dim = 1
        if arr:
            try:
                array_dim = int(arr, 0)
            except ValueError:
                array_dim = 1

        if typename in ("return", "if", "else", "for", "while", "switch", "case",
                        "const", "static", "inline", "virtual", "constexpr",
                        "using", "typedef"):
            pending_reflected = False
            continue
        if name in ("return", "if", "else"):
            pending_reflected = False
            continue

        fields.append(Field(lnum, typename, name, bf, pending_reflected, array_dim))
        pending_reflected = False

    return fields

def ParseSdkNamespace(sdk_path, class_name):
    with open(sdk_path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()
    ns_re = re.compile(
        r"^namespace\s+" + re.escape(class_name) + r"\s*\{(.*?)^\}",
        re.MULTILINE | re.DOTALL,
    )
    m = ns_re.search(text)
    if not m:
        return None
    body = m.group(1)

    reflected = []
    natives = []

    r_re = re.compile(
        r"constexpr\s+uint32_t\s+(\w+)\s*=\s*(0x[0-9a-fA-F]+);"
        r"\s*//\s*([^/]+?)\s*//\s*"
        r"(?:mask=(0x[0-9a-fA-F]+)\s*//\s*)?"
        r"size=(0x[0-9a-fA-F]+)"
        r"(?:\s*//\s*(native))?"
    )
    for m2 in r_re.finditer(body):
        name = m2.group(1)
        offset = int(m2.group(2), 16)
        type_str = m2.group(3).strip()
        mask = int(m2.group(4), 16) if m2.group(4) else 0
        size = int(m2.group(5), 16)
        is_native = m2.group(6) == "native"
        entry = {"name": name, "offset": offset, "type": type_str,
                 "mask": mask, "size": size}
        if is_native:
            natives.append(entry)
        else:
            reflected.append(entry)
    # Merge native bitfield holes into the same masked-bit view used by the
    # bitfield analyzer — they occupy a real byte+bit slot too.
    return {"reflected": reflected, "natives": natives,
            "native_bits": [n for n in natives if n["mask"] > 0]}

def AnalyzeBitfields(fields, sdk):
    src_chain = [f for f in fields if f.BitfieldWidth]
    src_idx = {f.Name: i for i, f in enumerate(src_chain)}
    bitfield_names = set(src_idx.keys())

    sdk_bits = sorted([e for e in sdk["reflected"] if e["mask"] > 0],
                      key=lambda e: (e["offset"], e["mask"]))
    sdk_by_byte = {}
    for e in sdk_bits:
        sdk_by_byte.setdefault(e["offset"], set()).add(e["mask"])

    print(f"\n=== Bitfield analysis ===")
    print(f"Source bitfield fields: {len(src_chain)}")
    print(f"SDK bitfield entries:   {len(sdk_bits)} across {len(sdk_by_byte)} bytes")

    anchors = []
    for e in sdk_bits:
        if e["name"] in src_idx:
            anchors.append((e["offset"], e["mask"], src_idx[e["name"]], e["name"]))
    anchors.sort()

    print(f"Anchors: {len(anchors)} reflected bitfields found in source")

    print(f"\n=== Interior candidates (between two same-byte anchors, gap count matches) ===")
    total_cands = 0
    for i in range(len(anchors) - 1):
        A = anchors[i]
        B = anchors[i + 1]
        if A[0] != B[0]:
            continue
        bit_A = A[1].bit_length() - 1
        bit_B = B[1].bit_length() - 1
        if bit_B <= bit_A:
            continue
        gap_bits = [b for b in range(bit_A + 1, bit_B) if (1 << b) not in sdk_by_byte[A[0]]]
        gap_src_indices = list(range(A[2] + 1, B[2]))
        if not gap_bits:
            continue
        if len(gap_bits) != len(gap_src_indices):
            print(f"  0x{A[0]:x} bits {bit_A+1}..{bit_B-1} between {A[3]} and {B[3]}: "
                  f"gap={len(gap_bits)} but source has {len(gap_src_indices)} — skip (drift)")
            continue
        for gb, si in zip(gap_bits, gap_src_indices):
            f = src_chain[si]
            print(f"  0x{A[0]:x} mask=0x{1<<gb:x}  candidate={f.Name}  (Actor.h:{f.Line})")
            total_cands += 1
    print(f"total interior candidates: {total_cands}")

    print(f"\n=== SDK bitfields NOT in source (likely ARC-added) ===")
    for e in sdk_bits:
        if e["name"] not in bitfield_names:
            print(f"  0x{e['offset']:x} mask=0x{e['mask']:x}  {e['name']}")

    matched_src = {a[3] for a in anchors}
    print(f"\n=== Source bitfields never found in SDK (ARC-removed or non-shipping) ===")
    for f in src_chain:
        if f.Name not in matched_src:
            print(f"  {f.Name}  (Actor.h:{f.Line})")

def AnalyzeNonBitfieldNatives(fields, sdk):
    reflected_by_name = {e["name"]: e for e in sdk["reflected"]}
    natives = sorted(sdk["natives"], key=lambda e: e["offset"])
    if not natives:
        return

    print(f"\n=== Non-bitfield native holes ===")
    non_bf_source = [f for f in fields if f.BitfieldWidth == 0]

    anchor_idx_by_name = {}
    for i, f in enumerate(non_bf_source):
        if f.Name in reflected_by_name:
            anchor_idx_by_name[f.Name] = i
    anchors = sorted(
        [(reflected_by_name[n]["offset"], i, n) for n, i in anchor_idx_by_name.items()])
    print(f"Anchors: {len(anchors)} non-bitfield reflected names matched to source")

    natives_by_prev_anchor = {}
    for nat in natives:
        prev_anchor = None
        next_anchor = None
        for off, i, name in anchors:
            if off <= nat["offset"]:
                prev_anchor = (off, i, name)
            elif off > nat["offset"] and next_anchor is None:
                next_anchor = (off, i, name)
                break
        if not prev_anchor or not next_anchor:
            continue
        key = (prev_anchor[2], next_anchor[2])
        natives_by_prev_anchor.setdefault(key, []).append(nat)

    high_conf = 0
    low_conf = 0
    for (prev_name, next_name), nats in natives_by_prev_anchor.items():
        prev_i = anchor_idx_by_name[prev_name]
        next_i = anchor_idx_by_name[next_name]
        between = [f for f in non_bf_source[prev_i+1:next_i]
                   if f.Name not in reflected_by_name]
        if not between:
            continue
        prev_off = reflected_by_name[prev_name]["offset"]
        next_off = reflected_by_name[next_name]["offset"]
        real_nats = [n for n in nats if n["type"] not in ("?",)]
        if len(between) == 1 and len(real_nats) == 1:
            n = real_nats[0]
            f = between[0]
            expect = TYPE_SIZE.get(f.TypeName.split("<")[0], 0)
            fit = "size-fit" if expect and expect == n["size"] else "size-unchecked"
            print(f"  [HIGH]  0x{n['offset']:x} {n['type']:>18s}  candidate={f.Name}  "
                  f"type={f.TypeName}  ({fit})  (Actor.h:{f.Line})")
            high_conf += 1
            continue

        # Walk source fields in order at prev_off, accumulate offsets by size,
        # only propose a source field for a native hole when the walked cursor
        # lands on that hole AND source size == hole size.
        cursor = prev_off + max(1, TYPE_SIZE.get(
            non_bf_source[prev_i].TypeName.split("<")[0], 8))
        walked = []
        for f in between:
            base = f.TypeName.split("<")[0].split("*")[0].strip()
            sz = TYPE_SIZE.get(base, 0)
            if f.TypeName.endswith("*") or "TObjectPtr" in f.TypeName \
                    or "TWeakObjectPtr" in f.TypeName:
                sz = 8
            if sz == 0:
                walked.clear()
                break
            align = min(sz, 8) if sz in (2, 4, 8, 16) else 1
            if align > 1 and cursor % align:
                cursor += align - (cursor % align)
            walked.append((cursor, f, sz))
            cursor += sz * f.ArrayDim
        if walked and cursor <= next_off:
            for n in nats:
                match = None
                for w_off, w_field, w_sz in walked:
                    if w_off == n["offset"] and w_sz == n["size"]:
                        match = w_field
                        break
                if match:
                    print(f"  [MED]   0x{n['offset']:x} {n['type']:>18s}  "
                          f"candidate={match.Name}  type={match.TypeName}  "
                          f"(Actor.h:{match.Line})")
                    high_conf += 1
                else:
                    print(f"  [???]   0x{n['offset']:x} {n['type']:>18s}  "
                          f"no source field at this offset in walked layout")
        else:
            names = ", ".join(f.Name for f in between[:6])
            offs = ", ".join(f"0x{n['offset']:x}" for n in nats)
            reason = "unknown size" if not walked else f"overshoots {cursor:x} > {next_off:x}"
            print(f"  [LOW]   {offs}  between {prev_name}(+0x{prev_off:x}) and "
                  f"{next_name}(+0x{next_off:x})  candidates: {names}  ({reason})")
            low_conf += 1
    print(f"high-confidence: {high_conf}, low-confidence: {low_conf}")

def CollectHighCandidates(fields, sdk):
    src_chain = [f for f in fields if f.BitfieldWidth]
    src_idx = {f.Name: i for i, f in enumerate(src_chain)}
    sdk_bits = sorted([e for e in sdk["reflected"] if e["mask"] > 0],
                      key=lambda e: (e["offset"], e["mask"]))
    sdk_by_byte = {}
    for e in sdk_bits:
        sdk_by_byte.setdefault(e["offset"], set()).add(e["mask"])
    anchors = sorted([(e["offset"], e["mask"], src_idx[e["name"]], e["name"])
                      for e in sdk_bits if e["name"] in src_idx])

    out = {}  # (offset, mask) -> name  (mask 0 for non-bf)
    for i in range(len(anchors) - 1):
        A = anchors[i]; B = anchors[i + 1]
        if A[0] != B[0]:
            continue
        bit_A = A[1].bit_length() - 1
        bit_B = B[1].bit_length() - 1
        if bit_B <= bit_A:
            continue
        gap_bits = [b for b in range(bit_A + 1, bit_B) if (1 << b) not in sdk_by_byte[A[0]]]
        gap_src_idxs = list(range(A[2] + 1, B[2]))
        if len(gap_bits) == len(gap_src_idxs):
            for gb, si in zip(gap_bits, gap_src_idxs):
                out[(A[0], 1 << gb)] = src_chain[si].Name

    reflected_by_name = {e["name"]: e for e in sdk["reflected"]}
    natives = sorted(sdk["natives"], key=lambda e: e["offset"])
    non_bf_source = [f for f in fields if f.BitfieldWidth == 0]
    anchor_idx_by_name = {f.Name: i for i, f in enumerate(non_bf_source)
                          if f.Name in reflected_by_name}
    anchors_nb = sorted([(reflected_by_name[n]["offset"], i, n)
                         for n, i in anchor_idx_by_name.items()])

    grouped = {}
    for nat in natives:
        prev = next_ = None
        for off, i, name in anchors_nb:
            if off <= nat["offset"]:
                prev = (off, i, name)
            elif off > nat["offset"] and next_ is None:
                next_ = (off, i, name); break
        if prev and next_:
            grouped.setdefault((prev[2], next_[2]), []).append(nat)

    for (pn, nn), nats in grouped.items():
        pi = anchor_idx_by_name[pn]; ni = anchor_idx_by_name[nn]
        between = [f for f in non_bf_source[pi+1:ni]
                   if f.Name not in reflected_by_name]
        if not between:
            continue
        real = [n for n in nats if n["type"] != "?"]
        if len(between) == 1 and len(real) == 1:
            out[(real[0]["offset"], 0)] = between[0].Name
            continue

        prev_off = reflected_by_name[pn]["offset"]
        next_off = reflected_by_name[nn]["offset"]
        cursor = prev_off + max(1, TYPE_SIZE.get(
            non_bf_source[pi].TypeName.split("<")[0], 8))
        walked = []
        for f in between:
            base = f.TypeName.split("<")[0].split("*")[0].strip()
            sz = TYPE_SIZE.get(base, 0)
            if f.TypeName.endswith("*") or "TObjectPtr" in f.TypeName \
                    or "TWeakObjectPtr" in f.TypeName:
                sz = 8
            if sz == 0:
                walked.clear(); break
            align = min(sz, 8) if sz in (2, 4, 8, 16) else 1
            if align > 1 and cursor % align:
                cursor += align - (cursor % align)
            walked.append((cursor, f, sz))
            cursor += sz * f.ArrayDim
        if walked and cursor <= next_off:
            for n in nats:
                for w_off, w_field, w_sz in walked:
                    if w_off == n["offset"] and w_sz == n["size"]:
                        out[(n["offset"], 0)] = w_field.Name
                        break
    return out

def ApplyToSdk(sdk_path, class_name, candidates):
    with open(sdk_path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()
    ns_re = re.compile(
        r"(^namespace\s+" + re.escape(class_name) + r"\s*\{)(.*?)(^\})",
        re.MULTILINE | re.DOTALL)
    m = ns_re.search(text)
    if not m:
        print(f"namespace {class_name} not in {sdk_path}", file=sys.stderr)
        return 0
    body = m.group(2)

    replaced = 0
    def RewriteLine(mo):
        nonlocal replaced
        line = mo.group(0)
        off = int(mo.group("off"), 16)
        mask_str = mo.group("mask")
        mask = int(mask_str, 16) if mask_str else 0
        key = (off, mask)
        if key not in candidates:
            return line
        new_name = candidates[key]
        if mask:
            bit_idx = (mask.bit_length() - 1)
            new_ident = f"Native_0x{off:x}_bit{bit_idx}_{new_name}"
        else:
            new_ident = f"Native_0x{off:x}_{new_name}"
        line = re.sub(r"Native_0x[0-9a-fA-F]+(?:_bit\d+)?(?:_\w+)?",
                      new_ident, line, count=1)
        if "// source-candidate" not in line:
            line = line.rstrip() + f"  // source-candidate={new_name}\n"
        else:
            if not line.endswith("\n"):
                line += "\n"
        replaced += 1
        return line

    line_re = re.compile(
        r"constexpr\s+uint32_t\s+Native_0x[0-9a-fA-F]+(?:_bit\d+)?(?:_\w+)?\s*=\s*"
        r"(?P<off>0x[0-9a-fA-F]+);\s*//[^\n]*?"
        r"(?:mask=(?P<mask>0x[0-9a-fA-F]+)\s*//[^\n]*?)?"
        r"size=0x[0-9a-fA-F]+[^\n]*\n")
    new_body = line_re.sub(RewriteLine, body)
    new_text = text[:m.start(2)] + new_body + text[m.end(2):]
    out_path = sdk_path + ".with_names"
    with open(out_path, "w") as f:
        f.write(new_text)
    print(f"wrote {out_path} — {replaced} lines renamed in namespace {class_name}")
    return replaced

def Main():
    ap = argparse.ArgumentParser()
    ap.add_argument("class_name", help="e.g. Actor, PlayerController")
    ap.add_argument("--sdk", default="SDK_Output.txt")
    ap.add_argument("--header", default=None,
                    help="Path to UE header; auto-located if not given")
    ap.add_argument("--apply", action="store_true",
                    help="Rewrite SDK namespace with HIGH-conf candidate names")
    args = ap.parse_args()

    header_path = args.header
    if not header_path:
        cls = "A" + args.class_name if args.class_name[0].isupper() and args.class_name[0] != "A" else args.class_name
        candidates = list(UE_ROOT.rglob(f"{args.class_name}.h"))
        if not candidates:
            print(f"header for {args.class_name} not found under {UE_ROOT}", file=sys.stderr)
            sys.exit(1)
        header_path = str(candidates[0])
        print(f"header: {header_path}")

    fields = ParseHeader(header_path, args.class_name)
    print(f"parsed {len(fields)} declared fields from source (editor-only stripped)")

    sdk = ParseSdkNamespace(args.sdk, args.class_name)
    if not sdk:
        print(f"namespace {args.class_name} not found in {args.sdk}", file=sys.stderr)
        sys.exit(1)
    print(f"SDK: {len(sdk['reflected'])} reflected, {len(sdk['natives'])} native holes")

    AnalyzeBitfields(fields, sdk)
    AnalyzeNonBitfieldNatives(fields, sdk)

    if args.apply:
        cands = CollectHighCandidates(fields, sdk)
        print(f"\ncollected {len(cands)} HIGH/MED candidates for injection")
        ApplyToSdk(args.sdk, args.class_name, cands)

if __name__ == "__main__":
    Main()
