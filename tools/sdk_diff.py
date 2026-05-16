#!/usr/bin/env python3
"""sdk_diff.py - Patch-day triage diff for FrostDumper SDK outputs.

Compares two SDK snapshots and reports namespace additions/removals, per-field
adds/removes, offset shifts (the load-bearing signal on patch day) and type +
inheritance changes.

Handles two input shapes:
  - flat FrostDumper SDK_Output.txt (single file, `namespace X { constexpr ...}`)
  - Dumper-7 multi-file refSDK directory (one .hpp per package,
    `struct FX { TYPE NAME; // 0xOFFSET(0xSIZE) }`)

Usage:
  python3 sdk_diff.py <old> <new> [--filter REGEX] [--no-color] [--summary-only]
"""

import argparse
import os
import re
import sys
from collections import OrderedDict
from glob import glob


ANSI = {
    "reset":  "\x1b[0m",
    "bold":   "\x1b[1m",
    "dim":    "\x1b[2m",
    "red":    "\x1b[31m",
    "green":  "\x1b[32m",
    "yellow": "\x1b[33m",
    "blue":   "\x1b[34m",
    "magenta":"\x1b[35m",
    "cyan":   "\x1b[36m",
}

UseColor = True


def colorize(s, color):
    if not UseColor:
        return s
    return f"{ANSI.get(color,'')}{s}{ANSI['reset']}"


FlatHeaderRe = re.compile(
    r"^//\s*(Enum|Struct|Class)\s+(\S+)\s*$"
)
FlatInheritsRe = re.compile(
    r"^//\s*Inherits:\s*(\w+)\s*(?:\(0x[0-9A-Fa-f]+\))?\s*$"
)
FlatInheritChainStepRe = re.compile(
    r"^//\s*(?:→|->)\s*(\w+)"
)
FlatNamespaceOpenRe = re.compile(
    r"^namespace\s+(\w+)\s*\{"
)
FlatNamespaceCloseRe = re.compile(
    r"^\}\s*//\s*namespace\s+(\w+)"
)
FlatFieldRe = re.compile(
    r"^\s*constexpr\s+uint32_t\s+(\S+)\s*=\s*0x([0-9A-Fa-f]+);\s*//\s*([^/]+?)\s*(?://.*)?$"
)
FlatEnumMemberRe = re.compile(
    r"^\s*constexpr\s+int(?:64_t|32_t)?\s+(\S+)\s*=\s*(-?\d+|0x[0-9A-Fa-f]+);"
)
FlatFunctionsHeaderRe = re.compile(
    r"^\s*//\s*===\s*Functions\s*\(\d+\)\s*===\s*$"
)
FlatFunctionSigRe = re.compile(
    r"^\s*(?:[\w<>:*&\s]+?)\s+(\w+)\s*\((.*)\)\s*;\s*(?://.*)?$"
)

RefStructOpenRe = re.compile(
    r"^(?:struct|class)\s+(?:alignas\(\d+\)\s+)?(\w+)(?:\s*:\s*public\s+(\w+))?\s*$"
)
RefFieldRe = re.compile(
    r"^\s*([\w<>:,\s\*&]+?)\s+(\w+)(?:\[\d+\])?\s*;\s*"
    r"//\s*0x([0-9A-Fa-f]+)\(0x([0-9A-Fa-f]+)\)"
)
RefBitfieldRe = re.compile(
    r"^\s*(\w[\w<>:\*]*)\s+(\w+)\s*:\s*\d+\s*;\s*"
    r"//\s*0x([0-9A-Fa-f]+)\(0x([0-9A-Fa-f]+)\)"
)
RefEnumOpenRe = re.compile(
    r"^enum(?:\s+class)?\s+(\w+)(?:\s*:\s*[\w\s]+)?\s*\{?\s*$"
)
RefEnumMemberRe = re.compile(
    r"^\s*(\w+)\s*=\s*(-?\d+|0x[0-9A-Fa-f]+)\s*,?"
)


def strip_name_prefix(name):
    if len(name) >= 2 and name[0] in "FUAE" and name[1].isupper():
        return name[1:]
    return name


def make_entry(kind):
    return {
        "kind": kind,
        "parent": None,
        "fields": OrderedDict(),
        "enum_members": OrderedDict(),
        "functions": set(),
    }


def parse_flat(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    model = OrderedDict()
    pending_kind = None
    pending_parent = None
    pending_inherit_chain = []
    cur_ns = None
    cur_entry = None
    in_functions_block = False

    for raw in lines:
        line = raw.rstrip("\n")

        m = FlatHeaderRe.match(line)
        if m:
            pending_kind = m.group(1)
            pending_parent = None
            pending_inherit_chain = []
            in_functions_block = False
            continue

        m = FlatInheritsRe.match(line)
        if m:
            pending_parent = m.group(1)
            continue

        m = FlatInheritChainStepRe.match(line)
        if m and pending_kind == "Class" and pending_parent is None:
            cand = m.group(1)
            if cand != "Unknown":
                pending_inherit_chain.append(cand)
            continue

        m = FlatNamespaceOpenRe.match(line)
        if m:
            ns_name = m.group(1)
            if ns_name in ("ARC", "Enums", "Types", "Structs", "Classes", "Functions"):
                continue
            kind = pending_kind or "Class"
            entry = make_entry(kind)
            if pending_parent:
                entry["parent"] = pending_parent
            elif pending_inherit_chain:
                entry["parent"] = pending_inherit_chain[0]
            model[ns_name] = entry
            cur_ns = ns_name
            cur_entry = entry
            pending_kind = None
            pending_parent = None
            pending_inherit_chain = []
            in_functions_block = False
            continue

        m = FlatNamespaceCloseRe.match(line)
        if m:
            cur_ns = None
            cur_entry = None
            in_functions_block = False
            continue

        if cur_entry is None:
            continue

        if FlatFunctionsHeaderRe.match(line):
            in_functions_block = True
            continue

        if cur_entry["kind"] == "Enum":
            em = FlatEnumMemberRe.match(line)
            if em:
                cur_entry["enum_members"][em.group(1)] = em.group(2)
            continue

        if not in_functions_block:
            fm = FlatFieldRe.match(line)
            if fm:
                fname = fm.group(1)
                foff = int(fm.group(2), 16)
                ftype = fm.group(3).strip()
                cur_entry["fields"][fname] = {"offset": foff, "type": ftype}
                continue

        if in_functions_block and line.strip().startswith("//"):
            continue
        if in_functions_block:
            sm = FlatFunctionSigRe.match(line)
            if sm:
                cur_entry["functions"].add(sm.group(1))

    return model


def parse_refdir(path):
    model = OrderedDict()
    files = sorted(glob(os.path.join(path, "*.hpp")) + glob(os.path.join(path, "**/*.hpp"), recursive=True))
    seen = set()

    for fp in files:
        if fp in seen:
            continue
        seen.add(fp)
        try:
            with open(fp, encoding="utf-8", errors="replace") as f:
                content = f.readlines()
        except OSError:
            continue

        cur_struct = None
        cur_parent = None
        cur_kind = None
        brace_depth = 0
        in_body = False
        cur_enum = None

        for raw in content:
            line = raw.rstrip("\n")
            stripped = line.strip()

            if cur_enum is None:
                em = RefEnumOpenRe.match(stripped)
                if em and "{" in line:
                    name = em.group(1)
                    short = strip_name_prefix(name)
                    entry = make_entry("Enum")
                    model[short] = entry
                    cur_enum = entry
                    continue

            if cur_enum is not None:
                mm = RefEnumMemberRe.match(stripped)
                if mm:
                    cur_enum["enum_members"][mm.group(1)] = mm.group(2)
                if "}" in line:
                    cur_enum = None
                continue

            sm = RefStructOpenRe.match(stripped)
            if sm and not in_body:
                raw_name = sm.group(1)
                if not raw_name or raw_name[0] not in "FUAE":
                    continue
                cur_struct = strip_name_prefix(raw_name)
                cur_parent = sm.group(2)
                if cur_parent:
                    cur_parent = strip_name_prefix(cur_parent)
                cur_kind = "Struct" if raw_name.startswith("F") else "Class"
                in_body = True
                brace_depth = 0
                continue

            if in_body:
                brace_depth += line.count("{") - line.count("}")
                if cur_struct is not None:
                    if cur_struct not in model:
                        entry = make_entry(cur_kind)
                        entry["parent"] = cur_parent
                        model[cur_struct] = entry
                    entry = model[cur_struct]

                    fm = RefBitfieldRe.match(line)
                    if fm:
                        ftype, fname, foff, _fsize = fm.groups()
                        entry["fields"][fname] = {
                            "offset": int(foff, 16),
                            "type": f"{ftype} (bitfield)",
                        }
                    else:
                        fm = RefFieldRe.match(line)
                        if fm:
                            ftype, fname, foff, _fsize = fm.groups()
                            entry["fields"][fname] = {
                                "offset": int(foff, 16),
                                "type": ftype.strip(),
                            }

                if brace_depth < 0 or stripped == "};":
                    in_body = False
                    cur_struct = None
                    cur_parent = None
                    cur_kind = None
                    brace_depth = 0

    return model


def load_sdk(path):
    if os.path.isdir(path):
        return parse_refdir(path)
    if os.path.isfile(path):
        return parse_flat(path)
    raise FileNotFoundError(path)


def diff_namespace(old_entry, new_entry):
    diffs = {
        "kind_changed": None,
        "parent_changed": None,
        "added_fields": [],
        "removed_fields": [],
        "offset_changes": [],
        "type_changes": [],
        "added_enum_members": [],
        "removed_enum_members": [],
        "enum_value_changes": [],
        "added_functions": [],
        "removed_functions": [],
    }

    if old_entry["kind"] != new_entry["kind"]:
        diffs["kind_changed"] = (old_entry["kind"], new_entry["kind"])

    if (old_entry["parent"] or "") != (new_entry["parent"] or ""):
        if old_entry["kind"] == "Class" or new_entry["kind"] == "Class":
            diffs["parent_changed"] = (old_entry["parent"], new_entry["parent"])

    old_fields = old_entry["fields"]
    new_fields = new_entry["fields"]
    old_names = set(old_fields)
    new_names = set(new_fields)

    for fname in sorted(new_names - old_names):
        f = new_fields[fname]
        diffs["added_fields"].append((fname, f["offset"], f["type"]))
    for fname in sorted(old_names - new_names):
        f = old_fields[fname]
        diffs["removed_fields"].append((fname, f["offset"], f["type"]))
    for fname in sorted(old_names & new_names):
        of = old_fields[fname]
        nf = new_fields[fname]
        if of["offset"] != nf["offset"]:
            diffs["offset_changes"].append((fname, of["offset"], nf["offset"]))
        if of["type"] != nf["type"]:
            diffs["type_changes"].append((fname, of["type"], nf["type"]))

    old_em = old_entry["enum_members"]
    new_em = new_entry["enum_members"]
    for k in sorted(set(new_em) - set(old_em)):
        diffs["added_enum_members"].append((k, new_em[k]))
    for k in sorted(set(old_em) - set(new_em)):
        diffs["removed_enum_members"].append((k, old_em[k]))
    for k in sorted(set(old_em) & set(new_em)):
        if old_em[k] != new_em[k]:
            diffs["enum_value_changes"].append((k, old_em[k], new_em[k]))

    for fn in sorted(new_entry["functions"] - old_entry["functions"]):
        diffs["added_functions"].append(fn)
    for fn in sorted(old_entry["functions"] - new_entry["functions"]):
        diffs["removed_functions"].append(fn)

    return diffs


def is_empty_diff(d):
    return (
        d["kind_changed"] is None
        and d["parent_changed"] is None
        and not d["added_fields"]
        and not d["removed_fields"]
        and not d["offset_changes"]
        and not d["type_changes"]
        and not d["added_enum_members"]
        and not d["removed_enum_members"]
        and not d["enum_value_changes"]
        and not d["added_functions"]
        and not d["removed_functions"]
    )


def format_namespace_block(name, old_entry, new_entry, diffs):
    out = []
    kind = (new_entry or old_entry)["kind"]
    header = f"{colorize('[' + kind + ']', 'cyan')} {colorize(name, 'bold')}"
    out.append(header)

    if diffs["kind_changed"]:
        a, b = diffs["kind_changed"]
        out.append(f"  {colorize('kind:', 'yellow')} {a} -> {b}")
    if diffs["parent_changed"]:
        a, b = diffs["parent_changed"]
        out.append(
            f"  {colorize('inherit:', 'magenta')} "
            f"{colorize(a or '(none)', 'red')} -> {colorize(b or '(none)', 'green')}"
        )

    for fname, oo, no in diffs["offset_changes"]:
        delta = no - oo
        sign = "+" if delta >= 0 else "-"
        out.append(
            f"  {colorize('~offset', 'yellow')} {fname:<48} "
            f"0x{oo:X} -> 0x{no:X}  ({sign}0x{abs(delta):X})"
        )
    for fname, ot, nt in diffs["type_changes"]:
        out.append(
            f"  {colorize('~type  ', 'magenta')} {fname:<48} "
            f"{ot} -> {nt}"
        )
    for fname, off, ftype in diffs["added_fields"]:
        out.append(
            f"  {colorize('+field ', 'green')} {fname:<48} "
            f"0x{off:X}  // {ftype}"
        )
    for fname, off, ftype in diffs["removed_fields"]:
        out.append(
            f"  {colorize('-field ', 'red')} {fname:<48} "
            f"0x{off:X}  // {ftype}"
        )
    for k, v in diffs["added_enum_members"]:
        out.append(f"  {colorize('+enum  ', 'green')} {k} = {v}")
    for k, v in diffs["removed_enum_members"]:
        out.append(f"  {colorize('-enum  ', 'red')} {k} = {v}")
    for k, ov, nv in diffs["enum_value_changes"]:
        out.append(
            f"  {colorize('~enum  ', 'yellow')} {k:<40} {ov} -> {nv}"
        )
    for fn in diffs["added_functions"]:
        out.append(f"  {colorize('+func  ', 'green')} {fn}")
    for fn in diffs["removed_functions"]:
        out.append(f"  {colorize('-func  ', 'red')} {fn}")

    return "\n".join(out)


def run_diff(old_path, new_path, filter_re, summary_only):
    sys.stderr.write(colorize(f"[+] loading old: {old_path}\n", "dim"))
    old_model = load_sdk(old_path)
    sys.stderr.write(colorize(f"[+] loading new: {new_path}\n", "dim"))
    new_model = load_sdk(new_path)
    sys.stderr.write(
        colorize(
            f"[+] old namespaces: {len(old_model)}  new namespaces: {len(new_model)}\n",
            "dim",
        )
    )

    old_names = set(old_model)
    new_names = set(new_model)
    added = sorted(new_names - old_names)
    removed = sorted(old_names - new_names)
    shared = sorted(old_names & new_names)

    if filter_re is not None:
        added = [n for n in added if filter_re.search(n)]
        removed = [n for n in removed if filter_re.search(n)]
        shared = [n for n in shared if filter_re.search(n)]

    per_ns_diffs = []
    total_offset_changes = 0
    total_type_changes = 0
    total_added_fields = 0
    total_removed_fields = 0
    total_parent_changes = 0
    changed_namespaces = 0

    for name in shared:
        d = diff_namespace(old_model[name], new_model[name])
        if is_empty_diff(d):
            continue
        changed_namespaces += 1
        total_offset_changes += len(d["offset_changes"])
        total_type_changes += len(d["type_changes"])
        total_added_fields += len(d["added_fields"])
        total_removed_fields += len(d["removed_fields"])
        if d["parent_changed"]:
            total_parent_changes += 1
        per_ns_diffs.append((name, d))

    out = []
    out.append(colorize("=" * 72, "dim"))
    out.append(colorize("  SDK Diff Summary", "bold"))
    out.append(colorize("=" * 72, "dim"))
    out.append(f"  old: {old_path}")
    out.append(f"  new: {new_path}")
    out.append("")
    out.append(f"  {colorize('+', 'green')} namespaces added   : {len(added)}")
    out.append(f"  {colorize('-', 'red')} namespaces removed : {len(removed)}")
    out.append(f"  {colorize('~', 'yellow')} namespaces changed : {changed_namespaces}")
    out.append("")
    out.append(f"  offset changes      : {colorize(str(total_offset_changes), 'yellow')}")
    out.append(f"  type   changes      : {colorize(str(total_type_changes), 'magenta')}")
    out.append(f"  fields added        : {colorize(str(total_added_fields), 'green')}")
    out.append(f"  fields removed      : {colorize(str(total_removed_fields), 'red')}")
    out.append(f"  inheritance changes : {colorize(str(total_parent_changes), 'magenta')}")
    out.append(colorize("=" * 72, "dim"))
    out.append("")

    print("\n".join(out))

    if summary_only:
        return 0

    if added:
        print(colorize("---- Added namespaces ----", "green"))
        for n in added:
            kind = new_model[n]["kind"]
            parent = new_model[n]["parent"]
            extra = f" : {parent}" if parent else ""
            nf = len(new_model[n]["fields"])
            nem = len(new_model[n]["enum_members"])
            print(f"  {colorize('+', 'green')} [{kind}] {n}{extra}  (fields={nf}, enums={nem})")
        print()

    if removed:
        print(colorize("---- Removed namespaces ----", "red"))
        for n in removed:
            kind = old_model[n]["kind"]
            parent = old_model[n]["parent"]
            extra = f" : {parent}" if parent else ""
            nf = len(old_model[n]["fields"])
            nem = len(old_model[n]["enum_members"])
            print(f"  {colorize('-', 'red')} [{kind}] {n}{extra}  (fields={nf}, enums={nem})")
        print()

    if per_ns_diffs:
        print(colorize("---- Changed namespaces ----", "yellow"))
        for name, d in per_ns_diffs:
            block = format_namespace_block(name, old_model[name], new_model[name], d)
            print(block)
            print()

    return 0


def main(argv):
    global UseColor
    ap = argparse.ArgumentParser(
        prog="sdk_diff.py",
        description="Diff two FrostDumper SDK_Output.txt files or refSDK directories.",
    )
    ap.add_argument("old", help="old SDK_Output.txt or refSDK directory")
    ap.add_argument("new", help="new SDK_Output.txt or refSDK directory")
    ap.add_argument("--filter", default=None, help="regex limiting which namespaces are reported")
    ap.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    ap.add_argument("--summary-only", action="store_true", help="print only the summary block")
    args = ap.parse_args(argv)

    if args.no_color or not sys.stdout.isatty():
        UseColor = False

    filter_re = re.compile(args.filter) if args.filter else None

    try:
        return run_diff(args.old, args.new, filter_re, args.summary_only)
    except FileNotFoundError as e:
        sys.stderr.write(f"error: {e}\n")
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
