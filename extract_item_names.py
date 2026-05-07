#!/usr/bin/env python3
"""
Simple Item Names Extractor
Extracts just the item names from /Game/Pioneer/Items/* paths
"""

import re
from pathlib import Path

def extract_item_names():
    """Extract unique item names from dump_objects.txt"""
    dump_file = Path("dump_objects.txt")
    item_names = set()

    print(f"📖 Reading {dump_file}...")

    with open(dump_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            # Look for /Game/Pioneer/Items/ paths
            match = re.search(r'/Game/Pioneer/Items/([^/]+)/([^/]+)/', line)
            if match:
                category = match.group(1)
                item_name = match.group(2)

                # Skip if it's just a file extension or asset type
                if not item_name.startswith(('DA_', 'BP_', 'SM_', 'MI_', 'T_', 'SK_')):
                    item_names.add(item_name)

    return sorted(item_names)

def main():
    print("🎯 Extracting Item Names...")

    # Extract names
    item_names = extract_item_names()

    # Save to text file
    with open("item_names_only.txt", 'w', encoding='utf-8') as f:
        f.write("ARC Raiders - Item Names Only\n")
        f.write("=" * 40 + "\n\n")
        f.write(f"Total Items: {len(item_names)}\n\n")

        for name in item_names:
            f.write(f"{name}\n")

    print(f"✅ Found {len(item_names)} unique item names")
    print(f"💾 Saved to item_names_only.txt")

if __name__ == "__main__":
    main()