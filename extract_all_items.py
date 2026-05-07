#!/usr/bin/env python3
"""
ARC Raiders Item Extractor
Extracts all items from /Game/Pioneer/Items/* and organizes them by category
"""

import re
import json
from pathlib import Path
from collections import defaultdict

class ItemExtractor:
    def __init__(self, dump_file="dump_objects.txt"):
        self.dump_file = Path(dump_file)
        self.items = defaultdict(list)
        self.all_items = []

    def extract_items(self):
        """Extract all /Game/Pioneer/Items/* entries from dump file"""
        print(f"📖 Reading {self.dump_file}...")

        with open(self.dump_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                # Look for /Game/Pioneer/Items/ paths
                match = re.search(r'/Game/Pioneer/Items/([^|]+)', line)
                if match:
                    full_path = match.group(0)
                    # Extract category (first subdirectory after Items/)
                    path_parts = full_path.split('/')
                    if len(path_parts) >= 5:  # /Game/Pioneer/Items/Category/...
                        category = path_parts[4]
                        asset_name = path_parts[-1]  # Last part of path

                        item_data = {
                            "full_path": full_path,
                            "category": category,
                            "asset_name": asset_name,
                            "line_number": line_num,
                            "raw_line": line.strip()
                        }

                        self.items[category].append(item_data)
                        self.all_items.append(item_data)

        print(f"✅ Found {len(self.all_items)} items in {len(self.items)} categories")

    def save_to_json(self, filename="all_pioneer_items.json"):
        """Save organized items to JSON"""
        output = {
            "metadata": {
                "total_items": len(self.all_items),
                "categories": list(self.items.keys()),
                "category_counts": {cat: len(items) for cat, items in self.items.items()}
            },
            "items_by_category": dict(self.items),
            "firearms": self.get_firearms_detailed()
        }

        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2, ensure_ascii=False)

        print(f"💾 JSON saved to {filename}")

    def save_to_text(self, filename="all_pioneer_items.txt"):
        """Save all items to organized text file"""
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("ARC Raiders - All /Game/Pioneer/Items/* Assets\n")
            f.write("=" * 60 + "\n\n")

            # Summary
            f.write(f"Total Items: {len(self.all_items)}\n")
            f.write(f"Categories: {len(self.items)}\n\n")

            # Category breakdown
            f.write("CATEGORY BREAKDOWN:\n")
            f.write("-" * 20 + "\n")
            for category, items in sorted(self.items.items(), key=lambda x: len(x[1]), reverse=True):
                f.write(f"{category:25} : {len(items):5} items\n")
            f.write("\n")

            # Detailed listings
            for category, items in sorted(self.items.items()):
                f.write(f"\n{'=' * 60}\n")
                f.write(f"CATEGORY: {category.upper()} ({len(items)} items)\n")
                f.write(f"{'=' * 60}\n\n")

                # Group by asset type
                asset_types = defaultdict(list)
                for item in items:
                    # Extract asset type (DA_, BP_, SM_, MI_, T_, etc.)
                    asset_name = item['asset_name']
                    if asset_name.startswith(('DA_', 'BP_', 'SM_', 'MI_', 'T_', 'SK_', 'WABP_')):
                        prefix = asset_name.split('_')[0]
                        asset_types[prefix].append(item)
                    else:
                        asset_types['Other'].append(item)

                for asset_type, type_items in sorted(asset_types.items()):
                    if type_items:
                        f.write(f"\n{asset_type} Assets ({len(type_items)} items):\n")
                        f.write("-" * 30 + "\n")
                        for item in sorted(type_items, key=lambda x: x['asset_name']):
                            f.write(f"  {item['asset_name']}\n")

            # Full path listings
            f.write(f"\n\n{'=' * 60}\n")
            f.write("FULL PATHS (All Items)\n")
            f.write(f"{'=' * 60}\n\n")

            for item in sorted(self.all_items, key=lambda x: x['full_path']):
                f.write(f"{item['full_path']}\n")

        print(f"📝 Text file saved to {filename}")

    def get_firearms_detailed(self):
        """Get detailed firearms breakdown"""
        if 'Firearms' not in self.items:
            return {}

        firearms = defaultdict(lambda: defaultdict(list))

        for item in self.items['Firearms']:
            path_parts = item['full_path'].split('/')
            if len(path_parts) >= 6:
                weapon_type = path_parts[5]  # e.g., AssaultRifle_LowTier_01
                asset_name = item['asset_name']

                # Categorize by asset type
                if asset_name.startswith('DA_Item_'):
                    firearms[weapon_type]['data_assets'].append(asset_name)
                elif asset_name.startswith('BP_'):
                    firearms[weapon_type]['blueprints'].append(asset_name)
                elif asset_name.startswith('SM_'):
                    firearms[weapon_type]['static_meshes'].append(asset_name)
                elif asset_name.startswith('MI_'):
                    firearms[weapon_type]['materials'].append(asset_name)
                elif asset_name.startswith('T_'):
                    firearms[weapon_type]['textures'].append(asset_name)
                elif asset_name.startswith('SK_'):
                    firearms[weapon_type]['skeletons'].append(asset_name)
                elif asset_name.startswith('DA_'):
                    firearms[weapon_type]['other_data_assets'].append(asset_name)
                else:
                    firearms[weapon_type]['other'].append(asset_name)

        return dict(firearms)

    def print_summary(self):
        """Print summary to console"""
        print("\n🎯 EXTRACTION SUMMARY")
        print("=" * 50)
        print(f"Total Items Found: {len(self.all_items)}")
        print(f"Categories: {len(self.items)}")
        print("\nTop Categories:")
        for category, items in sorted(self.items.items(), key=lambda x: len(x[1]), reverse=True)[:10]:
            print(f"  {category:20} : {len(items):5} items")

        # Firearms breakdown if available
        if 'Firearms' in self.items:
            print(f"\n🔫 FIREARMS BREAKDOWN:")
            firearms_detailed = self.get_firearms_detailed()
            for weapon, assets in sorted(firearms_detailed.items()):
                total_assets = sum(len(asset_list) for asset_list in assets.values())
                print(f"  {weapon:30} : {total_assets:3} assets")

def main():
    print("🚀 ARC Raiders Item Extractor")
    print("=" * 40)

    # Initialize extractor
    extractor = ItemExtractor()

    # Extract all items
    extractor.extract_items()

    # Save outputs
    extractor.save_to_json("all_pioneer_items.json")
    extractor.save_to_text("all_pioneer_items.txt")

    # Print summary
    extractor.print_summary()

    print(f"\n✅ COMPLETE!")
    print(f"📁 Files created:")
    print(f"   - all_pioneer_items.json (structured data)")
    print(f"   - all_pioneer_items.txt (readable text)")

if __name__ == "__main__":
    main()