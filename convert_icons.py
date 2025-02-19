#!/usr/bin/env python3
import sys
from pathlib import Path
try:
    import cairosvg
except ImportError:
    print("Please install cairosvg first:")
    print("pip install cairosvg")
    sys.exit(1)

icons_dir = Path("src/gui/resources/icons")

if not icons_dir.exists():
    print("Icons directory not found. Please run icons.py first.")
    sys.exit(1)

for svg_file in icons_dir.glob("*.svg"):
    png_file = svg_file.with_suffix(".png")
    print(f"Converting {svg_file.name} to {png_file.name}")
    cairosvg.svg2png(
        url=str(svg_file),
        write_to=str(png_file),
        output_width=24,
        output_height=24
    )

# Also update the resources.qrc file
qrc_content = '''<?xml version="1.0" encoding="UTF-8"?>
<RCC>
    <qresource prefix="/">
'''

for png_file in sorted(icons_dir.glob("*.png")):
    qrc_content += f'        <file>resources/icons/{png_file.name}</file>\n'

qrc_content += '''    </qresource>
</RCC>
'''

with open("src/gui/resources.qrc", "w") as f:
    f.write(qrc_content)

print("\nAll SVG files have been converted to PNG.")
print("Resources file (resources.qrc) has been updated.")
print("Icons are ready to be used in the application.")
