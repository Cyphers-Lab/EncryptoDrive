#!/usr/bin/env python3
import os
from pathlib import Path

# Create icons directory in resources folder
icons_dir = Path("src/gui/resources/icons")
icons_dir.mkdir(parents=True, exist_ok=True)

# Basic SVG template
SVG_TEMPLATE = '''<?xml version="1.0" encoding="UTF-8"?>
<svg width="24" height="24" version="1.1" xmlns="http://www.w3.org/2000/svg">
    {content}
</svg>'''

# Icon definitions (same as before)
ICONS = {
    "drive": '''<path fill="#000" d="M4 4v16h16V4H4zm2 2h12v8H6V6zm0 10h12v2H6v-2zm2-7h2v2H8V9zm8 0h2v2h-2V9z"/>''',
    "new": '''<path fill="#000" d="M11 3v8H3v2h8v8h2v-8h8v-2h-8V3h-2z"/>''',
    "open": '''<path fill="#000" d="M4 4v16h16V8h-8l-2-2H4zm2 4h4l2 2h6v4H6V8z"/>''',
    "close": '''<path fill="#000" d="M6 6l12 12m0-12L6 18" stroke="#000" stroke-width="2"/>''',
    "eject": '''<path fill="#000" d="M12 5L4 15h16L12 5zm0 11v3h8v-3h-8z"/>''',
    "mount": '''<path fill="#000" d="M12 3L4 15h16L12 3zm0 13v5h8v-5h-8z"/>''',
    "unmount": '''<path fill="#000" d="M12 21l8-12H4l8 12zm0-13V3H4v5h8z"/>''',
    "refresh": '''<path fill="none" stroke="#000" stroke-width="2" d="M4 12a8 8 0 1 1 8 8m0-8l4-4m-4 4l4 4"/>''',
    "settings": '''<path fill="#000" d="M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8zm-6 4a6 6 0 1 1 12 0 6 6 0 0 1-12 0z M11 2h2v4h-2zM11 18h2v4h-2zM2 11v2h4v-2zM18 11v2h4v-2z"/>''',
    "password": '''<path fill="#000" d="M12 2a5 5 0 0 0-5 5v3H5v12h14V10h-2V7a5 5 0 0 0-5-5zm0 2a3 3 0 0 1 3 3v3H9V7a3 3 0 0 1 3-3z"/>''',
    "keys": '''<path fill="#000" d="M7 14a3 3 0 1 1 0-6 3 3 0 0 1 0 6zm0-2a1 1 0 1 0 0-2 1 1 0 0 0 0 2zm5-1h8v2h-8z"/>''',
    "import": '''<path fill="#000" d="M12 3L4 9h4v7h8V9h4L12 3zm0 14v4h8v-4h-8z"/>''',
    "export": '''<path fill="#000" d="M12 21l8-6h-4V8H8v7H4l8 6zm0-14V3H4v4h8z"/>''',
    "help": '''<path fill="#000" d="M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zm0 18a8 8 0 1 1 0-16 8 8 0 0 1 0 16zm-1-8v5h2v-5h-2zm0-5v2h2V7h-2z"/>''',
    "about": '''<path fill="#000" d="M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zm0 18a8 8 0 1 1 0-16 8 8 0 0 1 0 16zm-1-8v5h2v-5h-2zm0-5v2h2V7h-2z"/>''',
    "update": '''<path fill="#000" d="M12 2v4l3-3a7 7 0 1 1-7 7H4a9 9 0 1 0 9-9z"/>''',
    "quit": '''<path fill="#000" d="M4 4v16h8v-2H6V6h6V4H4zm8 7l4 3-4 3v-2H8v-2h4v-2z"/>'''
}

# Generate SVG files
for name, content in ICONS.items():
    svg_content = SVG_TEMPLATE.format(content=content)
    with open(icons_dir / f"{name}.svg", "w") as f:
        f.write(svg_content)

print("Created SVG icons in", icons_dir)
