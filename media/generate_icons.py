#!/usr/bin/env python3
"""Generate QuantaVNC icon files (ICO + PNG) using PIL.

Produces a shield shape in dark navy (#0a1628) with a cyan "Q" (#00e5ff),
matching the SVG logo design. Generates:
  - media/icons/quantavnc.ico  (16, 24, 32, 48, 256)
  - media/icons/quantavnc_*.png (16, 22, 24, 32, 48, 64, 128)
  - java/com/tigervnc/vncviewer/quantavnc.ico (copy)
  - java/com/tigervnc/vncviewer/quantavnc.png (48x48 copy)
"""

import math
import os
import shutil
from PIL import Image, ImageDraw, ImageFont


# Colors matching the SVG
BG_DARK = (10, 22, 40)        # #0a1628
CYAN = (0, 229, 255)          # #00e5ff
CYAN_GLOW = (0, 229, 255, 80) # glow effect
SHIELD_BORDER = (0, 180, 220) # border highlight


def draw_shield(draw, w, h, fill, outline=None, outline_width=1):
    """Draw a shield shape that fills the given width/height."""
    # Shield: rounded top, pointed bottom
    cx, cy = w / 2, h / 2
    # Inset slightly
    margin = max(1, w * 0.06)
    left = margin
    right = w - margin
    top = margin
    bottom = h - margin * 0.5

    # Shield proportions
    shield_top = top + h * 0.02
    shield_shoulder = top + h * 0.35
    shield_bottom = bottom
    corner_r = w * 0.12

    points = []
    # Top-left corner (rounded)
    for angle in range(180, 271, 5):
        rad = math.radians(angle)
        px = left + corner_r + corner_r * math.cos(rad)
        py = shield_top + corner_r + corner_r * math.sin(rad)
        points.append((px, py))
    # Top-right corner (rounded)
    for angle in range(270, 361, 5):
        rad = math.radians(angle)
        px = right - corner_r + corner_r * math.cos(rad)
        py = shield_top + corner_r + corner_r * math.sin(rad)
        points.append((px, py))
    # Right side down to shoulder
    points.append((right, shield_shoulder))
    # Curve down to point
    for t in [i / 20.0 for i in range(21)]:
        # Quadratic bezier: right side -> bottom point
        px = (1 - t) ** 2 * right + 2 * (1 - t) * t * (right * 0.6) + t ** 2 * cx
        py = (1 - t) ** 2 * shield_shoulder + 2 * (1 - t) * t * (shield_bottom * 0.85) + t ** 2 * shield_bottom
        points.append((px, py))
    # Bottom point to left side
    for t in [i / 20.0 for i in range(21)]:
        px = (1 - t) ** 2 * cx + 2 * (1 - t) * t * (left * 0.4 + cx * 0.6) + t ** 2 * left
        py = (1 - t) ** 2 * shield_bottom + 2 * (1 - t) * t * (shield_bottom * 0.85) + t ** 2 * shield_shoulder
        points.append((px, py))
    # Left side up
    points.append((left, shield_shoulder))
    points.append((left, shield_top + corner_r))

    draw.polygon(points, fill=fill, outline=outline)

    # Draw outline with width if requested
    if outline and outline_width > 1:
        for i in range(outline_width):
            # Scale points slightly for outline passes
            pass  # PIL polygon outline is 1px, good enough for small icons


def draw_letter_q(draw, w, h, color):
    """Draw a stylized 'Q' letter centered in the shield."""
    cx, cy = w / 2, h / 2
    # Q circle center - slightly above center of shield
    qcx = cx
    qcy = cy * 0.88
    radius = w * 0.22

    # Try to use a font
    font = None
    font_size = int(w * 0.52)

    # Try common font paths
    font_paths = [
        "C:/Windows/Fonts/arialbd.ttf",
        "C:/Windows/Fonts/arial.ttf",
        "C:/Windows/Fonts/segoeui.ttf",
        "C:/Windows/Fonts/calibrib.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/System/Library/Fonts/Helvetica.ttc",
    ]

    for fp in font_paths:
        try:
            font = ImageFont.truetype(fp, font_size)
            break
        except (IOError, OSError):
            continue

    if font is None:
        # Fallback: draw Q as circle + tail
        line_w = max(1, int(w * 0.06))
        # Outer circle
        draw.ellipse(
            [qcx - radius, qcy - radius, qcx + radius, qcy + radius],
            outline=color, width=line_w
        )
        # Q tail - diagonal line from lower-right of circle
        tail_start_x = qcx + radius * 0.5
        tail_start_y = qcy + radius * 0.5
        tail_end_x = qcx + radius * 1.1
        tail_end_y = qcy + radius * 1.2
        draw.line(
            [tail_start_x, tail_start_y, tail_end_x, tail_end_y],
            fill=color, width=line_w
        )
    else:
        # Use font to draw Q
        text = "Q"
        bbox = draw.textbbox((0, 0), text, font=font)
        tw = bbox[2] - bbox[0]
        th = bbox[3] - bbox[1]
        tx = qcx - tw / 2 - bbox[0]
        ty = qcy - th / 2 - bbox[1]
        draw.text((tx, ty), text, fill=color, font=font)


def generate_icon(size):
    """Generate a single icon image at the given size."""
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Draw shield background with slight glow effect
    # First draw a slightly larger, semi-transparent version for glow
    if size >= 32:
        glow_img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        glow_draw = ImageDraw.Draw(glow_img)
        draw_shield(glow_draw, size, size, fill=(0, 60, 80, 40))
        img = Image.alpha_composite(img, glow_img)
        draw = ImageDraw.Draw(img)

    # Draw main shield
    draw_shield(draw, size, size, fill=BG_DARK + (255,), outline=SHIELD_BORDER + (200,))

    # Draw the Q
    draw_letter_q(draw, size, size, CYAN)

    return img


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    icons_dir = os.path.join(script_dir, "icons")
    java_dir = os.path.join(script_dir, "..", "java", "com", "tigervnc", "vncviewer")

    os.makedirs(icons_dir, exist_ok=True)

    # Windows ICO sizes
    ico_sizes = [16, 24, 32, 48, 256]
    # Linux PNG sizes
    linux_sizes = [16, 22, 24, 32, 48, 64, 128]
    # All unique sizes needed
    all_sizes = sorted(set(ico_sizes + linux_sizes))

    # Generate all sizes
    images = {}
    for size in all_sizes:
        img = generate_icon(size)
        images[size] = img
        # Save individual PNGs for Linux
        png_path = os.path.join(icons_dir, f"quantavnc_{size}.png")
        img.save(png_path, "PNG")
        print(f"  Created: icons/quantavnc_{size}.png ({size}x{size})")

    # Generate ICO with multiple resolutions
    ico_path = os.path.join(icons_dir, "quantavnc.ico")
    # PIL's ICO save wants the largest image, with sizes param for included sizes
    ico_images = [images[s] for s in ico_sizes]
    # Save ICO - use the largest as base, include all sizes
    images[256].save(
        ico_path,
        format="ICO",
        sizes=[(s, s) for s in ico_sizes],
        append_images=[images[s] for s in ico_sizes if s != 256]
    )
    print(f"  Created: icons/quantavnc.ico (sizes: {ico_sizes})")

    # Also save the scalable SVG reference PNG (128x128) as the main quantavnc.png
    # This is used by vncviewer on Linux
    main_png = os.path.join(icons_dir, "quantavnc.png")
    images[128].save(main_png, "PNG")
    print(f"  Created: icons/quantavnc.png (128x128)")

    # Copy to Java directory
    if os.path.isdir(java_dir):
        java_ico = os.path.join(java_dir, "quantavnc.ico")
        java_png = os.path.join(java_dir, "quantavnc.png")
        shutil.copy2(ico_path, java_ico)
        images[48].save(java_png, "PNG")
        print(f"  Created: java/.../quantavnc.ico (copy)")
        print(f"  Created: java/.../quantavnc.png (48x48)")

    print("\nDone! All QuantaVNC icons generated.")


if __name__ == "__main__":
    main()
