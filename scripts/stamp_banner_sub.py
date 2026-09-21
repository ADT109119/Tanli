#!/usr/bin/env python3
"""壓 subtitle 到去字 banner：真字體渲染（Noto Sans CJK TC），非 AI 生成文字。
auto-fit + 兩端對齊：文字總寬恰好等於主標題寬（不超出主標題左右界線）。
用法: python3 stamp_fit.py <in.png> <out.png> <subtitle> <x0> <x1> [size]
"""
import os
import sys
from PIL import Image, ImageDraw, ImageFont

# 字型解析：環境變數 STAMP_FONT > ~/.fonts/ 慣例位置（不硬編碼個人帳號路徑）
_FONT_CANDIDATES = [
    os.environ.get("STAMP_FONT", ""),
    os.path.expanduser("~/.fonts/NotoSansCJKtc-Regular.otf"),
]
FONT = next((p for p in _FONT_CANDIDATES if p and os.path.exists(p)), _FONT_CANDIDATES[1])
MIN_SIZE = 16


def measure(d, text, font, tracking):
    total = 0.0
    for i, ch in enumerate(text):
        total += d.textlength(ch, font=font)
        if i < len(text) - 1:
            total += font.size * tracking
    return total


def draw_tracked(d, xy, text, font, fill, tracking):
    x, y = xy
    for ch in text:
        d.text((x, y), ch, font=font, fill=fill)
        x += d.textlength(ch, font=font) + font.size * tracking
    return x


def main():
    src, dst, text = sys.argv[1], sys.argv[2], sys.argv[3]
    x0, x1 = int(sys.argv[4]), int(sys.argv[5])
    size = int(sys.argv[6]) if len(sys.argv) > 6 else 28
    y0 = int(sys.argv[7]) if len(sys.argv) > 7 else 430
    fill = (101, 112, 109, 255)

    im = Image.open(src).convert("RGBA")
    layer = Image.new("RGBA", im.size, (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    target_w = x1 - x0

    # 1) auto-fit：字級從大到小，直到零字距自然寬 <= 目標寬
    while size > MIN_SIZE and measure(d, text, ImageFont.truetype(FONT, size), 0.0) > target_w:
        size -= 1
    font = ImageFont.truetype(FONT, size)
    natural = measure(d, text, font, 0.0)
    # 2) 其餘空間平均分配為字距 → 兩端恰好對齊 x0/x1
    n = len(text) - 1
    tracking_px = (target_w - natural) / n if n else 0.0
    end_x = draw_tracked(d, (x0, y0), text, font, fill, tracking_px / size)

    out = Image.alpha_composite(im, layer).convert("RGB")
    out.save(dst, quality=92)
    print(f"STAMPED {dst} size={size} natural={natural:.0f} target={target_w} "
          f"track/char={tracking_px:.1f}px end_x={end_x:.0f}")


if __name__ == "__main__":
    main()
