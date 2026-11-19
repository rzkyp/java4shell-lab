#!/usr/bin/env python3
"""Generate Java4Shell banner.png + logo.png (Pillow, stdlib-friendly)."""
from PIL import Image, ImageDraw, ImageFont
from pathlib import Path

HERE = Path(__file__).resolve().parent
F_BOLD = "C:/Windows/Fonts/arialbd.ttf"
F_REG = "C:/Windows/Fonts/arial.ttf"
F_MONO = "C:/Windows/Fonts/consola.ttf"

ORANGE = (255, 107, 53)
RED = (248, 81, 73)
WHITE = (230, 237, 243)
GREY = (139, 148, 158)
DARK = (13, 17, 23)


def vgrad(w, h, top, bot):
    img = Image.new("RGB", (w, h))
    d = ImageDraw.Draw(img)
    for y in range(h):
        t = y / max(1, h - 1)
        d.line([(0, y), (w, y)], fill=tuple(int(top[i] + (bot[i] - top[i]) * t) for i in range(3)))
    return img


def grid(d, w, h, step=44, color=(22, 30, 40)):
    for x in range(0, w, step):
        d.line([(x, 0), (x, h)], fill=color)
    for y in range(0, h, step):
        d.line([(0, y), (w, y)], fill=color)


def coffee(d, cx, cy, scale=1.0, cup=(230, 237, 243), accent=ORANGE):
    s = scale
    # saucer
    d.ellipse([cx - 110 * s, cy + 128 * s, cx + 110 * s, cy + 158 * s], fill=(31, 41, 55), outline=(70, 82, 96), width=3)
    # cup body
    d.rounded_rectangle([cx - 92 * s, cy - 30 * s, cx + 92 * s, cy + 138 * s], radius=18 * s, fill=cup)
    # coffee surface
    d.ellipse([cx - 80 * s, cy - 42 * s, cx + 80 * s, cy - 12 * s], fill=(62, 39, 27), outline=(120, 80, 50), width=2)
    # handle
    d.arc([cx + 78 * s, cy + 10 * s, cx + 150 * s, cy + 95 * s], start=-90, end=90, fill=cup, width=int(16 * s))
    # steam
    for i, dx in enumerate((-34, 0, 34)):
        x = cx + dx * s
        pts = [(x + (10 if (y // 14) % 2 else -10) * s, cy - 70 * s - y * s) for y in range(0, 96, 8)]
        d.line(pts, fill=(120, 130, 140), width=int(5 * s))


def text_w(d, s, font):
    b = d.textbbox((0, 0), s, font=font)
    return b[2] - b[0], b[3] - b[1]


def banner():
    W, H = 1280, 640
    img = vgrad(W, H, (10, 14, 19), (18, 25, 33))
    d = ImageDraw.Draw(img)
    grid(d, W, H)

    # top pill
    pill = "AUTHORIZED SECURITY LAB"
    fp = ImageFont.truetype(F_MONO, 20)
    pw, ph = text_w(d, pill, fp)
    d.rounded_rectangle([48, 40, 48 + pw + 28, 40 + ph + 18], radius=18, fill=(22, 33, 28), outline=(46, 160, 67))
    d.text((62, 49), pill, font=fp, fill=(80, 200, 120))

    # title
    f_big = ImageFont.truetype(F_BOLD, 128)
    x, y = 54, 140
    d.text((x, y), "Java", font=f_big, fill=WHITE)
    w1, _ = text_w(d, "Java", f_big)
    d.text((x + w1, y), "4", font=f_big, fill=ORANGE)
    w2, _ = text_w(d, "4", f_big)
    d.text((x + w1 + w2, y), "Shell", font=f_big, fill=WHITE)

    # subtitle
    f_mono = ImageFont.truetype(F_MONO, 42)
    d.text((60, 310), "CVE-2026-114938", font=f_mono, fill=ORANGE)

    f_tag = ImageFont.truetype(F_REG, 31)
    d.text((60, 380), "OpenJDK Base64 decoder heap overflow", font=f_tag, fill=WHITE)
    f_sub = ImageFont.truetype(F_REG, 24)
    d.text((60, 428), "pre-auth RCE  ·  AVX-512 VBMI  ·  JavaBleed memory disclosure", font=f_sub, fill=GREY)

    # cup on the right
    coffee(d, 1035, 250, 1.15)

    # bottom strip
    d.rectangle([0, 560, W, H], fill=(9, 12, 16))
    d.line([(0, 560), (W, 560)], fill=(40, 50, 62), width=2)
    f_foot = ImageFont.truetype(F_MONO, 21)
    foot = "LAB TARGET + DETECTOR + EXPLOIT PoC  ·  NO PUBLIC RCE CHAIN  ·  EDUCATIONAL USE ONLY"
    fw, _ = text_w(d, foot, f_foot)
    d.text(((W - fw) / 2, 590), foot, font=f_foot, fill=(120, 130, 140))

    img.save(HERE / "banner.png")
    print("banner.png", img.size)


def logo():
    S = 512
    img = vgrad(S, S, (12, 16, 22), (20, 28, 37))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([18, 18, S - 18, S - 18], radius=64, outline=(45, 56, 70), width=4)
    f_big = ImageFont.truetype(F_BOLD, 190)
    s = "J4S"
    w, h = text_w(d, s, f_big)
    d.text(((S - w) / 2, 92), "J", font=f_big, fill=WHITE)
    wj, _ = text_w(d, "J", f_big)
    d.text(((S - w) / 2 + wj, 92), "4", font=f_big, fill=ORANGE)
    w4, _ = text_w(d, "4", f_big)
    d.text(((S - w) / 2 + wj + w4, 92), "S", font=f_big, fill=WHITE)
    f_mono = ImageFont.truetype(F_MONO, 34)
    sub = "CVE-2026-114938"
    sw, _ = text_w(d, sub, f_mono)
    d.text(((S - sw) / 2, 320), sub, font=f_mono, fill=ORANGE)
    coffee(d, S // 2, 390, 0.55)
    img.save(HERE / "logo.png")
    print("logo.png", img.size)


if __name__ == "__main__":
    banner()
    logo()
