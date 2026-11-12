"""Generate the Riff logo (client/icons/logo.png + logo.ico).

Design: rounded teal square with three repeating "packet" pulses -
a riff is a repeated phrase, and a traffic generator repeats packets.
Usage: python win/make-icon.py   (from the repo root, needs Pillow)
"""
import os
from PIL import Image, ImageDraw

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ICONS = os.path.join(ROOT, "client", "icons")
S = 1024  # draw large, downscale for smooth edges


def draw():
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    # background: vertical gradient teal -> deep blue, rounded square
    grad = Image.new("RGBA", (S, S))
    gd = ImageDraw.Draw(grad)
    top, bot = (20, 184, 166), (30, 64, 175)
    for y in range(S):
        t = y / (S - 1)
        c = tuple(int(top[i] + (bot[i] - top[i]) * t) for i in range(3))
        gd.line([(0, y), (S, y)], fill=c + (255,))
    mask = Image.new("L", (S, S), 0)
    ImageDraw.Draw(mask).rounded_rectangle([40, 40, S - 40, S - 40],
                                           radius=200, fill=255)
    img.paste(grad, (0, 0), mask)

    # baseline + three repeated pulses (packets on a wire)
    white = (255, 255, 255, 255)
    y0, h, w, lw = 650, 330, 150, 46
    xs = [170, 400, 630]
    pts = [(100, y0)]
    for x in xs:
        pts += [(x, y0), (x, y0 - h), (x + w, y0 - h), (x + w, y0)]
    pts.append((S - 100, y0))
    d.line(pts, fill=white, width=lw, joint="curve")
    # small dots under each pulse = repetition marks
    for x in xs:
        cx = x + w // 2
        d.ellipse([cx - 34, 760, cx + 34, 828], fill=white)
    return img


def main():
    big = draw()
    big.resize((200, 200), Image.LANCZOS).save(os.path.join(ICONS, "logo.png"))
    big.resize((256, 256), Image.LANCZOS).save(
        os.path.join(ICONS, "logo.ico"),
        sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (256, 256)])
    print("wrote logo.png, logo.ico")


if __name__ == "__main__":
    main()
