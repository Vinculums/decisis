import re
import sys
from importlib import metadata
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

FONTS = Path("/usr/share/fonts/truetype/dejavu")
SANS = str(FONTS / "DejaVuSans.ttf")
SANS_BOLD = str(FONTS / "DejaVuSans-Bold.ttf")
MONO = str(FONTS / "DejaVuSansMono.ttf")
MONO_BOLD = str(FONTS / "DejaVuSansMono-Bold.ttf")

BG = (13, 17, 23)
PANEL = (22, 27, 34)
LINE = (48, 54, 61)
TEXT = (230, 237, 243)
MUTED = (139, 148, 158)
VINC = (163, 113, 247)
LOCK = (227, 179, 65)
OSV = (248, 81, 73)
GREEN = (63, 185, 80)
BLUE = (88, 166, 255)


def font(path, size):
    return ImageFont.truetype(path, size)


def social(out: Path):
    W, H = 1280, 640
    im = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(im)
    x0 = 72
    mark = Image.open(out.parent / "logo-mark.png").convert("RGBA")
    mh = 100
    mark = mark.resize((round(mark.width * mh / mark.height), mh), Image.Resampling.LANCZOS)
    im.paste(mark, (x0 - 6, 58), mark)
    d.text((x0 + mark.width + 18, 58 + mh // 2), "decisis", font=font(SANS_BOLD, 88), fill=TEXT, anchor="lm")
    d.text((x0, 176), "Stand by what was decided.", font=font(SANS_BOLD, 34), fill=VINC)
    sub = font(SANS, 24)
    d.text((x0, 230), "Join a team's decisions with code and outside facts in a throwaway graph,", font=sub, fill=MUTED)
    d.text((x0, 262), "find the path from a decision to what breaks it, and keep only verified findings.", font=sub, fill=MUTED)

    nodes = [
        ("Decision", "no HIGH", "advisories shipped", VINC),
        ("Concept", "demo-app", "", VINC),
        ("Repository", "Demo", "", LOCK),
        ("Package", "report-kit", "2.1.0", LOCK),
        ("Package", "lodash", "4.17.15", LOCK),
        ("Advisory", "GHSA-r5fr-…", "HIGH", OSV),
    ]
    edges = [("ABOUT", 1), ("DESCRIBED_BY", -1), ("DEPENDS_ON", 1), ("DEPENDS_ON", 1), ("AFFECTED_BY", 1)]
    bw, bh, gap = 158, 104, 46
    total = len(nodes) * bw + (len(nodes) - 1) * gap
    bx = (W - total) // 2
    by = 352
    kind_f, name_f, small_f, edge_f = font(SANS, 16), font(SANS_BOLD, 19), font(SANS, 17), font(MONO_BOLD, 12)
    for i, (kind, name, extra, color) in enumerate(nodes):
        x = bx + i * (bw + gap)
        d.rounded_rectangle((x, by, x + bw, by + bh), radius=14, fill=PANEL, outline=color, width=3)
        d.text((x + bw / 2, by + 24), kind, font=kind_f, fill=color, anchor="mm")
        size = 19
        while d.textlength(name, font=font(SANS_BOLD, size)) > bw - 18:
            size -= 1
        d.text((x + bw / 2, by + 54), name, font=font(SANS_BOLD, size), fill=TEXT, anchor="mm")
        if extra:
            esize = 17
            while d.textlength(extra, font=font(SANS, esize)) > bw - 18:
                esize -= 1
            d.text((x + bw / 2, by + 80), extra, font=font(SANS, esize), fill=MUTED, anchor="mm")
    for i, (label, direction) in enumerate(edges):
        x1 = bx + i * (bw + gap) + bw + 6
        x2 = x1 + gap - 12
        y = by + bh / 2
        d.line((x1, y, x2, y), fill=MUTED, width=3)
        tip = x2 if direction > 0 else x1
        s = 1 if direction > 0 else -1
        d.polygon([(tip, y), (tip - 10 * s, y - 7), (tip - 10 * s, y + 7)], fill=MUTED)
        lx = (x1 + x2) / 2
        d.text((lx, by - 16 if i % 2 == 0 else by + bh + 16), label, font=edge_f, fill=MUTED, anchor="mm")

    ly = 520
    leg = font(SANS, 20)
    lx = bx
    for color, name in ((VINC, "decision graph (Vinc or a JSON snapshot)"), (LOCK, "npm lockfile"), (OSV, "OSV advisories")):
        d.rounded_rectangle((lx, ly - 9, lx + 18, ly + 9), radius=4, fill=color)
        d.text((lx + 28, ly), name, font=leg, fill=MUTED, anchor="lm")
        lx += 28 + d.textlength(name, font=leg) + 40

    foot = font(MONO, 21)
    d.text((x0, 584), "pip install decisis", font=foot, fill=GREEN)
    right = "Apache-2.0  ·  runs offline  ·  github.com/Vinculums/decisis"
    d.text((W - x0, 584), right, font=foot, fill=MUTED, anchor="ra")
    im.save(out, optimize=True)


def color_of(line: str):
    s = line.strip()
    if re.match(r"^\d\. ", line):
        return BLUE, True
    if line.startswith("$ "):
        return GREEN, True
    if "violates" in line:
        return OSV, False
    if s.startswith("affected") and "MODERATE" in s:
        return LOCK, False
    if s.startswith("affected"):
        return TEXT, False
    if " -ABOUT-> " in line:
        return VINC, False
    if s.startswith("Waiting for a person") or s.startswith("Operational sandbox deleted"):
        return GREEN, False
    return TEXT if line.startswith("   ") or not line.startswith(" ") else MUTED, False


def wrap(line: str, cols: int) -> list[str]:
    if len(line) <= cols:
        return [line]
    indent = " " * (len(line) - len(line.lstrip()) + 2)
    out, cur = [], line
    while len(cur) > cols:
        cut = cur.rfind(" ", 0, cols)
        cut = cut if cut > len(indent) + 10 else cols
        out.append(cur[:cut])
        cur = indent + cur[cut:].lstrip()
    out.append(cur)
    return out


def install_line(root: str = "decisis") -> str:
    seen, todo = {}, [root]
    while todo:
        dist = metadata.distribution(todo.pop())
        name = dist.metadata["Name"]
        if name.lower() in {k.lower() for k in seen}:
            continue
        seen[name] = dist.version
        for req in dist.requires or []:
            if "extra ==" in req:
                continue
            todo.append(re.split(r"[\s;<>=!~\[(]", req, maxsplit=1)[0])
    return "Successfully installed " + " ".join(f"{n}-{v}" for n, v in sorted(seen.items()))


def terminal(demo_text: Path, out: Path):
    cols, rows = 104, 30
    f, fb = font(MONO, 15), font(MONO_BOLD, 15)
    cw = f.getlength("M")
    lh = 20
    pad, bar = 20, 34
    W = int(cols * cw + pad * 2)
    H = rows * lh + pad * 2 + bar
    raw = demo_text.read_text(encoding="utf-8").splitlines()
    keep = []
    for line in raw:
        if line.startswith("Transcript:"):
            line = "Transcript: demo-out/transcript.json; expected findings: demo-out/expected_findings.json"
        keep.append(line)
    lines, styles = [], []
    for line in keep:
        parts = wrap(line, cols)
        style = color_of(line)
        lines += parts
        styles += [style] * len(parts)
    style_of = dict()

    def frame(shown: list[str], cursor: str | None = None) -> Image.Image:
        im = Image.new("RGB", (W, H), BG)
        d = ImageDraw.Draw(im)
        d.rectangle((0, 0, W, bar), fill=PANEL)
        for i, c in enumerate(((255, 95, 86), (255, 189, 46), (39, 201, 63))):
            d.ellipse((16 + i * 22, 11, 28 + i * 22, 23), fill=c)
        d.text((W / 2, bar / 2), "decisis demo", font=font(SANS, 14), fill=MUTED, anchor="mm")
        view = shown[-rows:]
        vstyles = shown_styles[-rows:]
        for r, line in enumerate(view):
            color, bold = vstyles[r] if r < len(vstyles) and vstyles[r] else color_of(line)
            d.text((pad, bar + pad + r * lh), line, font=fb if bold else f, fill=color)
        if cursor is not None:
            r = len(view) - 1
            x = pad + cw * len(view[-1])
            d.rectangle((x + 1, bar + pad + r * lh + 2, x + cw - 1, bar + pad + r * lh + lh - 2), fill=TEXT)
        return im

    frames, durations = [], []
    shown_styles = []
    prompt = "$ "
    typed = ["$ pip install decisis", "$ decisis demo"]
    shown = []
    def add(line, style=None):
        shown.append(line)
        shown_styles.append(style)

    for cmd in typed:
        for k in range(len(prompt), len(cmd) + 1, 3):
            shown_styles.append(None)
            frames.append(frame(shown + [cmd[:k]], cursor="on"))
            shown_styles.pop()
            durations.append(70)
        add(cmd)
        frames.append(frame(shown, cursor="on"))
        durations.append(500)
        if cmd.endswith("pip install decisis"):
            add(install_line())
            add("")
            frames.append(frame(shown))
            durations.append(900)
    pending = 0
    for line, style in zip(lines, styles):
        add(line, style)
        pending += 1
        is_head = bool(re.match(r"^\d\. ", line))
        is_path = " -ABOUT-> " in line or "-AFFECTED_BY->" in line
        if is_head or is_path or pending >= 3 or line == "":
            frames.append(frame(shown))
            durations.append(1000 if is_head else (1800 if is_path else 260))
            pending = 0
    frames.append(frame(shown))
    durations.append(5000)

    palette_src = Image.new("RGB", (W, H * 3))
    for i, fr in enumerate((frames[len(frames) // 3], frames[2 * len(frames) // 3], frames[-1])):
        palette_src.paste(fr, (0, i * H))
    pal = palette_src.quantize(colors=48, method=Image.Quantize.MEDIANCUT)
    q = [fr.quantize(palette=pal, dither=Image.Dither.NONE) for fr in frames]
    q[0].save(out, save_all=True, append_images=q[1:], duration=durations, loop=0, optimize=True, disposal=1)


if __name__ == "__main__":
    dest = Path(sys.argv[1])
    dest.mkdir(parents=True, exist_ok=True)
    social(dest / "social-preview.png")
    terminal(Path(sys.argv[2]), dest / "demo.gif")
