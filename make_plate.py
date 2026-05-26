#!/usr/bin/env python3
"""Signal Cartography - canvas plate. Renders a radial network 'atlas'."""
import math, random
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib import font_manager as fm
from matplotlib.patches import Circle
import numpy as np

FONTDIR = "/sessions/dazzling-clever-keller/mnt/.claude/skills/canvas-design/canvas-fonts"
def reg(name):
    p = f"{FONTDIR}/{name}"
    fm.fontManager.addfont(p)
    return fm.FontProperties(fname=p)

f_thin   = reg("Jura-Light.ttf")
f_med    = reg("Jura-Medium.ttf")
f_mono   = reg("GeistMono-Regular.ttf")
f_monob  = reg("GeistMono-Bold.ttf")
f_disp   = reg("Tektur-Regular.ttf")

# palette ------------------------------------------------------------------
GROUND  = "#080b12"
INK2    = "#0c1barchive"  # placeholder, fixed below
INK2    = "#0b1019"
GRID    = "#15233a"
GRIDS   = "#1d3350"
RING    = "#22out"        # fixed below
RING    = "#203a5e"
CYAN    = "#49d8f2"
BLUE    = "#3b82f6"
TEAL    = "#5fe3c0"
AMBER   = "#ecb24a"
WARM    = "#f4d58a"
WHITE   = "#e9eff7"
MUTE    = "#5a6c86"
MUTE2   = "#3c4a61"

random.seed(73); np.random.seed(73)

fig = plt.figure(figsize=(8, 10), dpi=300)
fig.patch.set_facecolor(GROUND)
ax = fig.add_axes([0, 0, 1, 1])
ax.set_xlim(-1, 1); ax.set_ylim(-1.25, 1.25)
ax.set_aspect("equal"); ax.axis("off")

CX, CY = 0.0, -0.02      # map center
ring_r = [0.165, 0.275, 0.39, 0.505, 0.62, 0.735]
OUTER  = 0.80

# faint paper grain ---------------------------------------------------------
gx = np.random.uniform(-1, 1, 1400)
gy = np.random.uniform(-1.25, 1.25, 1400)
ax.scatter(gx, gy, s=0.4, c="#11192a", alpha=0.5, linewidths=0, zorder=0)

# coordinate spokes ---------------------------------------------------------
for deg in range(0, 360, 15):
    a = math.radians(deg)
    x2, y2 = CX + OUTER*math.cos(a), CY + OUTER*math.sin(a)
    ax.plot([CX, x2], [CY, y2], color=GRID, lw=0.45, alpha=0.55, zorder=1)

# concentric rings ----------------------------------------------------------
for i, r in enumerate(ring_r):
    ax.add_patch(Circle((CX, CY), r, fill=False, ec=RING, lw=0.6,
                         alpha=0.7 - i*0.04, zorder=1))

# outer azimuth scale -------------------------------------------------------
for deg in range(0, 360, 5):
    a = math.radians(deg - 90)
    inner = OUTER + (0.018 if deg % 30 else 0.030)
    x1, y1 = CX + OUTER*math.cos(a), CY + OUTER*math.sin(a)
    x2, y2 = CX + inner*math.cos(a), CY + inner*math.sin(a)
    ax.plot([x1, x2], [y1, y2], color=GRIDS if deg % 30 else MUTE,
            lw=0.5 if deg % 30 else 0.8, alpha=0.8, zorder=2)
    if deg % 30 == 0:
        lr = OUTER + 0.055
        ax.text(CX + lr*math.cos(a), CY + lr*math.sin(a), f"{deg:03d}",
                ha="center", va="center", color=MUTE, fontsize=4.6,
                fontproperties=f_mono, rotation=0, zorder=2)

# device nodes --------------------------------------------------------------
node_colors = [CYAN, BLUE, TEAL]
nidx = 1
labelled = 0
for ri, r in enumerate(ring_r):
    count = 6 + ri*3
    base = random.uniform(0, 30)
    for k in range(count):
        a = math.radians(base + k*(360/count) + random.uniform(-6, 6))
        rr = r + random.uniform(-0.022, 0.022)
        x, y = CX + rr*math.cos(a), CY + rr*math.sin(a)
        # filament to center
        ax.plot([CX, x], [CY, y], color=CYAN, lw=0.3,
                alpha=0.06 + random.uniform(0, 0.05), zorder=1)
        ports = random.choice([1, 1, 1, 2, 2, 3, 4, 6])
        col = random.choices(node_colors, weights=[6, 3, 2])[0]
        size = 5 + ports*4
        bright = ports >= 4
        # glow
        ax.scatter([x], [y], s=size*7, c=col, alpha=0.10, linewidths=0, zorder=2)
        ax.scatter([x], [y], s=size, c=(WARM if bright else col),
                   alpha=0.95, linewidths=0, zorder=3)
        if bright:
            ax.scatter([x], [y], s=size*0.35, c=GROUND, alpha=1, linewidths=0, zorder=4)
        # sparse clinical labels on a few outer, bright nodes
        if bright and ri >= 2 and labelled < 11 and random.random() < 0.7:
            labelled += 1
            lx = x + 0.045*math.cos(a)
            ly = y + 0.045*math.sin(a)
            ha = "left" if math.cos(a) >= 0 else "right"
            ax.plot([x, lx], [y, ly], color=MUTE, lw=0.4, alpha=0.7, zorder=2)
            ax.text(lx + (0.012 if ha == "left" else -0.012), ly,
                    f"N{nidx:02d}·{ports*22+10}", ha=ha, va="center",
                    color=MUTE, fontsize=4.4, fontproperties=f_mono, zorder=4)
        nidx += 1

# crosshair tick decorations on a ring
for deg in (40, 130, 255, 312):
    a = math.radians(deg)
    r = ring_r[3]
    x, y = CX + r*math.cos(a), CY + r*math.sin(a)
    for off in (0, 90, 180, 270):
        aa = math.radians(off)
        ax.plot([x, x + 0.02*math.cos(aa)], [y, y + 0.02*math.sin(aa)],
                color=CYAN, lw=0.5, alpha=0.5, zorder=2)

# ORIGIN — the warm anchor --------------------------------------------------
for s, al in [(2200, 0.05), (1300, 0.08), (720, 0.14), (360, 0.22)]:
    ax.scatter([CX], [CY], s=s, c=AMBER, alpha=al, linewidths=0, zorder=4)
ax.scatter([CX], [CY], s=130, c=AMBER, alpha=1, linewidths=0, zorder=5)
ax.scatter([CX], [CY], s=34, c=WARM, alpha=1, linewidths=0, zorder=6)
ax.add_patch(Circle((CX, CY), 0.052, fill=False, ec=AMBER, lw=0.7, alpha=0.6, zorder=5))
ax.text(CX, CY - 0.085, "ORIGIN", ha="center", va="center", color=AMBER,
        fontsize=5.0, fontproperties=f_mono, zorder=6)

# ---- typography: title band ----------------------------------------------
def spaced(s, n=1):
    return (" " * n).join(list(s))

ax.text(0, 1.13, spaced("SIGNAL CARTOGRAPHY"), ha="center", va="center",
        color=WHITE, fontsize=21, fontproperties=f_thin, zorder=7)
ax.plot([-0.46, 0.46], [1.055, 1.055], color=MUTE2, lw=0.6, alpha=0.9, zorder=7)
ax.text(0, 1.0, spaced("AN ATLAS OF THE INVISIBLE NETWORK", 2), ha="center",
        va="center", color=MUTE, fontsize=5.4, fontproperties=f_mono, zorder=7)

# corner registration marks
for (mx, my) in [(-0.93, 1.18), (0.93, 1.18), (-0.93, -1.18), (0.93, -1.18)]:
    ax.plot([mx-0.02, mx+0.02], [my, my], color=MUTE2, lw=0.6, zorder=7)
    ax.plot([mx, mx], [my-0.02, my+0.02], color=MUTE2, lw=0.6, zorder=7)
ax.text(-0.93, 1.10, "PLATE I", ha="left", va="center", color=MUTE,
        fontsize=4.6, fontproperties=f_mono, zorder=7)
ax.text(0.93, 1.10, "λ / 802.11", ha="right", va="center", color=MUTE,
        fontsize=4.6, fontproperties=f_mono, zorder=7)

# ---- legend / footer ------------------------------------------------------
ly = -0.96
items = [(AMBER, "ORIGIN — gateway / source"),
         (CYAN, "NODE — discovered host"),
         (WARM, "DENSE — open service ports")]
x0 = -0.62
for i, (c, t) in enumerate(items):
    yy = ly - i*0.052
    ax.scatter([x0], [yy], s=34, c=c, alpha=0.95, linewidths=0, zorder=7)
    ax.text(x0 + 0.03, yy, t, ha="left", va="center", color=MUTE,
            fontsize=5.0, fontproperties=f_mono, zorder=7)

ax.plot([-0.62, 0.62], [ly + 0.045, ly + 0.045], color=MUTE2, lw=0.5, alpha=0.8, zorder=7)
ax.text(0.62, ly, "FIELD SURVEY", ha="right", va="center", color=MUTE,
        fontsize=5.0, fontproperties=f_med, zorder=7)
ax.text(0.62, ly - 0.052, "254 COORDINATES", ha="right", va="center", color=MUTE2,
        fontsize=4.6, fontproperties=f_mono, zorder=7)
ax.text(0.62, ly - 0.104, "RADIAL · CONCENTRIC", ha="right", va="center", color=MUTE2,
        fontsize=4.6, fontproperties=f_mono, zorder=7)

ax.text(0, -1.20, spaced("OBSERVE · MAP · UNDERSTAND", 3), ha="center", va="center",
        color=MUTE2, fontsize=4.8, fontproperties=f_mono, zorder=7)

fig.savefig("/sessions/dazzling-clever-keller/mnt/outputs/signal_cartography.png",
            facecolor=GROUND, dpi=300)
fig.savefig("/sessions/dazzling-clever-keller/mnt/outputs/signal_cartography.pdf",
            facecolor=GROUND)
print("saved plate")
