"""
make_figures.py — figures for the IEEE paper, generated from saved results
===========================================================================
Every number is read from a results file, never typed in:
  robustness_v4.json     -> Fig. 2 (breaches vs firewall effect)
  gmcp_sim_results.json  -> Fig. 3 (device stranding vs message loss)
Fig. 1 is the system architecture.

Style: IEEE column width (88.6 mm), Times New Roman, readable in
black-and-white print (each series has its own marker and a direct
label; the same numbers appear in the paper's tables). Palette: the
dataviz reference categorical order, validated against white paper with
validate_palette.py (all checks pass; slots 3-4 are below 3:1 contrast,
so direct labels are mandatory and present).

    python paper/make_figures.py
"""

import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "paper", "figures")
COL_W = 88.6 / 25.4          # IEEE column width, inches
DPI = 600

# dataviz reference palette (light), fixed order
S1, S2, S3, S4 = "#2a78d6", "#eb6834", "#1baf7a", "#eda100"
INK, INK2, MUTED = "#0b0b0b", "#52514e", "#898781"
GRID, AXIS = "#e1e0d9", "#c3c2b7"

plt.rcParams.update({
    "font.family": "serif", "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
    "mathtext.fontset": "stix", "font.size": 8, "axes.labelsize": 8,
    "xtick.labelsize": 7.5, "ytick.labelsize": 7.5, "legend.fontsize": 7.5,
    "axes.edgecolor": AXIS, "axes.labelcolor": INK, "xtick.color": INK2,
    "ytick.color": INK2, "axes.linewidth": 0.6, "xtick.major.width": 0.6,
    "ytick.major.width": 0.6, "savefig.dpi": DPI, "savefig.bbox": "tight",
    "savefig.pad_inches": 0.02,
})


def style_axes(ax):
    ax.grid(axis="y", color=GRID, linewidth=0.5)
    ax.set_axisbelow(True)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)


def line(ax, x, y, color, marker, label, label_xy, ha="left"):
    ax.plot(x, y, color=color, linewidth=1.4, marker=marker, markersize=5,
            markeredgecolor="white", markeredgewidth=0.8, solid_joinstyle="round",
            solid_capstyle="round", label=label, zorder=3)
    ax.annotate(label, label_xy, color=INK, fontsize=7.5, ha=ha, va="center")


# ─── Fig. 2: robustness to firewall-model error ──────────────────────────
def fig_robustness():
    r = json.load(open(os.path.join(ROOT, "robustness_v4.json")))["settings"]
    keys = [("firewall does nothing", 0.0), ("firewall cut 0.05", 0.05),
            ("firewall cut 0.10", 0.10), ("as trained", 0.15)]
    x = [v for _, v in keys]
    get = lambda col: [r[k]["succeeded"]["means"][col] for k, _ in keys]
    series = [("Greedy rule", "Greedy", S1, "o"), ("PPO", "PPO", S2, "s"),
              ("DQN", "DQN", S3, "^"), ("PPO, robust training", "PPO-FWRAND", S4, "D")]

    fig, ax = plt.subplots(figsize=(COL_W, 2.25))
    style_axes(ax)
    ys = {lab: get(col) for lab, col, _, _ in series}
    # direct labels at the left edge, nudged apart where lines are close
    nudge = {"Greedy rule": -0.16, "PPO, robust training": 0.16, "DQN": 0.0, "PPO": 0.0}
    for lab, col, c, m in series:
        y = ys[lab]
        line(ax, x, y, c, m, lab, (x[0] - 0.006, y[0] + nudge[lab]), ha="right")
    ax.axvline(0.15, color=AXIS, linewidth=0.6, zorder=1)
    ax.annotate("value used\nin training", (0.15, 4.25), ha="right", va="top",
                fontsize=7, color=INK2, xytext=(-3, 0), textcoords="offset points")
    ax.set_xlim(-0.072, 0.158)
    ax.set_ylim(0, 4.4)
    ax.set_xticks(x)
    ax.set_xticklabels(["0\n(no effect)", "0.05", "0.10", "0.15"])
    ax.set_xlabel("Modelled effect of the firewall action (exposure reduction)")
    ax.set_ylabel("Breaches per game")
    fig.savefig(os.path.join(OUT, "fig2_robustness.png"))
    plt.close(fig)


# ─── Fig. 3: GMCP vs deployed relocation schemes ──────────────────────────
def fig_gmcp():
    g = json.load(open(os.path.join(ROOT, "gmcp_sim_results.json")))["broker_move"]
    ps = ["0.0", "0.05", "0.1", "0.2", "0.3", "0.5"]
    x = [100 * float(p) for p in ps]
    stranded = lambda s: [g[s][p].get("pct_stranded", 0.0) for p in ps]
    fig, ax = plt.subplots(figsize=(COL_W, 2.1))
    style_axes(ax)
    line(ax, x, stranded("naive"), S1, "o", "No notice", (x[-1] + 1.5, stranded("naive")[-1]))
    line(ax, x, stranded("announced"), S2, "s", "Single notice\n(deployed)",
         (x[-1] + 1.5, stranded("announced")[-1]))
    line(ax, x, stranded("gmcp"), S3, "^", "GMCP", (x[-1] + 1.5, stranded("gmcp")[-1] + 4))
    ax.set_xlim(-2, 66)
    ax.set_ylim(-4, 108)
    ax.set_xticks(x)
    ax.set_xticklabels([f"{v:g}" for v in x])
    ax.set_xlabel("Control messages lost (%)")
    ax.set_ylabel("Relocations that strand\nthe device (%)")
    fig.savefig(os.path.join(OUT, "fig3_gmcp.png"))
    plt.close(fig)


# ─── Fig. 1: architecture ─────────────────────────────────────────────────
def box(ax, x, y, w, h, title, lines=(), fill="#f6f6f4", edge=INK2, bold=True):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0,rounding_size=0.05",
                                linewidth=0.6, edgecolor=edge, facecolor=fill, zorder=2))
    n = len(lines)
    ty = y + h / 2 + (0.072 * n)
    ax.text(x + w / 2, ty, title, ha="center", va="center", fontsize=7.6,
            fontweight="bold" if bold else "normal", color=INK, zorder=3)
    for i, t in enumerate(lines):
        ax.text(x + w / 2, ty - 0.145 * (i + 1), t, ha="center", va="center",
                fontsize=6.8, color=INK2, zorder=3)


def arrow(ax, p, q, style="-|>", ls="-", color=INK2, rad=0.0):
    ax.add_patch(FancyArrowPatch(p, q, arrowstyle=style, mutation_scale=7, linewidth=0.7,
                                 color=color, linestyle=ls, zorder=1,
                                 connectionstyle=f"arc3,rad={rad}"))


def fig_architecture():
    W, H = COL_W, 3.92
    fig = plt.figure(figsize=(W, H))
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, W)
    ax.set_ylim(0, H)
    ax.axis("off")
    m, gap = 0.04, 0.08
    half = (W - 2 * m - gap) / 2
    xl, xr = m, m + half + gap
    full = W - 2 * m

    box(ax, xl, 3.46, half, 0.42, "Threat-intelligence feeds",
        ["NVD · Shodan · AbuseIPDB · ATT&CK"])
    box(ax, xr, 3.46, half, 0.42, "Exposure estimates",
        ["IDS view of attacker progress"])
    box(ax, m, 2.96, full, 0.34, r"Threat-state vector  $s \in [0,1]^{12}$",
        [], fill="#eef4fc", edge=S1)
    box(ax, m, 2.42, full, 0.38, r"Learned policy  $\pi(a \mid s)$",
        ["7 actions: 6 mutations + hold"], fill="#eef4fc", edge=S1)
    # Status words match Table II: verified (confirmed on the live deployment),
    # pending (implemented, live validation pending), partial (changes no live
    # infrastructure), gated (disabled by default). Update after live tests.
    box(ax, xl, 1.58, half, 0.68, "Cloud executor",
        ["port rotation (verified)", "host firewall blocklist (pending)",
         "SG tag, API path (partial)"])
    box(ax, xr, 1.58, half, 0.68, "IoT executor",
        ["MQTT topic rotation (verified)", "broker relocation (gated)",
         "GMCP coordination (pending)"])
    box(ax, xl, 1.14, half, 0.30, "AWS SG · EC2 host", [], bold=False)
    box(ax, xr, 1.14, half, 0.30, "Broker · infusion pump", [], bold=False)
    box(ax, m, 0.62, full, 0.38, "Verification at target and consumer",
        ["SG re-read · ipset check · telemetry on new topic"])
    box(ax, m, 0.02, full, 0.46, "Mutation ledger",
        ["old value · new value · verified · rolled back",
         "supplies the live configuration to both executors"], fill="#ffffff")

    cx_l, cx_r, cx = xl + half / 2, xr + half / 2, W / 2
    arrow(ax, (cx_l, 3.46), (cx_l, 3.30))
    arrow(ax, (cx_r, 3.46), (cx_r, 3.30))
    arrow(ax, (cx, 2.96), (cx, 2.80))
    arrow(ax, (cx - 0.25, 2.42), (cx_l, 2.26))
    arrow(ax, (cx + 0.25, 2.42), (cx_r, 2.26))
    arrow(ax, (cx_l, 1.58), (cx_l, 1.44))
    arrow(ax, (cx_r, 1.58), (cx_r, 1.44))
    arrow(ax, (cx_l, 1.14), (cx_l, 1.00))
    arrow(ax, (cx_r, 1.14), (cx_r, 1.00))
    arrow(ax, (cx, 0.62), (cx, 0.48))
    fig.savefig(os.path.join(OUT, "fig1_architecture.png"))
    plt.close(fig)


if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    fig_architecture()
    fig_robustness()
    fig_gmcp()
    print("written:", sorted(os.listdir(OUT)))
