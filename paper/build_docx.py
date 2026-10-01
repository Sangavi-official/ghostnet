"""
build_docx.py — assemble the IEEE-format Word file from the Markdown source
===========================================================================
Reads paper/GhostNet_v4_paper.md, applies IEEE conference formatting (A4,
two-column, Times New Roman, the sizes from the template's Table I),
resolves [CITE key] -> [n], embeds the figures, inserts the four data
tables, and emits paper/GhostNet_v4_IEEE.docx.

Re-run after editing the Markdown prose. Tables IV data and the reference
list live in THIS file (they come from result files, not prose), so edit
them here.

    python paper/build_docx.py
"""

import os
import re

from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Pt, Twips, Mm

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "paper", "GhostNet_v4_paper.md")
OUT = os.path.join(ROOT, "paper", "GhostNet_v4_IEEE.docx")
FIG = os.path.join(ROOT, "paper", "figures")
COL_W_IN = 3.4            # one IEEE column, inches (image width)

# ── reference list: number -> IEEE string. Order = first appearance in text.
#    Verified in paper/REFERENCES_VERIFIED.md (16) + 4 new (1 Oct 2026).
CITE = {
    "Claroty": 1, "DESOLATER": 2, "Celdran": 3, "Eghtesad": 4, "Zhang": 5,
    "Feng": 6, "Armis": 7, "Torquato": 8, "Park": 9, "Alavizadeh": 10,
    "ATTACK": 11, "Applebaum": 12, "Yulianto": 13, "Holm": 14, "PPO": 15,
    "SB3": 16, "Gymnasium": 17, "DQN": 18, "A2C": 19, "HMAC": 20, "DomainRand": 21,
}
REFS = [
 "Claroty Team82, \"State of CPS security report: Healthcare 2023,\" Claroty, 2023.",
 "S. Yoon, J.-H. Cho, D. S. Kim, T. J. Moore, F. Free-Nelson, and H. Lim, \"DESOLATER: Deep reinforcement learning-based resource allocation and moving target defense deployment framework,\" IEEE Access, vol. 9, pp. 70700-70714, 2021.",
 "A. Huertas Celdran, P. M. Sanchez Sanchez, J. von der Assen, T. Schenk, G. Bovet, G. Martinez Perez, and B. Stiller, \"RL and fingerprinting to select moving target defense mechanisms for zero-day attacks in IoT,\" IEEE Trans. Inf. Forensics Security, vol. 19, pp. 5520-5529, 2024.",
 "T. Eghtesad, Y. Vorobeychik, and A. Laszka, \"Adversarial deep reinforcement learning based adaptive moving target defense,\" in Decision and Game Theory for Security (GameSec), LNCS. Springer, 2020, pp. 58-79.",
 "T. Zhang, C. Xu, J. Shen, X. Kuang, and L. A. Grieco, \"How to disturb network reconnaissance: A moving target defense approach based on deep reinforcement learning,\" IEEE Trans. Inf. Forensics Security, vol. 18, pp. 5735-5748, 2023.",
 "C. Feng, A. Huertas Celdran, P. M. Sanchez Sanchez, J. Kreischer, J. von der Assen, G. Bovet, G. Martinez Perez, and B. Stiller, \"CyberForce: A federated reinforcement learning framework for malware mitigation,\" IEEE Trans. Dependable Secure Comput., vol. 22, no. 4, pp. 4398-4411, 2025.",
 "Armis, \"Medical and IoT device security for healthcare,\" White Paper, Armis Inc., 2024.",
 "M. Torquato and M. Vieira, \"Moving target defense in cloud computing: A systematic mapping study,\" Computers & Security, vol. 92, art. 101742, 2020.",
 "J.-G. Park, Y. Lee, K.-W. Kang, S.-H. Lee, and K.-W. Park, \"Ghost-MTD: Moving target defense via protocol mutation for mission-critical cloud systems,\" Energies, vol. 13, no. 8, art. 1883, 2020.",
 "H. Alavizadeh, S. Aref, D. S. Kim, and J. Jang-Jaccard, \"Evaluating the security and economic effects of moving target defense techniques on the cloud,\" IEEE Trans. Emerg. Topics Comput., vol. 10, no. 4, pp. 1772-1788, 2022.",
 "B. E. Strom, A. Applebaum, D. P. Miller, K. C. Nickels, A. G. Pennington, and C. B. Thomas, \"MITRE ATT&CK: Design and philosophy,\" The MITRE Corporation, Tech. Rep., 2020.",
 "A. Applebaum, D. Miller, B. Strom, C. Korban, and R. Wolf, \"Intelligent, automated red team emulation,\" in Proc. 32nd Annu. Computer Security Applications Conf. (ACSAC), 2016, pp. 363-373.",
 "S. Yulianto, B. Soewito, F. L. Gaol, and A. Kurniawan, \"Enhancing cybersecurity resilience through advanced red-teaming exercises and MITRE ATT&CK framework integration,\" Cyber Security and Applications, vol. 3, art. 100077, 2025.",
 "H. Holm and L. Helgeson, \"An empirical study of automated adversary emulators,\" in Proc. 59th Hawaii Int. Conf. System Sciences (HICSS), 2026.",
 "J. Schulman, F. Wolski, P. Dhariwal, A. Radford, and O. Klimov, \"Proximal policy optimization algorithms,\" arXiv:1707.06347, 2017.",
 "A. Raffin, A. Hill, A. Gleave, A. Kanervisto, M. Ernestus, and N. Dormann, \"Stable-Baselines3: Reliable reinforcement learning implementations,\" J. Mach. Learn. Res., vol. 22, no. 268, pp. 1-8, 2021.",
 "M. Towers et al., \"Gymnasium: A standard interface for reinforcement learning environments,\" in Adv. Neural Inf. Process. Syst. 38, 2025, pp. 163114-163129.",
 "V. Mnih, K. Kavukcuoglu, D. Silver, A. A. Rusu, J. Veness, M. G. Bellemare et al., \"Human-level control through deep reinforcement learning,\" Nature, vol. 518, no. 7540, pp. 529-533, 2015.",
 "V. Mnih, A. P. Badia, M. Mirza, A. Graves, T. Lillicrap, T. Harley, D. Silver, and K. Kavukcuoglu, \"Asynchronous methods for deep reinforcement learning,\" in Proc. 33rd Int. Conf. Machine Learning (ICML), PMLR 48, 2016, pp. 1928-1937.",
 "H. Krawczyk, M. Bellare, and R. Canetti, \"HMAC: Keyed-hashing for message authentication,\" RFC 2104, 1997.",
 "J. Tobin, R. Fong, A. Ray, J. Schneider, W. Zaremba, and P. Abbeel, \"Domain randomization for transferring deep neural networks from simulation to the real world,\" in Proc. IEEE/RSJ Int. Conf. Intelligent Robots and Systems (IROS), 2017, pp. 23-30.",
]

TABLES = {
 "I": ("Threat-State Vector Dimensions",
       ["Idx", "State dimension", "Source"],
       [["0", "Cloud IP exposure", "Derived"], ["1", "Open ports", "Derived"],
        ["2", "API exposure", "Derived"], ["3", "IoT gateway IP exposure", "Derived"],
        ["4", "MQTT exposure", "Derived"], ["5", "CVE severity", "NIST NVD (live)"],
        ["6", "Exposed services", "Shodan (live)"], ["7", "Traffic load", "Network"],
        ["8", "Recon attempts", "Network"], ["9", "Time since mutation", "Internal"],
        ["10", "IP reputation", "AbuseIPDB (live)"], ["11", "ATT&CK relevance", "MITRE (live)"]]),
 "II": ("Dual-Domain Action Space and Execution Status",
        ["#", "Mutation", "Domain", "Status"],
        [["0", "Rotate cloud IP identity", "Cloud", "Partial (SG tag)"],
         ["1", "Rotate open port", "Cloud", "Verified (live)"],
         ["2", "Rotate API path", "Cloud", "Partial (local file)"],
         ["3", "Rotate IoT gateway / broker", "IoT", "Gated (off by default)"],
         ["4", "Rotate MQTT topic", "IoT", "Verified (live)"],
         ["5", "Update firewall (blocklist)", "Cloud", "Pending live test"],
         ["6", "Hold (no mutation)", "-", "n/a"]]),
 "III": ("PPO Training Hyperparameters",
         ["Parameter", "Value"],
         [["Learning rate", "3 x 10^-4"], ["Rollout length", "2048 steps"],
          ["Mini-batch size", "64"], ["Discount factor", "0.99"],
          ["Entropy coefficient", "0.02"], ["Seeds per method", "10"],
          ["Timesteps per seed", "300,000"], ["Rivals", "DQN, A2C (SB3 defaults)"]]),
 "IV": ("Attacker-Outcome Comparison on the Nine-Stage Chain",
        ["Policy", "Attacks", "Breaches", "Inside %", "Disrupt.", "Reward"],
        [["Static (no defence)", "5.0", "5.00", "94.9", "0.00", "-453.6"],
         ["Round-robin MTD", "13.9", "3.00", "3.4", "4.09", "-20.5"],
         ["Greedy (most exposed)", "4.5", "0.88", "1.2", "4.15", "-13.5"],
         ["PPO (ours)", "2.3", "0.69", "1.3", "3.61", "-9.8"],
         ["DQN", "2.7", "0.72", "1.1", "3.45", "-9.6"],
         ["A2C", "1.1", "0.87", "10.1", "3.61", "-20.1"],
         ["PPO, robust (ours)", "4.1", "0.92", "1.4", "3.80", "-11.5"],
         ["PPO v2 (prior model)", "5.7", "4.12", "37.1", "4.62", "-67.7"]]),
}
TABLE_NOTE = {
 "IV": "Learned policies: mean over 10 training seeds. Lower is better except "
       "Reward. The PPO-vs-Greedy breach difference is not significant.",
}

TNR = "Times New Roman"


# ── low-level helpers ─────────────────────────────────────────────────────
def set_cols(section, n, space_twips=238):
    cols = section._sectPr.xpath("./w:cols")[0]
    cols.set(qn("w:num"), str(n))
    cols.set(qn("w:space"), str(space_twips))
    if n == 2:
        cols.set(qn("w:equalWidth"), "1")


def no_space(p):
    pf = p.paragraph_format
    pf.space_before = Pt(0)
    pf.space_after = Pt(0)
    pf.line_spacing = 1.0


def run(p, text, size, *, bold=False, italic=False, caps=False, font=TNR):
    r = p.add_run(text)
    r.font.name = font
    r.font.size = Pt(size)
    r.bold = bold
    r.italic = italic
    r.font.small_caps = caps
    # east-asian font binding so Word doesn't substitute
    rpr = r._element.get_or_add_rPr()
    rf = rpr.find(qn("w:rFonts"))
    if rf is None:
        rf = OxmlElement("w:rFonts"); rpr.insert(0, rf)
    for a in ("w:ascii", "w:hAnsi", "w:cs", "w:eastAsia"):
        rf.set(qn(a), font)
    return r


def para(doc, align=None, indent_first=0.0, space_after=0.0, space_before=0.0):
    p = doc.add_paragraph()
    no_space(p)
    if align is not None:
        p.alignment = align
    pf = p.paragraph_format
    if indent_first:
        pf.first_line_indent = Pt(indent_first)
    pf.space_after = Pt(space_after)
    pf.space_before = Pt(space_before)
    return p


# ── rich inline: **bold** and *italic* and leading "Word." emphasis ───────
def emit_runs(p, text, size):
    for seg in re.split(r"(\*\*.+?\*\*|\*.+?\*)", text):
        if not seg:
            continue
        if seg.startswith("**") and seg.endswith("**"):
            run(p, seg[2:-2], size, bold=True)
        elif seg.startswith("*") and seg.endswith("*"):
            run(p, seg[1:-1], size, italic=True)
        else:
            run(p, seg, size)


# ── tables ────────────────────────────────────────────────────────────────
def add_table(doc, key):
    title, head, rows = TABLES[key]
    cap = para(doc, WD_ALIGN_PARAGRAPH.CENTER, space_before=4, space_after=2)
    run(cap, f"TABLE {key}", 8, caps=True)
    cap2 = para(doc, WD_ALIGN_PARAGRAPH.CENTER, space_after=3)
    run(cap2, title, 8, caps=True)
    t = doc.add_table(rows=1, cols=len(head))
    t.style = "Table Grid"
    t.alignment = WD_ALIGN_PARAGRAPH.CENTER
    for c, h in zip(t.rows[0].cells, head):
        c.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
        no_space(c.paragraphs[0])
        run(c.paragraphs[0], h, 8, bold=True)
    for row in rows:
        cells = t.add_row().cells
        for i, (c, v) in enumerate(zip(cells, row)):
            no_space(c.paragraphs[0])
            c.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.LEFT if i == 1 else WD_ALIGN_PARAGRAPH.CENTER
            run(c.paragraphs[0], v, 8)
    if key in TABLE_NOTE:
        n = para(doc, WD_ALIGN_PARAGRAPH.LEFT, space_before=2, space_after=4)
        run(n, TABLE_NOTE[key], 7.5, italic=True)
    else:
        para(doc, space_after=4)


def add_figure(doc, path, number, caption):
    p = para(doc, WD_ALIGN_PARAGRAPH.CENTER, space_before=4, space_after=2)
    if os.path.exists(path):
        p.add_run().add_picture(path, width=Mm(COL_W_IN * 25.4))
    else:
        run(p, f"[missing figure: {path}]", 8, italic=True)
    cap = para(doc, WD_ALIGN_PARAGRAPH.CENTER, space_after=4)
    run(cap, f"Fig. {number}  ", 8)
    run(cap, caption, 8)


# ── markdown parse ────────────────────────────────────────────────────────
def clean(text):
    text = re.sub(r"\[CITE ([A-Za-z0-9]+)\]",
                  lambda m: f"[{CITE.get(m.group(1), '?')}]", text)
    text = re.sub(r"\s*\[LIVE[^\]]*\]", "", text)
    return text


def load_blocks():
    """Split the Markdown into logical blocks. Blank lines separate blocks, so a
    wrapped bullet or numbered item (its continuation lines are not blank-
    separated) stays a single block."""
    raw = open(SRC, encoding="utf-8").read()
    raw = re.sub(r"<!--.*?-->", "", raw, flags=re.S)       # strip HTML comments
    blocks = []
    for chunk in re.split(r"\n[ \t]*\n", raw):
        joined = " ".join(l.strip() for l in chunk.splitlines() if l.strip()).strip()
        if not joined:
            continue
        s = chunk.strip()
        first = s.splitlines()[0].strip()
        if first.startswith("# "):
            blocks.append(("title", first[2:].strip()))
        elif first.startswith("### "):
            blocks.append(("h2", first[4:].strip()))
        elif first.startswith("## "):
            h = first[3:].strip()
            blocks.append(("abstract_h" if h.lower() == "abstract" else
                           "refs_h" if h.lower() == "references" else "h1", h))
        elif first.startswith("**[FIGURE"):
            blocks.append(("figure", joined))
        elif first.startswith("**[TABLE"):
            blocks.append(("table", joined))
        elif first.startswith("*Keywords"):
            blocks.append(("keywords", joined))
        elif first.startswith("- "):
            # one chunk may hold several bullets, each starting with "- "
            for b in re.split(r"(?m)^- ", chunk):
                b = " ".join(x.strip() for x in b.splitlines() if x.strip()).strip()
                if b:
                    blocks.append(("bullet", b))
        elif re.match(r"^\d+\.\s", first):
            for b in re.split(r"(?m)^(?=\d+\.\s)", chunk):
                b = " ".join(x.strip() for x in b.splitlines() if x.strip()).strip()
                if b:
                    blocks.append(("num", b))
        else:
            blocks.append(("p", joined))
    return blocks


# ── build ─────────────────────────────────────────────────────────────────
def build():
    blocks = load_blocks()
    doc = Document()
    sec = doc.sections[0]
    sec.page_width, sec.page_height = Twips(11906), Twips(16838)      # A4
    sec.top_margin, sec.bottom_margin = Twips(1077), Twips(1440)
    sec.left_margin = sec.right_margin = Twips(811)
    sec.header_distance = sec.footer_distance = Twips(709)
    set_cols(sec, 1)
    st = doc.styles["Normal"]
    st.font.name = TNR; st.font.size = Pt(10)
    st.element.rPr.rFonts.set(qn("w:eastAsia"), TNR)

    body_started = False
    authors = affil = None
    in_refs = False
    pend_fig = 0

    for kind, text in blocks:
        if kind == "title":
            p = para(doc, WD_ALIGN_PARAGRAPH.CENTER, space_after=6)
            run(p, text, 20)                      # 20pt (fits A4 col; IEEE title scale)
            continue
        if kind == "abstract_h":
            body_started = "await"                 # authors/affil already consumed
            continue
        if kind in ("p",) and body_started == "need_meta":
            pass
        # authors + affiliation: the two paragraphs before the abstract heading
        if kind == "p" and not body_started and authors is None:
            authors = text
            p = para(doc, WD_ALIGN_PARAGRAPH.CENTER, space_after=2, space_before=2)
            run(p, text, 11)
            continue
        if kind == "p" and not body_started and affil is None:
            affil = text
            p = para(doc, WD_ALIGN_PARAGRAPH.CENTER, space_after=6)
            run(p, text, 10, italic=True)
            continue
        if kind == "p" and body_started == "await":
            # the abstract paragraph: bold "Abstract—" lead, then bold body (IEEE)
            p = para(doc, WD_ALIGN_PARAGRAPH.JUSTIFY)
            run(p, "Abstract—", 9, bold=True)
            for seg in re.split(r"(\*.+?\*)", clean(text)):
                if seg.startswith("*") and seg.endswith("*") and len(seg) > 2:
                    run(p, seg[1:-1], 9, bold=True, italic=True)
                elif seg:
                    run(p, seg, 9, bold=True)
            body_started = "pre_cols"
            continue
        if kind == "keywords":
            p = para(doc, WD_ALIGN_PARAGRAPH.JUSTIFY, space_before=4, space_after=4)
            t = clean(text).replace("*Keywords —*", "").replace("*Keywords —*", "").strip()
            run(p, "Keywords—", 9, bold=True, italic=True)
            run(p, t, 9, italic=True)
            # switch to two columns for everything after the abstract block
            doc.add_section(WD_SECTION.CONTINUOUS)
            s2 = doc.sections[-1]
            s2.top_margin, s2.bottom_margin = Twips(1077), Twips(1440)
            s2.left_margin = s2.right_margin = Twips(811)
            set_cols(s2, 2)
            body_started = True
            continue
        if kind == "refs_h":
            in_refs = True
            p = para(doc, WD_ALIGN_PARAGRAPH.CENTER, space_before=8, space_after=4)
            run(p, "References", 10, caps=True)
            for i, r in enumerate(REFS, 1):
                rp = para(doc, WD_ALIGN_PARAGRAPH.JUSTIFY)
                rp.paragraph_format.left_indent = Pt(14)
                rp.paragraph_format.first_line_indent = Pt(-14)
                run(rp, f"[{i}] ", 8)
                run(rp, r, 8)
            continue
        if in_refs:
            continue
        if kind == "h1":
            p = para(doc, WD_ALIGN_PARAGRAPH.CENTER, space_before=9, space_after=3)
            run(p, text, 10, caps=True)
        elif kind == "h2":
            p = para(doc, WD_ALIGN_PARAGRAPH.LEFT, space_before=6, space_after=2)
            run(p, text, 10, italic=True)
        elif kind == "figure":
            m = re.match(r"\*\*\[FIGURE\s*\d*:?\s*(\S+)\s*[—-]\s*(.+?)\.?\]\*\*", text)
            pend_fig += 1
            if m:
                add_figure(doc, os.path.join(ROOT, m.group(1).replace("paper/figures/", "paper/figures/")),
                           pend_fig, clean(m.group(2)).strip())
            else:
                add_figure(doc, "MISSING", pend_fig, text)
        elif kind == "table":
            m = re.match(r"\*\*\[TABLE\s+([IVX]+)", text)
            if m and m.group(1) in TABLES:
                add_table(doc, m.group(1))
        elif kind == "bullet":
            p = para(doc, WD_ALIGN_PARAGRAPH.JUSTIFY, space_after=1)
            p.paragraph_format.left_indent = Pt(14)
            p.paragraph_format.first_line_indent = Pt(-8)
            run(p, "•  ", 10)
            emit_runs(p, clean(text), 10)
        elif kind == "num":
            p = para(doc, WD_ALIGN_PARAGRAPH.JUSTIFY, space_after=1, indent_first=0)
            p.paragraph_format.left_indent = Pt(14)
            p.paragraph_format.first_line_indent = Pt(-14)
            emit_runs(p, clean(text), 10)
        elif kind == "p":
            p = para(doc, WD_ALIGN_PARAGRAPH.JUSTIFY, indent_first=11)
            emit_runs(p, clean(text), 10)

    doc.save(OUT)
    print("wrote", OUT)


if __name__ == "__main__":
    build()
