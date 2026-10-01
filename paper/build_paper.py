"""
build_paper.py — build the IEEE conference Word file from plain text
=====================================================================
Reads  paper/paper_text.md     (the paper, in the light markup below)
       paper/references.txt    (key | IEEE-style entry)
       paper/figures/*.png
Writes paper/GhostNet_IEEE_Paper.docx

Layout follows the IEEE A4 conference template (Causal Productions V2) used
by the authors' department: A4, margins 19 / 43 / 14.32 / 14.32 mm, title
block in one column, body in two 88.6 mm columns 4.2 mm apart, Times New
Roman throughout, sizes per the template's Table 1 (title 24 pt, author
11 pt, affiliation 10 pt italic, e-mail 9 pt Courier, abstract 9 pt bold,
body 10 pt, headings 10 pt, captions and references 8 pt, table cells 9 pt).
No headers, footers or page numbers.

Everything uses NAMED STYLES, so the file stays easy to edit in Word:
Normal (body), Paper Title, Author, Affiliation, Email, Abstract,
Keywords, Heading 1 (auto I., II.), Heading 2 (auto A., B.), Heading
Unnumbered, Figure, Figure Caption, Table Caption, Table Text, Equation,
Reference (auto [1], [2]), Bullet.

Markup
  @title: / @author: / @affil: / @email: / @abstract: / @keywords:
  # Heading            numbered level-1 heading
  #* Heading           unnumbered level-1 heading (Acknowledgment, References)
  ## Heading           level-2 heading
  - text               bullet
  !fig label | file.png | caption
  !table label | Title         then pipe rows "| a | b |"; first row = header
  !widths 1.4,1,1              relative column widths (after !table)
  !eq label | equation
  !refs                        the reference list
  % comment
  inline: {i|..} {b|..} {sup|..} {sub|..} {sc|..} {hl|..} (yellow = to fill in)
          [@key] or [@a; @b] citations, numbered by first use
          {ref:label} -> "Fig. 2", "Table III" or "(1)"

    python paper/build_paper.py
"""

import os
import re
import struct
import sys
import zipfile
from datetime import datetime, timezone
from xml.sax.saxutils import escape

HERE = os.path.dirname(os.path.abspath(__file__))
SRC, REFS = os.path.join(HERE, "paper_text.md"), os.path.join(HERE, "references.txt")
FIGDIR, OUT = os.path.join(HERE, "figures"), os.path.join(HERE, "GhostNet_IEEE_Paper.docx")

PAGE = '<w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1077" w:right="811" w:bottom="2438" ' \
       'w:left="811" w:header="709" w:footer="709" w:gutter="0"/>'
COL_TW = 5023                       # one column, twips
FIG_EMU = 4990 * 635                # figure width (twips -> EMU)
ROMAN = ["I", "II", "III", "IV", "V", "VI", "VII", "VIII", "IX", "X", "XI", "XII"]

NS = ('xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
      'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
      'xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" '
      'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
      'xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture"')


# ─── inline markup -> runs ───────────────────────────────────────────────
class Ctx:
    def __init__(self, refkeys, labels):
        self.refkeys, self.labels = refkeys, labels
        self.cite_order = []

    def cite(self, keys):
        nums = []
        for k in keys:
            if k not in self.refkeys:
                sys.exit(f"unknown citation key: {k}")
            if k not in self.cite_order:
                self.cite_order.append(k)
            nums.append(self.cite_order.index(k) + 1)
        nums = sorted(set(nums))
        groups, start = [], nums[0]
        for a, b in zip(nums, nums[1:] + [None]):
            if b != a + 1:
                groups.append((start, a))
                start = b
        parts = []
        for s, e in groups:
            if e - s >= 2:
                parts.append(f"[{s}]–[{e}]")
            else:
                parts.extend(f"[{n}]" for n in range(s, e + 1))
        return ", ".join(parts)


def run(text, props):
    if not text:
        return ""
    rpr = ""
    if "b" in props: rpr += "<w:b/><w:bCs/>"
    if "i" in props: rpr += "<w:i/><w:iCs/>"
    if "sc" in props: rpr += "<w:smallCaps/>"
    if "hl" in props: rpr += '<w:highlight w:val="yellow"/>'
    if "sup" in props: rpr += '<w:vertAlign w:val="superscript"/>'
    if "sub" in props: rpr += '<w:vertAlign w:val="subsc