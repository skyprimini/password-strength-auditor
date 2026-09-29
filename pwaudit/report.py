"""Render a batch audit as a standalone HTML file.

The point of this report is to be shareable: something you can hand to a team
lead to decide what gets rotated first. That shapes two decisions.

It is entirely self-contained, with the styles and the sorting script inline,
so it survives being emailed around without breaking.

And it never contains a password. Only the label, the score, and the derived
numbers are written out. A report that leaked the credentials it was auditing
would be worse than no report at all.
"""

from __future__ import annotations

import datetime
import html

from . import crack_time
from .batch import BatchRow, summarise

# Chosen to stay distinguishable in greyscale and for the common forms of
# colour blindness, rather than a plain red-to-green ramp.
SCORE_COLOURS = {
    "very weak":   ("#7f1d1d", "#fee2e2"),
    "weak":        ("#9a3412", "#ffedd5"),
    "fair":        ("#854d0e", "#fef9c3"),
    "strong":      ("#155e75", "#cffafe"),
    "very strong": ("#14532d", "#dcfce7"),
}

STYLE = """
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { margin: 0; padding: 32px 20px; background: #f6f5f1; color: #14181d;
       font: 15px/1.6 "Segoe UI", -apple-system, Helvetica, Arial, sans-serif; }
.wrap { max-width: 880px; margin: 0 auto; }
h1 { font-size: 1.5rem; margin: 0 0 4px; letter-spacing: -0.01em; }
.meta { color: #5c6570; font-size: 0.88rem; margin: 0 0 26px; }
.cards { display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 26px; }
.card { flex: 1 1 130px; padding: 14px 16px; border-radius: 10px;
        border: 1px solid #ddd8cb; background: #fffdf8; }
.card strong { display: block; font-size: 1.6rem; line-height: 1.1; }
.card span { font-size: 0.78rem; text-transform: uppercase;
             letter-spacing: 0.08em; color: #5c6570; }
table { width: 100%; border-collapse: collapse; background: #fffdf8;
        border: 1px solid #ddd8cb; border-radius: 10px; overflow: hidden; }
th, td { padding: 10px 14px; text-align: left; border-bottom: 1px solid #eee9dd; }
th { background: #f0ece1; font-size: 0.8rem; text-transform: uppercase;
     letter-spacing: 0.06em; cursor: pointer; user-select: none; }
th:hover { background: #e7e2d4; }
th[aria-sort="ascending"]::after { content: " \\2191"; }
th[aria-sort="descending"]::after { content: " \\2193"; }
tr:last-child td { border-bottom: 0; }
.pill { display: inline-block; padding: 2px 10px; border-radius: 999px;
        font-size: 0.82rem; font-weight: 600; }
.num { font-variant-numeric: tabular-nums; }
footer { margin-top: 24px; color: #5c6570; font-size: 0.82rem; }
@media (prefers-color-scheme: dark) {
  body { background: #11161c; color: #e7e6e1; }
  .card, table { background: #171d26; border-color: #2a313c; }
  th { background: #1e2530; }
  th:hover { background: #262e3b; }
  td { border-color: #242b35; }
  .meta, .card span, footer { color: #98a2ae; }
}
"""

SORT_SCRIPT = """
document.querySelectorAll('th[data-key]').forEach(function (th, index) {
  th.addEventListener('click', function () {
    var table = th.closest('table');
    var body = table.tBodies[0];
    var rows = Array.prototype.slice.call(body.rows);
    var numeric = th.dataset.type === 'number';
    var asc = th.getAttribute('aria-sort') !== 'ascending';

    table.querySelectorAll('th').forEach(function (h) { h.removeAttribute('aria-sort'); });
    th.setAttribute('aria-sort', asc ? 'ascending' : 'descending');

    rows.sort(function (a, b) {
      var x = a.cells[index].dataset.sort;
      var y = b.cells[index].dataset.sort;
      if (numeric) { x = parseFloat(x); y = parseFloat(y); }
      if (x < y) return asc ? -1 : 1;
      if (x > y) return asc ? 1 : -1;
      return 0;
    });
    rows.forEach(function (r) { body.appendChild(r); });
  });
});
"""


def _pill(label: str) -> str:
    fg, bg = SCORE_COLOURS.get(label, ("#333", "#eee"))
    return f'<span class="pill" style="color:{fg};background:{bg}">{html.escape(label)}</span>'


def render(rows: list[BatchRow], title: str = "Password audit") -> str:
    """Build the report. Passwords are never included, only their labels."""
    stats = summarise(rows)
    generated = datetime.datetime.now().strftime("%d %B %Y at %H:%M")

    cards = []
    cards.append(f'<div class="card"><strong>{stats["total"]}</strong><span>audited</span></div>')
    for label, count in stats["by_label"].items():
        if count:
            fg, _ = SCORE_COLOURS.get(label, ("#333", "#eee"))
            cards.append(
                f'<div class="card"><strong style="color:{fg}">{count}</strong>'
                f'<span>{html.escape(label)}</span></div>'
            )

    body_rows = []
    for row in rows:
        fast = next(e.human for e in crack_time.estimate_all(row.result.entropy)
                    if e.key == "offline_fast_hash")
        weaknesses = ", ".join(f.kind for f in row.result.findings) or "none found"
        body_rows.append(
            "<tr>"
            f'<td data-sort="{html.escape(row.identifier.lower())}">{html.escape(row.identifier)}</td>'
            f'<td data-sort="{row.result.score}">{_pill(row.result.label)}</td>'
            f'<td class="num" data-sort="{row.result.entropy:.2f}">{row.result.entropy:.1f}</td>'
            f'<td data-sort="{row.result.entropy:.2f}">{html.escape(fast)}</td>'
            f'<td data-sort="{html.escape(weaknesses)}">{html.escape(weaknesses)}</td>'
            "</tr>"
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<style>{STYLE}</style>
</head>
<body>
<div class="wrap">
  <h1>{html.escape(title)}</h1>
  <p class="meta">Generated {generated} by pwaudit. Weakest entry: <strong>{html.escape(str(stats["weakest"]))}</strong>.</p>

  <div class="cards">{"".join(cards)}</div>

  <table>
    <thead>
      <tr>
        <th data-key="identifier">Identifier</th>
        <th data-key="score" data-type="number">Strength</th>
        <th data-key="entropy" data-type="number">Bits</th>
        <th data-key="crack" data-type="number">Offline fast hash</th>
        <th data-key="weaknesses">Weaknesses</th>
      </tr>
    </thead>
    <tbody>{"".join(body_rows)}</tbody>
  </table>

  <footer>
    Passwords themselves are never written into this report, only their labels
    and the scores derived from them. Column headers sort the table.
  </footer>
</div>
<script>{SORT_SCRIPT}</script>
</body>
</html>
"""


def write(rows: list[BatchRow], path: str, title: str = "Password audit") -> str:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(render(rows, title))
    return path
