#!/usr/bin/env python3
"""แปลง progress-presentation.md เป็น HTML ที่ copy ไปวางใน Google Docs ได้

วิธีใช้:
    python3 docs/md_to_html.py
    เปิดไฟล์ docs/progress-presentation.html ใน browser
    กด Ctrl+A แล้ว Ctrl+C จากนั้นวางใน Google Docs
"""

from html import escape
from pathlib import Path
import re

DOCS = Path(__file__).parent
SRC = DOCS / "progress-presentation.md"
OUT = DOCS / "progress-presentation.html"

# Google Docs อ่าน inline style ได้ดีกว่า class จึงฝัง style ตรงแท็ก
STYLE = {
    "h1": "font-size:20pt;font-weight:700;color:#1a3a6b;margin:24pt 0 10pt;",
    "h2": "font-size:15pt;font-weight:700;color:#22508f;margin:18pt 0 8pt;",
    "h3": "font-size:12pt;font-weight:700;color:#333;margin:12pt 0 6pt;",
    "p": "font-size:11pt;line-height:1.55;margin:0 0 8pt;",
    "td": "border:1px solid #999;padding:5pt 8pt;font-size:10pt;vertical-align:top;",
    "th": "border:1px solid #999;padding:5pt 8pt;font-size:10pt;"
          "background:#e8eef7;font-weight:700;text-align:left;",
    "pre": "background:#f4f6f8;border:1px solid #ccd;border-left:3px solid #22508f;"
           "padding:8pt 10pt;font-family:'Courier New',monospace;font-size:9pt;"
           "white-space:pre-wrap;margin:0 0 10pt;",
    "li": "font-size:11pt;line-height:1.55;margin-bottom:3pt;",
}


def inline(text: str) -> str:
    """แปลง **bold**, `code`, emoji marker — escape ก่อนกันแท็กหลุด"""
    out = escape(text)
    out = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", out)
    out = re.sub(r"`(.+?)`",
                 r"<code style='background:#f0f2f5;padding:1pt 3pt;"
                 r"font-family:\"Courier New\",monospace;font-size:9.5pt;'>\1</code>",
                 out)
    return out


def convert(md: str) -> str:
    lines = md.split("\n")
    html: list[str] = []
    i = 0
    in_table = False

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # ปิดตารางเมื่อเจอบรรทัดที่ไม่ใช่แถวตาราง
        if in_table and not stripped.startswith("|"):
            html.append("</table>")
            in_table = False

        # ข้าม HTML comment placeholder
        if stripped.startswith("<!--"):
            i += 1
            continue

        # code block
        if stripped.startswith("```"):
            block: list[str] = []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith("```"):
                block.append(escape(lines[i]))
                i += 1
            html.append(f"<pre style=\"{STYLE['pre']}\">" + "\n".join(block) + "</pre>")
            i += 1
            continue

        # heading
        heading = re.match(r"^(#{1,3})\s+(.*)$", stripped)
        if heading:
            level = len(heading.group(1))
            tag = f"h{level}"
            html.append(f"<{tag} style=\"{STYLE[tag]}\">{inline(heading.group(2))}</{tag}>")
            i += 1
            continue

        # เส้นคั่น
        if stripped in {"---", "***", "___"}:
            html.append("<hr style='border:none;border-top:1px solid #bbb;margin:16pt 0;'>")
            i += 1
            continue

        # ตาราง
        if stripped.startswith("|"):
            cells = [c.strip() for c in stripped.strip("|").split("|")]
            # บรรทัดคั่นหัวตาราง |---|---| ข้ามไป
            if all(re.fullmatch(r":?-{2,}:?", c) for c in cells if c):
                i += 1
                continue
            if not in_table:
                html.append("<table style='border-collapse:collapse;width:100%;"
                            "margin:0 0 12pt;'>")
                in_table = True
                tag, style = "th", STYLE["th"]
            else:
                tag, style = "td", STYLE["td"]
            row = "".join(f"<{tag} style=\"{style}\">{inline(c)}</{tag}>" for c in cells)
            html.append(f"<tr>{row}</tr>")
            i += 1
            continue

        # bullet list
        if re.match(r"^[-*]\s+", stripped):
            html.append("<ul style='margin:0 0 10pt;padding-left:20pt;'>")
            while i < len(lines) and re.match(r"^[-*]\s+", lines[i].strip()):
                item = re.sub(r"^[-*]\s+", "", lines[i].strip())
                html.append(f"<li style=\"{STYLE['li']}\">{inline(item)}</li>")
                i += 1
            html.append("</ul>")
            continue

        # บรรทัดว่าง
        if not stripped:
            i += 1
            continue

        # ย่อหน้าปกติ — รวมบรรทัดที่ต่อเนื่องกันเป็นย่อหน้าเดียว
        # ต้องรวมก่อนเรียก inline() ไม่งั้น **bold** ที่ข้ามบรรทัดจะแปลงไม่ได้
        para: list[str] = []
        while i < len(lines):
            nxt = lines[i].strip()
            if (not nxt or nxt.startswith(("#", "|", "```", "<!--"))
                    or nxt in {"---", "***", "___"}
                    or re.match(r"^[-*]\s+", nxt)):
                break
            para.append(nxt)
            i += 1
        html.append(f"<p style=\"{STYLE['p']}\">{inline(' '.join(para))}</p>")

    if in_table:
        html.append("</table>")

    body = "\n".join(html)
    return (
        "<!DOCTYPE html>\n<html lang='th'>\n<head>\n<meta charset='utf-8'>\n"
        "<title>รายงานความก้าวหน้า MIMIC Defender</title>\n</head>\n"
        "<body style=\"font-family:'Sarabun','Segoe UI',Arial,sans-serif;"
        "max-width:820px;margin:0 auto;padding:28pt;color:#1a1a1a;\">\n"
        f"{body}\n</body>\n</html>\n"
    )


if __name__ == "__main__":
    if not SRC.exists():
        raise SystemExit(f"ไม่พบไฟล์ {SRC}")
    OUT.write_text(convert(SRC.read_text(encoding="utf-8")), encoding="utf-8")
    print(f"Created: {OUT}")
    print(f"Size: {OUT.stat().st_size:,} bytes")
