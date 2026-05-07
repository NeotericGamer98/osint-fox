import os
import csv
import json
from datetime import datetime
from fpdf import FPDF


class PDFReport(FPDF):
    def __init__(self, dark=True):
        super().__init__()
        self.dark = dark
        self.set_auto_page_break(auto=True, margin=20)

    def header(self):
        if self.dark:
            self.set_text_color(232, 117, 26)
        else:
            self.set_text_color(0, 102, 204)
        self.set_font("Helvetica", "B", 10)
        self.cell(0, 8, "OSINT FOX - Intelligence Report", align="C", new_x="LMARGIN", new_y="NEXT")
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")

    def section_title(self, title):
        if self.dark:
            self.set_text_color(232, 117, 26)
        else:
            self.set_text_color(0, 102, 204)
        self.set_font("Helvetica", "B", 13)
        self.cell(0, 10, title, new_x="LMARGIN", new_y="NEXT")
        self.ln(2)

    def sub_category(self, text):
        if self.dark:
            self.set_text_color(200, 200, 200)
        else:
            self.set_text_color(60, 60, 60)
        self.set_font("Helvetica", "B", 11)
        self.cell(0, 8, text, new_x="LMARGIN", new_y="NEXT")
        self.ln(1)

    def key_value(self, key, value):
        self.set_font("Helvetica", "", 10)
        if self.dark:
            self.set_text_color(180, 180, 200)
        else:
            self.set_text_color(80, 80, 100)
        kw = self.get_string_width(key) + 4
        self.cell(kw, 7, key)
        if self.dark:
            self.set_text_color(220, 220, 220)
        else:
            self.set_text_color(40, 40, 40)
        self.cell(0, 7, str(value), new_x="LMARGIN", new_y="NEXT")


def export_to_pdf(results_flat, filepath, target=None, dark=True):
    pdf = PDFReport(dark=dark)
    pdf.alias_nb_pages()
    pdf.add_page()

    if dark:
        pdf.set_text_color(232, 117, 26)
    else:
        pdf.set_text_color(0, 102, 204)
    pdf.set_font("Helvetica", "B", 20)
    pdf.cell(0, 15, "OSINT FOX", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 12)
    if dark:
        pdf.set_text_color(200, 200, 200)
    else:
        pdf.set_text_color(60, 60, 60)
    pdf.cell(0, 8, "Open Source Intelligence Report", align="C", new_x="LMARGIN", new_y="NEXT")
    if target:
        pdf.cell(0, 8, f"Target: {target}", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 8, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(10)

    for key, value in results_flat:
        if not key and not value:
            pdf.ln(3)
            continue
        if key.startswith("[") and key.endswith("]"):
            pdf.sub_category(key.strip("[]"))
        elif key.startswith("  "):
            pdf.key_value(key.strip(), value)
        elif key in ("Scan Time", "Module", "Description"):
            pdf.key_value(key, value)

    pdf.output(filepath)
    return filepath


def export_to_txt(results_flat, filepath, target=None):
    lines = []
    lines.append("=" * 60)
    lines.append("                    OSINT FOX")
    lines.append("          Open Source Intelligence Report")
    lines.append("=" * 60)
    lines.append("")
    if target:
        lines.append(f"  Target: {target}")
    lines.append(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")

    for key, value in results_flat:
        if not key and not value:
            lines.append("")
            continue
        if key.startswith("[") and key.endswith("]"):
            section = key.strip("[]")
            lines.append(f"\n{'─' * 50}")
            lines.append(f"  {section}")
            lines.append(f"{'─' * 50}")
        elif key.startswith("  "):
            lines.append(f"    {key.strip()}: {value}")
        else:
            lines.append(f"  {key}: {value}")

    lines.append("")
    lines.append("=" * 60)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return filepath


def export_to_csv(results_flat, filepath, target=None):
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["OSINT FOX Report", target or "N/A", datetime.now().isoformat()])
        w.writerow([])
        for key, value in results_flat:
            if not key and not value:
                w.writerow([])
                continue
            if key.startswith("[") and key.endswith("]"):
                w.writerow([key.strip("[]"), ""])
            elif key.startswith("  "):
                w.writerow([key.strip(), value])
            else:
                w.writerow([key, value])
    return filepath


def export_to_json(results_flat, filepath, target=None):
    data = {
        "report": "OSINT FOX Intelligence Report",
        "target": target,
        "generated": datetime.now().isoformat(),
        "sections": {},
    }
    current_section = "General"
    for key, value in results_flat:
        if key.startswith("[") and key.endswith("]"):
            current_section = key.strip("[]")
            if current_section not in data["sections"]:
                data["sections"][current_section] = []
        elif key and value:
            data["sections"].setdefault(current_section, []).append(
                {"key": key.strip(), "value": value}
            )
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return filepath


def export_to_html(results_flat, filepath, target=None, dark=True):
    bg = "#1a1a2e" if dark else "#ffffff"
    fg = "#e0e0e0" if dark else "#222222"
    accent = "#e8751a" if dark else "#0066cc"
    border = "#333366" if dark else "#cccccc"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>OSINT FOX Report</title>
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family:'Segoe UI',Arial,sans-serif; background:{bg}; color:{fg}; padding:30px; }}
h1 {{ color:{accent}; border-bottom:2px solid {accent}; padding-bottom:8px; }}
h2 {{ color:{accent}; margin:20px 0 8px; }}
table {{ width:100%; border-collapse:collapse; margin:6px 0 12px; }}
td {{ padding:4px 10px; border:1px solid {border}; }}
td:first-child {{ font-weight:bold; width:220px; color:{accent}; }}
.footer {{ margin-top:30px; color:#888; font-size:12px; text-align:center; }}
</style></head><body>
<h1>OSINT FOX &mdash; Intelligence Report</h1>
<p><strong>Target:</strong> {target or "N/A"}<br>
<strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
"""
    current_section = ""
    for key, value in results_flat:
        if not key and not value:
            continue
        if key.startswith("[") and key.endswith("]"):
            section_name = key.strip("[]")
            if section_name != current_section:
                current_section = section_name
                html += f"<h2>{section_name}</h2>\n<table>\n"
        elif key.startswith("  ") or key in ("Scan Time", "Module", "Description"):
            html += f"<tr><td>{key.strip()}</td><td>{value}</td></tr>\n"
        elif not key and value:
            html += f"<tr><td colspan='2'>{value}</td></tr>\n"

    html += """</table>
<div class="footer">Generated by OSINT FOX</div>
</body></html>"""
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)
    return filepath


EXPORT_FORMATS = {
    "PDF": ("PDF files", "*.pdf", export_to_pdf),
    "TXT": ("Text files", "*.txt", export_to_txt),
    "CSV": ("CSV files", "*.csv", export_to_csv),
    "JSON": ("JSON files", "*.json", export_to_json),
    "HTML": ("HTML files", "*.html", export_to_html),
}
