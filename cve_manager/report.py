# report.py
from fpdf import FPDF

def generate_pdf(rows):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=10)

    pdf.cell(200, 10, "Executive CVE Risk Report", ln=True)

    for r in rows:
        pdf.multi_cell(0, 8, f"{r[2]} | {r[3]} | CVSS {r[4]}")
    pdf.output("Executive_Report.pdf")
