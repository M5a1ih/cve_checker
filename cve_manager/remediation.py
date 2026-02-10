# remediation.py
import subprocess

@app.route("/", methods=["POST"])
def fix_cve():
    cve_id = request.form.get("cve")

    logging.info(f"FIX requested for CVE: {cve_id}")

    # ŞU AN: kontrollü / simülasyon
    logging.info(f"Simulated remediation applied for {cve_id}")

    return redirect("/")
