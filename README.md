# cve_checker
CVE_Checker (Last 3 Months)


## Usage

After installing the dependencies, run the application from the command line:

```bash
python cve_checker.py


Example Output
=== Main Menu ===
1 - List installed devices
2 - Generate automatic scan report
3 - Manual CVE query
4 - Review logs
5 - Exit

+----------------------------+-------------------+
| Device                     | Version           |
+----------------------------+-------------------+
| Intel(R) Ethernet Controller | 12.18.9         |
| NVIDIA GeForce GTX 1050    | 31.0.15.5222      |
| Realtek Audio Device       | Version not found |
+----------------------------+-------------------+

---

## Commit Message Style
Keep commit messages simple and developer‑like:
- `feat: add device listing menu`
- `fix: correct CSV encoding to utf-8-sig`
- `docs: update README with usage instructions`
- `chore: add requirements.txt`

---

## Repository Description
On GitHub, you can describe the repo as:
> A Python tool to list Windows devices, fetch CVEs from NVD, and generate security reports.

---


# Windows Device & CVE Reporter

This project is a Python application that collects installed devices and drivers on Windows, 
fetches CVE data from the NVD API (last 3 months), and generates security reports.

## Features
- List installed devices and drivers
- Update CVE database from NVD
- Generate automatic scan reports
- Perform manual CVE queries
- Review logs (recent CVEs)
- Export results to CSV files on the Desktop

## Installation
```bash
git clone https://github.com/yourusername/cve-reporter.git
cd cve-reporter
pip install -r requirements.txt


