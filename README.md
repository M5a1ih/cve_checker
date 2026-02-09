# CVE Checker

A Python tool to list Windows devices and drivers, fetch CVE data from NVD (last 3 months), and generate security reports.

## Features
- List installed devices and drivers (with version info if available)
- Fetch CVE data from NVD (last 3 months)
- Generate automatic scan reports
- Perform manual CVE queries
- Review logs (recent CVEs)
- Export results to CSV files on Desktop

## Installation
```bash
git clone https://github.com/M5a1ih/cve_checker.git
cd cve_checker
pip install -r requirements.txt



##Usage
python cve_checker.py


=== Main Menu ===
1 - List installed devices
2 - Generate automatic scan report
3 - Manual CVE query
4 - Review logs
5 - Exit

Example Output

+----------------------------+-------------------+
| Device                     | Version           |
+----------------------------+-------------------+
| Intel(R) Ethernet Controller | 12.18.9         |
| NVIDIA GeForce GTX 1050    | 31.0.15.5222      |
| Realtek Audio Device       | Versiyon bulunamadı |
+----------------------------+-------------------+

