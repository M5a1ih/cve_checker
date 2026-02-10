# CVE Vulnerability Manager

A mini dashboard for Windows that scans installed applications, matches them against the NVD CVE database, enriches results with KEV information, and provides remediation suggestions.

---

## 🚀 Features

### Inventory Collection
- Uses `wmic product get Name, Version` to list installed applications and versions.
- Displays results in a table.
- Provides downloadable CSV/Excel output (`installed_programs.csv`).

### CVE Database (SQLite)
- Downloads CVE records from the NVD `cves/2.0` API and stores them in `cve.db`.
- On first run:
  - Fetches data for the last X years (configurable) in **120-day segments**.
- On subsequent runs:
  - Performs **incremental updates**:
    - Finds the latest `published` date in the database,
    - Downloads only new CVEs published after that date.
- Uses `INSERT OR IGNORE` to avoid duplicate entries.

### PC-Specific CVE Matching
- `inventory.py` collects installed programs.
- `matcher.py` normalizes names and matches them against CPE strings.
- CVEs matching installed applications are shown in the **top table**.
- Other CVEs (not matched but within filters) are shown in the **bottom table**.

### Filtering and Sorting
- Display modes:
  - `Last 120 days`
  - `After 2022`
  - `All CVEs in database`
- CVSS threshold (`CVSS ≥ x.x`)
- Free-text search:
  - Searches CVE ID, description, and CPE fields simultaneously.
  - Examples: `chrome`, `144.0.7559.59`, `intel`, `CVE-2019-18278`
- Sorting:
  - First by `kev_flag` (Known Exploited Vulnerabilities),
  - Then by `cvss_score` (descending).

### KEV (Known Exploited Vulnerabilities) Integration
- `kev.py` enriches CVEs with KEV flags.
- UI highlights:
  - KEV: yellow (`kev-row`)
  - Critical (CVSS ≥ 9): red (`critical-row`)
  - High (CVSS ≥ 7): orange (`high-row`)

### Fix Button and Command Execution
- Each CVE row includes:
  - `Fix` button
  - **Default**: shows suggested command (e.g., `winget`) in **simulation mode**.
  - If `Run actual command` checkbox is selected:
    - Executes the command via `subprocess.run`,
    - Displays output/error in flash messages,
    - Logs results to `fix.log`.
- Ensures controlled remediation without accidental updates.

### AI-Powered Remediation Suggestions (Optional)
- Each CVE row includes **“Get AI suggestion”** button:
  - Generates a suggestion for that CVE only.
- Workflow:
  1. If `OPENAI_API_KEY` is set:
     - Calls OpenAI Chat Completions API (`gpt-4o-mini`).
     - Produces **short, step-by-step remediation guidance in Turkish** using CVE details and NVD remediation URLs.
  2. If:
     - `OPENAI_API_KEY` is missing, or
     - API call fails,
     - Falls back to **rule-based suggestions** using vendor patch URLs.
- UI behavior:
  - If `OPENAI_API_KEY` is missing:
    - Shows info message: `AI suggestions are enabled when OPENAI_API_KEY is set.`
    - Rows display: “AI disabled (no OPENAI_API_KEY).”
  - If set:
    - “Get AI suggestion” buttons are active.

### Simple and Clear UI
- Two main tables:
  - CVEs matching installed applications,
  - Other CVEs.
- Columns:
  - CVE ID (as link),
  - Description (shortened),
  - Severity, CVSS,
  - CPE (Affected Products),
  - Suggested Fix (NVD remediation),
  - Published date,
  - Action (Fix / Get AI suggestion).
- Flash messages:
  - Success (green),
  - Error (red),
  - Info / AI suggestion (blue),
  - Command outputs formatted with `white-space: pre-wrap`.

---

## 📂 File Structure
- `run.py` → Entry point, bootstrap, and Flask startup.
- `server.py` → Flask web server and HTTP endpoints.
- `core.py` → Database schema and NVD feed management.
- `inventory.py` → Collects installed programs.
- `matcher.py` → Matches program names with CPE strings.
- `kev.py` → KEV flagging logic.
- `templates/index.html` → Dashboard HTML + CSS template.

---

## 🔧 Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/USERNAME/cve-vulnerability-manager.git
   cd cve-vulnerability-manager
2.	Install dependencies: 
3.	pip install -r requirements.txt
(At minimum, Flask and requests must be installed.)
4.	(Optional) Enable AI suggestions with OpenAI API key: 
5.	setx OPENAI_API_KEY "YOUR_OPENAI_API_KEY"
Restart terminal.
6.	Run the application: 
7.	python run.py
o	Bootstrap logs will appear in the terminal.
o	Browser will open at http://127.0.0.1:5000.
________________________________________
🔒 Security Notes
•	API keys are never hardcoded.
•	OPENAI_API_KEY is read only from environment variables.
•	NVD API key can also be set via NVD_API_KEY environment variable.
•	Never commit real API keys, .env files, or logs to the repository.
•	Fix button requires explicit confirmation before running real commands.
•	Default behavior is simulation only.
________________________________________
🛠 Roadmap / Development Ideas
•	Real KEV feed integration.
•	Smarter vendor/product-based filtering in NVD.
•	More precise CPE matching by application version.
•	User profile settings (default CVSS threshold, filters, etc.).
________________________________________

