# AVS — AutoVuln Scanner (Surface DNA)

Network vulnerability **assessment** assistant: fast parallel discovery, targeted service fingerprinting (Nmap), **intel fusion** (DNS / HTTP(S) / TLS), plugin-style findings, CVE hints (NVD API), PDF/JSON export, and a **Spectral Surface** visualization.

> **Legal:** Use only on systems you own or have **written permission** to test. Unauthorized scanning is illegal in many jurisdictions.

> **Reality check:** No scanner can guarantee detection of *every* vulnerability. AVS maximizes **observable network signal**; combine with authenticated reviews and manual testing for important systems.

---

## How the scanner operates (end-to-end)

1. **Target input** — You enter hostname(s) or IP(s). The app resolves DNS to IPv4 (`scanner.py` / `intel_fusion.py`).

2. **Profile selection**
   - **hyper** (default): **Pulse sweep** — hundreds of TCP connect probes in parallel (`turbo_sweep.py`) across a curated high-signal port list → **Nmap `-sV` only on open ports** (`scanner.py`) for speed.
   - **quick / standard / deep**: Classic Nmap-only paths (`-F`, `-sV`, or `-sV -sC` with deeper version probes).

3. **Service table** — Open ports with service names and version strings from Nmap.

4. **Intel fusion** (optional checkbox / CLI flag) — Parallel probes:
   - Reverse DNS (PTR), DNS aliases  
   - HTTP(S) `GET /`: status line, `Server`, page title, security-related headers  
   - TLS: negotiated version, cert subject/issuer/SANs, expiry (`intel_fusion.py`)

5. **Plugins** — Structured findings (plugin ID, severity, CVSS-style score, remediation):
   - Risky exposures (Telnet, FTP, SMB, databases, Redis, etc.)  
   - TLS protocol weakness, cert issues  
   - Web hardening (HSTS, framing, cookies, etc.) when intel is available (`plugins.py`)

6. **CVE hints** — Keyword search against **NIST NVD API 2.0** per service/version (`cve_lookup.py`). This is *indicative*, not a full CPE correlation engine.

7. **Risk score** — Aggregated from finding severities (`vuln_checker.py`).

8. **Persistence** — SQLite history + JSON blobs for ports, findings, intel (`database.py`).

9. **Outputs** — PDF report, export folder with `scan_bundle.json`, matplotlib **dashboard** and **Spectral Surface** map (`spectral_surface.py`).

---

## Repository layout

| File / folder | Role |
|---------------|------|
| `main.py` | CustomTkinter GUI, threaded scan pipeline |
| `cli.py` | Headless JSON runs (servers / automation) |
| `config.py` | Login credentials via env vars |
| `scanner.py` | Nmap profiles + Hyper (pulse + targeted Nmap) |
| `turbo_sweep.py` | Parallel TCP pulse sweep |
| `intel_fusion.py` | DNS + HTTP(S) + TLS fusion |
| `plugins.py` | Finding records + intel plugins |
| `vuln_checker.py` | Merges plugins + scoring |
| `cve_lookup.py` | NVD keyword lookup |
| `database.py` | SQLite scan history |
| `report_generator.py` | PDF |
| `exporter.py` | JSON + text bundle |
| `dashboard.py` | Classic charts |
| `spectral_surface.py` | Polar port/risk map |
| `login.py` | GUI login |
| `requirements.txt` | Python dependencies |
| `scripts/` | Setup and launch helpers |

---

## Prerequisites

- **Python 3.10+** (3.12+ recommended)
- **Nmap** installed and on your **PATH** ([Windows download](https://nmap.org/download.html))
- Internet access for **NVD** CVE lookups (optional in CLI with `--no-cve`)

---

## Install & run (GUI)

```powershell
cd AutoVulnScanner
py -3 -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt
.\.venv\Scripts\python main.py
```

Or use the helper (expects `.venv` under project root):

```powershell
.\scripts\setup_venv.ps1
.\scripts\run_avs.ps1
```

**Default login:** `admin` / `admin123` — change via environment variables (see `env.example`).

**Skip login window** (lab only):

```powershell
$env:AVS_SKIP_LOGIN="1"
.\.venv\Scripts\python main.py
```

---

## Run headless (tool / server / CI)

From the `AutoVulnScanner` directory:

```powershell
.\.venv\Scripts\python cli.py -t scanme.nmap.org --profile hyper -o report.json
```

Options:

- `--profile` `quick` | `standard` | `deep` | `hyper`
- `--no-fusion` — skip HTTP/TLS/DNS intel (faster)
- `--no-cve` — skip NVD calls (faster, offline-friendly)
- `-o file.json` — write bundle; omit for stdout

---

## Deploy as a tool

| Scenario | Approach |
|----------|----------|
| **Analyst laptop** | GUI (`main.py`) or CLI (`cli.py`) after venv + Nmap |
| **Shared machine** | Same + set `AVS_USER` / `AVS_PASSWORD`; avoid `AVS_SKIP_LOGIN` in production |
| **Automation** | Schedule `cli.py` with `-o`; ingest JSON in SIEM/ticketing |
| **Windows EXE (optional)** | `pip install pyinstaller` then e.g. `pyinstaller --noconfirm --windowed --name AVS main.py` (test hidden-imports for `customtkinter` if the build misses DLLs) |

**Docker note:** The GUI needs a display; headless use is better suited to **`cli.py`** in a slim image with Nmap installed (`apt install nmap` on Debian-based images).

---

## Push to GitHub (`Abhishek-7j/AVS`)

1. Create an empty repository **AVS** under GitHub user **Abhishek-7j** (no README/license on GitHub if you want a clean first push).

2. From this project folder:

```powershell
cd AutoVulnScanner
git init
git add .
git commit -m "Initial commit: AVS Surface DNA scanner"
git branch -M main
git remote add origin https://github.com/Abhishek-7j/AVS.git
git push -u origin main
```

3. If prompted, authenticate with a **Personal Access Token** (GitHub → Settings → Developer settings) or GitHub CLI (`gh auth login`).

---

## Contributing & safety

Improve plugins and intel checks in small, reviewable changes. Never add exploit payloads or unauthenticated destructive tests without clear scope and legal use documentation.
