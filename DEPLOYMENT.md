# AVS — Deployment & Operations Guide

This guide provides step-by-step instructions on installing, deploying, and running AutoVulnScanner (AVS) in various environments (local, containerized, and CI/CD pipelines).

---

## 1. Local Deployment

### Prerequisites
- **Python**: version 3.9 or higher.
- **Nmap**: AVS requires Nmap on your system PATH to execute version fingerprints and vulnerability scripts.
  - **Windows**: Download and run the installer from [Nmap Download](https://nmap.org/download.html). Ensure "Add Nmap to system PATH" is checked during setup.
  - **Linux (Debian/Ubuntu)**: `sudo apt-get update && sudo apt-get install -y nmap`
  - **macOS**: `brew install nmap`

### Setup Instructions
1. Clone the repository:
   ```bash
   git clone https://github.com/Abhishek-7j/AVS.git
   cd AVS
   ```
2. Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   # Windows:
   .venv\Scripts\activate
   # Linux/macOS:
   source .venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Run the scanner:
   - **Headless mode** (Command Line):
     ```bash
     python cli.py -t scanme.nmap.org --profile quick
     ```
   - **GUI mode** (Desktop Application):
     ```bash
     python main.py
     ```

---

## 2. Docker Deployment

AVS comes with a preconfigured `Dockerfile` that packages Python, pip libraries, and Nmap automatically. This is ideal for headless servers and containerized tasks.

### Build the Image
```bash
docker build -t avs-scanner .
```

### Run the Container
Run a quick scan on a target and output the JSON directly:
```bash
docker run --rm avs-scanner -t scanme.nmap.org --profile quick
```

To write scan output to a local directory, mount a volume:
```bash
docker run --rm -v $(pwd):/output avs-scanner -t scanme.nmap.org --profile standard -o /output/scan_report.json
```

---

## 3. Authenticated (Credential-Based) Scanning

AVS supports authenticated security audits of target configurations for **SSH** (port 22) and **MySQL** (port 3306). 

To perform credential-based scans, create a `.env` file in the project root:

```env
# SSH Credentials (optional)
AVS_SSH_USER=root
AVS_SSH_PASS=yoursecurepassword
# AVS_SSH_KEY=/path/to/id_rsa

# MySQL Credentials (optional)
AVS_MYSQL_USER=admin
AVS_MYSQL_PASS=rootpassword
```

When AVS runs, it detects open ports. If port 22 or 3306 is open, it automatically attempts authentication using the loaded credentials and performs configuration checks (e.g. gathering OS info, checking for empty database passwords, verifying root login restrictions).

---

## 4. CI/CD Integration (GitHub Actions)

You can easily run AVS as a security gate in your CI/CD pipelines to monitor exposed ports and missing security headers.

Create a file named `.github/workflows/security-scan.yml` in your repository:

```yaml
name: Continuous Security Scan

on:
  push:
    branches: [ "main" ]
  schedule:
    - cron: '0 0 * * 1' # Run weekly on Mondays

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install System dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y nmap

      - name: Install Python dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt

      - name: Run AVS Scan
        run: |
          python cli.py -t scanme.nmap.org --profile standard -o scan_report.json

      - name: Upload Scan Report Artifact
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: scan_report.json
```

---

## 5. Legality & Safe Usage

> [!WARNING]
> Scanning systems without authorization is illegal in most jurisdictions. Ensure you have explicit written consent from the network/system owner before conducting scans with AVS.
