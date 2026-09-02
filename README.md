# 🔬 AegisForensics: Digital Forensics & Incident Response (DFIR) Suite

A modular, high-performance Python-based digital forensics toolkit designed to analyze **live Windows systems**, **offline mounted disks**, and **volatile memory (RAM) dumps**. 

AegisForensics provides end-to-end DFIR capabilities, including parsing low-level Windows structures, decrypting Chromium credentials, interpreting raw Windows Event Logs (`.evtx`), recovering deleted items via the Recycle Bin `$I` struct, and carving artifacts from raw memory.

---

## 🏗️ Architecture

```text
AegisForensics/
├── main.py                     # CLI Entry Point
├── app.py                      # Streamlit Interactive Web Dashboard
├── aegis_forensics/            # Core forensic engine package
│   ├── core/
│   │   ├── engine.py           # Master forensics coordinator
│   │   └── memory.py           # High-speed chunk-streamed RAM pattern carver
│   ├── plugins/
│   │   ├── browser_forensics.py# Chromium & Firefox history and credential parser
│   │   ├── event_logs.py       # Standalone binary .evtx event log parser
│   │   ├── file_recovery.py    # Recycle Bin $I/$R binary struct parser & recovery
│   │   └── system_info.py      # Host metadata, OS details, and USB history
│   └── utils/
│       ├── decryptor.py        # Windows DPAPI & AES-256-GCM decryptor
│       └── reporter.py         # Responsive HTML, JSON, and CSV report engine
├── tests/                      # Unit and integration tests
├── requirements.txt            # Python dependencies
└── README.md                   # Project documentation
```

---

## 🌟 Key Capabilities

### 1. Live System & Offline Disk Inspection
- **Live Mode**: Directly inspects the current executing Windows host.
- **Offline Mode**: Analyzes mounted forensic drive letters, raw folders, or extracted image folders without booting the system.

### 2. Browser Forensics (Chromium & Firefox)
- **Credential Decryption**: Recovers and decrypts saved usernames and passwords from Chromium browsers (Google Chrome, Microsoft Edge, Brave) using the Windows Data Protection API (`DPAPI`) and `AES-256-GCM`.
- **Browsing History & Downloads**: Queries SQLite databases and normalizes Unix/WebKit timestamps into standardized UTC records.

### 3. Native Windows Event Log (`.evtx`) Analysis
- Parses binary event logs without relying on native Windows Event APIs (fully cross-platform compatible).
- Correlates critical security event IDs:
  - **4624 / 4625**: Successful and failed logon attempts with logon types and IP addresses.
  - **4688 / Sysmon 1**: Process creation tracking with command line arguments.
  - **7045**: New service installation (persistence detection).
  - **1102 / 104**: Audit log tampering and log clearance events.

### 4. Recycle Bin Forensics & File Recovery
- Parses binary `$I` metadata structures (both Version 1 and Version 2 formats) to extract original file names, original directory paths, file sizes, and exact deletion timestamps.
- Pairs with the corresponding `$R` payload data files and provides one-click file restoration.

### 5. High-Performance Volatile RAM Carver
- Scans memory dump files (`.raw`, `.dmp`, `.img`, `.vmem`) using buffered chunk streaming (4MB default chunks with 64KB overlap) to prevent memory exhaustion.
- Extracts key Indicators of Compromise (IOCs) with pre-compiled regular expressions:
  - IPv4 addresses (with validated octet ranges).
  - Web URLs (HTTP/HTTPS).
  - Email addresses.
  - AWS Access Keys (`AKIA` tokens).
  - PEM Private Key headers.

### 6. Interactive Web Dashboard & Multi-Format Reporting
- Features a **Streamlit** dashboard with interactive timeline charts (**Plotly**).
- Exports self-contained, interactive **HTML reports** with search and filter capabilities, as well as raw **JSON** and **CSV** files.

---

## 🚀 Installation & Running

### Prerequisites
- Python 3.8 or higher.
- Windows (recommended for DPAPI credential decryption and live registry checks).

### Step 1: Install Dependencies
```bash
cd AegisForensics
pip install -r requirements.txt
```

### Step 2: Launch the Web Dashboard
```bash
streamlit run app.py
```
The interactive web dashboard will automatically open in your default browser at: **`http://localhost:8501`**.

### Step 3: Run via Command Line (CLI)
You can also run automated forensic scans directly from the terminal:
```bash
# Run a full live audit and export to an HTML report
python main.py --live --html live_report.html --json live_report.json

# Carve a raw RAM dump for IOCs
python main.py --memory memdump.raw --output memory_results.json

# Inspect an offline drive or mounted volume
python main.py --offline D:\MountedImage --html offline_report.html
```

---

## ⚠️ Disclaimer
AegisForensics is created for academic research, digital forensic investigations, and authorized incident response testing. Ensure proper legal authorization before examining systems or memory captures.
