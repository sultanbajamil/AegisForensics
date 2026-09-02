# 🛡️ AegisForensics: Digital Forensics & Incident Response (DFIR) Suite

A modular, high-performance Python-based digital forensics tool designed to inspect live systems, offline directory mounts, and volatile memory (RAM) dumps. 

This project is built to demonstrate end-to-end digital forensic engineering capability, parsing low-level Windows structures, decrypting Chromium credentials, reading Windows Event Logs, and carving patterns from raw memory blocks without consuming excessive system resources.

---

## 🛠️ Key Features

### 1. Live System & Offline Partition Ingestion
- Runs in **Live Mode** directly on the host machine.
- Runs in **Offline Mode** targeting a specific folder, drive letter, or mounted disk image partition.

### 2. Browser Forensics (Chromium & Firefox)
- **Credential Decryption:** Extracts and decrypts saved usernames and passwords from Chromium browsers (Google Chrome, Microsoft Edge, Brave) using the Windows Data Protection API (DPAPI) and AES-256-GCM.
- **Browsing History:** Extracts SQLite history records and matches visits to readable UTC timestamps.

### 3. Windows Event Log (`.evtx`) Parser
- Parses raw binary event log files without relying on native Windows Event APIs (fully cross-platform).
- Extracts critical cybersecurity indicator events:
  - **Successful/Failed Logons (IDs 4624 / 4625):** Including logon type (network vs interactive) and source IP addresses.
  - **Process Creations (ID 4688 / Sysmon ID 1):** Command line execution monitoring.
  - **Service Installations (ID 7045):** Identifies persistence entrypoints.
  - **Cleared Audit Logs (IDs 1102 / 104):** Flags anti-forensics activity.

### 4. Recycle Bin Recovery & Parsing
- Parses binary metadata `$I` files (both Version 1 and Version 2 structs) to extract:
  - Original file path and filename.
  - Deletion timestamp.
  - File size.
- Detects the existence of the corresponding `$R` payload data files and provides **one-click recovery** to restore deleted items.

### 5. High-Performance Memory Carver (RAM analysis)
- Scans volatile RAM dumps (`.raw`, `.dmp`, `.img`) in stream-buffered chunks (4MB default, 64KB overlap) to prevent memory crashes.
- Employs pre-compiled regular expressions to extract indicators of compromise (IOCs):
  - IPv4 Addresses (validated octets).
  - HTTP/HTTPS URLs.
  - Email addresses.
  - AWS Access Keys (`AKIA` tokens).
  - PEM Private Key Headers.

### 6. Interactive Web Dashboard & Custom Reporting
- Built using **Streamlit** and **Plotly** to visualize logon timelines and running process distribution.
- Generates professional, interactive **HTML forensic reports** containing search/filter tables, timelines, and security alert badges.
- Exports raw forensic data to **JSON** and **CSV**.

---

## 🏗️ Architecture

```
AegisForensics/
├── main.py                     # CLI Entry Point
├── app.py                      # Streamlit Web App Entry Point
├── aegis_forensics/            # Core library package
│   ├── core/
│   │   ├── engine.py           # Coordinating forensic manager
│   │   └── memory.py           # Custom RAM pattern carver
│   ├── plugins/
│   │   ├── browser_forensics.py# Chromium/Firefox extractor
│   │   ├── event_logs.py       # .evtx parser
│   │   ├── file_recovery.py    # Recycle Bin struct parser
│   │   └── system_info.py      # Host metadata & USB history
│   └── utils/
│       ├── decryptor.py        # DPAPI & AES-256-GCM decryptor
│       └── reporter.py         # HTML & JSON report engine
├── tests/                      # Automated unit tests
│   ├── test_memory.py          # Memory regex unit tests
│   └── test_recovery.py        # Binary $I struct tests
└── requirements.txt            # Package dependencies
```

---

## ⚡ Setup & Installation

### Prerequisites
- Python 3.8 or higher.
- Windows (preferred for DPAPI browser password decryption and live registry checks).

### Installation Steps

1. **Clone the repository and enter the directory:**
   ```bash
   git clone https://github.com/yourusername/AegisForensics.git
   cd AegisForensics
   ```

2. **Create a virtual environment:**
   ```bash
   python -m venv .venv
   .venv\\Scripts\\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

---

## 🚀 Usage Guide

### 1. Interactive Streamlit Web Dashboard
Run the following command to open the beautiful interactive dashboard in your web browser:
```bash
streamlit run app.py
```

### 2. Command Line Interface (CLI)

#### Live Host Investigation:
Analyze the active machine and generate a report:
```bash
python main.py --live --html output_report.html --json output_raw.json
```

#### Offline Ingestion:
Analyze a mounted image partition or copy of a system drive:
```bash
python main.py --offline E:\\ --html offline_report.html
```

#### Memory Dump Carving:
Carve a memory dump in real-time:
```bash
python main.py --memory E:\\cases\\ram_dump.raw --json carved_data.json
```

---

## 🧪 Running Tests
Unit tests verify the accuracy of the memory regex parser and the Recycle Bin binary structure decoder. Run them using:
```bash
python -m unittest discover -s tests
```
