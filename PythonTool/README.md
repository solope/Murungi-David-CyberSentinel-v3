# CyberSentinel v2
### Unified Digital Forensics & OSINT Platform — Python Desktop Application

---

## Quick Start

```bash
# 1. Install (only Pillow is optional — for EXIF metadata)
pip install pillow

# 2. Run
python main.py
```

> **tkinter** ships built-in with Python on Windows and macOS.  
> On Ubuntu/Debian: `sudo apt install python3-tk`

---

## Modules & What You Can Upload

| Module | Upload Formats | What it does |
|---|---|---|
| **Log Timeline** | `.log` `.txt` `.evtx` | Parses auth.log, syslog, Event logs — classifies CRITICAL/WARNING/INFO |
| **IP Geolocation** | `.log` `.txt` `.csv` | Single lookup or batch-extract all IPs from a log file |
| **CDR Analyzer** | `.csv` `.txt` | Finds top communication pairs from call records |
| **Email Header Trace** | `.eml` `.txt` `.msg` | Traces phishing origin — SPF, DKIM, sender IP |
| **File Type ID** | Any file | Reads magic bytes — detects real type even if extension changed |
| **Hash Verifier** | Any file | Computes SHA-256 / MD5 / SHA-1 — verify evidence integrity |
| **Steganography** | `.jpg` `.png` `.bmp` `.gif` | Checks for hidden data via size ratio + header anomalies |
| **EXIF Metadata** | `.jpg` `.jpeg` `.png` | Extracts GPS, camera model, timestamps (requires Pillow) |
| **Encoding Detector** | `.txt` `.log` | Detects & decodes Base64, Hex, URL, Binary, ROT13 |
| **Keyword Scanner** | `.txt` `.log` `.csv` `.html` `.json` | Scans for terrorism, narcotics, financial crime, cyber keywords |
| **PowerShell Detector** | `.log` `.txt` `.evtx` `.xml` | Finds encoded commands, AMSI bypass, download cradles, reverse shells |
| **Crypto Wallets** | `.txt` `.log` `.csv` `.json` | Detects Bitcoin, Ethereum, Litecoin, Monero addresses |
| **Network Packets** | `.csv` `.log` | Wireshark export analyzer — suspicious packet flagging |
| **Social Feed** | `.json` `.csv` `.txt` | Import social media exports — keyword flagging |
| **Chain of Custody** | — | Auto-logged; export to CSV |
| **Report Generator** | — | Generates `.txt` report + custody `.csv` |

---

## Project Structure

```
cybersentinel_py/
├── main.py                  ← Entry point — run this
├── requirements.txt
├── README.md
└── modules/
    ├── gui_theme.py         ← Dark theme + shared widgets
    ├── custody_log.py       ← Shared chain-of-custody logger
    ├── tab_timeline.py      ← Log Timeline module
    ├── tab_ipgeo.py         ← IP Geolocation module
    ├── tabs.py              ← All remaining modules (CDR, Email, Hash, etc.)
    └── tab_*.py             ← Individual tab imports
```

---

## TA-2 Project Mapping

This tool covers items **#1–#13, #20, #22, #28, #29, #30** from the TA-2 project definition list, unified into a single Python desktop application with a real GUI.

Key features demonstrating required skills:
- **CSV parsing + frequency count** → CDR Analyzer
- **Pattern matching** → PowerShell Detector, Keyword Scanner
- **Binary file reading** → File Type Identifier (magic bytes)
- **Regex + string processing** → Email Header, Encoding Detector
- **Hashlib** → Hash Verifier (SHA-256, MD5, SHA-1)
- **Regex + file parsing** → Log Timeline, IP Frequency
- **Socket programming** → IP Geolocation (extensible to live lookups)
- **PIL / EXIF** → EXIF Metadata tab (with Pillow)
