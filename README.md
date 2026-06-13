# 🛡️ Windows Forensic Security Audit (PowerShell)

A lightweight **Windows forensic and anomaly detection script** designed to identify:
- suspicious processes
- potential DLL injection indicators
- unusual network listeners
- persistence mechanisms (startup, scheduled tasks, WMI)
- unsigned or abnormal system components

This tool is intended for:
- security auditing
- incident response triage
- SOC learning environments
- personal system integrity checks

⚠️ **Not an antivirus or EDR replacement.**

---

# 🚀 Features

This script performs a multi-layer forensic scan:

## 1. 🧠 Process & Injection Heuristics
- Lists all running processes
- Flags:
  - `svchost.exe` instances without valid path
  - processes running from:
    - `AppData`
    - `Temp`
  - potential execution anomalies

---

## 2. 🌐 Network Connections Analysis
- Maps:
  - TCP ports → PID → process name → state
- Flags:
  - high ephemeral ports (> 45000) in listening state
  - unusual bindings

---

## 3. 🧬 SVCHOST DLL & Module Inspection
- Extracts loaded DLL modules from `svchost.exe`
- Verifies:
  - digital signatures (Authenticode)
  - system directory origin

Flags:
- unsigned DLLs outside `C:\Windows\System32`
- DLLs loaded from:
  - `AppData`
  - `Temp`

👉 Useful for detecting:
- user-mode DLL injection
- living-off-the-land techniques
- service hijacking

---

## 4. ⚙️ Persistence Mechanisms

### Startup Programs
Checks:
- registry + startup entries
- user and system-level auto-start entries

Flags:
- execution from `AppData` or `Temp`

---

### Scheduled Tasks
Lists all scheduled tasks

Flags:
- suspicious naming patterns:
  - `Update`
  - `Temp`
  - `Cache`
  - randomized task names

---

## 5. 🧠 WMI Persistence Detection
Detects WMI event filters in:
