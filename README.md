<div align="center">

# 🛡️ AI-Powered Network Threat Detection System

### A Hybrid Rule-Based and Machine Learning Approach to Real-Time Intrusion Detection

![Python](https://img.shields.io/badge/Python-3.12-blue?logo=python)
![Scapy](https://img.shields.io/badge/Scapy-2.5+-green)
![scikit-learn](https://img.shields.io/badge/scikit--learn-1.x-orange)
![XGBoost](https://img.shields.io/badge/XGBoost-3.2-red)
![SQLite](https://img.shields.io/badge/SQLite-3-blue)
![React](https://img.shields.io/badge/React-18-61DAFB?logo=react)
![Node.js](https://img.shields.io/badge/Node.js-Express-green?logo=node.js)
![License](https://img.shields.io/badge/License-MIT-yellow)

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Architecture](#-architecture)
- [Detection Capabilities](#-detection-capabilities)
- [AI/ML Layer](#-aiml-layer)
- [Dashboard](#-dashboard)
- [Project Structure](#-project-structure)
- [Installation](#-installation)
- [Usage](#-usage)
- [Configuration](#-configuration)
- [Test Scripts](#-test-scripts)
- [Team](#-team)

---

## 🔍 Overview

An AI-Powered Network Intrusion Detection System (NIDS) that passively monitors
network traffic and detects attacks in real time using a **5-layer hybrid detection
architecture** :

| Layer | Description |
|-------|-------------|
| **Rule-Based** | Deterministic thresholds for known attack patterns |
| **AI/ML** | RandomForest + XGBoost models for sub-threshold evasive attacks |
| **Long Window** | 5–10 minute tracking for slow patient attackers |
| **Correlation** | Links multi-detector alerts from the same source IP |
| **Distributed** | Detects coordinated attacks from multiple source IPs |

**Key result :** Zero false positives on legitimate traffic · 13/13 standard attacks detected · AI layer catches evasive sub-threshold attacks missed by rules.

---

## 🏗️ Architecture

### System Architecture

```
Network Traffic (eth0)
        ↓
   [Scapy sniff()]        passive — never sends packets
        ↓
   [Packet Queue]         10,000 buffer, producer/consumer, 0 drops
        ↓
   [Worker Thread]        all detection logic runs here
        ↓
   ┌─────────────────────────────────────────┐
   │           7 Detector Classes            │
   │  SYN · ARP · ICMP · DNS                 │
   │  BRUTEFORCE · FTP · DHCP               │
   └─────────────────────────────────────────┘
        ↓
   [Correlation · Distributed · Long Window]
        ↓
   ┌──────────────────────────────┐
   │        Alert Output          │
   │  Terminal  ·  JSONL  · SQLite│
   └──────────────────────────────┘
        ↓
   [React Dashboard]
```

### 3-Layer Dashboard Architecture

```
React (port 3000)          Visualization & UI
        ↕  HTTP REST + WebSocket
Node.js/Express (port 3001)  API Layer
        ↕  SQL Queries
SQLite (data/ids.db)        Persistent Storage
        ↑  Python writes
IDS Engine (manager.py)     7 Detectors + 7 AI Models
```

### Real-Time Alert Flow

```
1. Attack detected by IDS  →  INSERT INTO alerts (SQLite)
2. Node.js polls every 2s  →  new alert found
3. WebSocket push          →  React Live Feed (instant flash)
```

---

## 🚨 Detection Capabilities

### Alert Icons

| Icon | Label | Meaning |
|------|-------|---------|
| 🚨 | `RULE` | Rule-based threshold crossed |
| 🤖 | `AI_ONLY` | AI model fired, rule did not (sub-threshold evasion caught) |
| 🔥 | `RULE+AI` | Both rule and AI fired |
| 🐢 | `SLOW` | Long-window slow attack detected |
| 🌐 | `DISTRIBUTED` | Coordinated attack from multiple source IPs |
| 🔴 | `CORRELATION` | Same IP triggered 2+ detectors |

### Detected Attack Types

**SYN Detector**
- `SYN_FLOOD` — high SYN rate to one port (> 10 pps)
- `SYN_SCAN` — SYNs across many ports (>= 5 unique in 5s)
- `SLOW_SYN_SCAN` — slow scan over 10 minutes (long window)

**ICMP Detector**
- `ICMP_FLOOD` — echo request flood (> 20 pps)
- `ICMP_REDIRECT` — type=5 from non-gateway (routing hijack)

**DNS Detector**
- `DNS_FLOOD` — query flood (>= 30 requests at >= 10 pps)
- `DNS_TUNNEL` — long encoded subdomains (avg > 50 chars)
- `DNS_AI` — AI-only sub-threshold detection
- `SLOW_DNS_FLOOD` — slow flood over 5 minutes

**Brute Force Detector**
- `BRUTE_FORCE` — SSH/FTP/Telnet brute force
- `CREDENTIAL_STUFFING` — spread across multiple auth ports
- `MULTI_SOURCE_BRUTE` — many IPs hitting same port (MAC-spoof evasion)
- `SLOW_BRUTE_FORCE` — slow brute force over 10 minutes

**FTP Detector**
- `FTP_BRUTE_FORCE` — brute force on port 21
- `FTP_BOUNCE` — PORT command to third-party IP

**ARP Detector**
- `ARP_SPOOFING` — MAC change, gratuitous ARP, high rate (score-based)

**DHCP Detector**
- `DHCP_STARVATION` — flood of DISCOVERs with spoofed MACs
- `DHCP_ROGUE_SERVER` — OFFERs from unknown server (always CRITICAL)
- `DHCP_DECLINE_FLOOD` — conflict injection attack
- `DHCP_RAPID_CYCLING` — rapid RELEASE+DISCOVER cycling

**Cross-Layer**
- `ATTACK_CAMPAIGN` — same IP triggered 2+ detectors in 120s
- `DISTRIBUTED_*_FLOOD` — 5–10+ unique sources targeting same destination

---

## 🤖 AI/ML Layer

### Models

| Detector | Algorithm | F1 Score | Features |
|----------|-----------|----------|----------|
| SYN | RandomForest | **0.9965** | 5 |
| ICMP | RandomForest | **0.9780** | 5 |
| DNS | RandomForest | **0.9922** | 9 |
| Brute Force | XGBoost | **0.9991** | 8 |
| FTP | XGBoost | **0.9991** | 8 |
| ARP | — | pending lab data | — |
| DHCP | — | pending lab data | — |

### Training Datasets

- **CIC-IDS-2017** — University of New Brunswick (~2.8M flows)
- **CIC-IDS-2018** — University of New Brunswick (~1M flows)
- **UNSW-NB15** — University of New South Wales (~2.5M records)
- **CIRA-CIC-DoHBrw-2020** — DNS over HTTPS dataset
- **Kaggle DNS Tunneling** — 20K labeled records

### Training Modes

```bash
python ai/train.py --mode best       # save winner per detector (default)
python ai/train.py --mode ensemble   # RF+XGB voting
python ai/train.py --mode force_rf   # RandomForest only
python ai/train.py --mode force_xgb  # XGBoost only
python ai/train.py --detector dns    # single detector
```

---

## 📊 Dashboard

Built by the dashboard team using React + Node.js + SQLite.

### Pages & Features

| Page | Key Feature |
|------|-------------|
| **Live Feed** | Real-time alert stream via WebSocket — severity badges, AI confidence bar, severity filters |
| **Statistics** | 24h timeline normal vs attacks, breakdown by severity, detection method chart |
| **Detectors** | Real alert counts from SQLite, alert breakdown per attack type per detector |
| **Threat Map** | Top attacking IPs ranked by volume, expandable rows with alert history |
| **System Health** | Packet count (total + PPS), AI models status |
| **Configuration** | Live threshold tuning — writes to SQLite → manager.py reads every 30s → IDS updated without restart |

### SQLite Tables

| Table | Content | Used By |
|-------|---------|---------|
| `alerts` | Attacks only (label=1) | Live Feed, Statistics, Detectors, Threat Map |
| `traffic` | All packets (label=0 + label=1) | Statistics, System Health |
| `config` | Live thresholds | Configuration → IDS Engine |

---

## 📁 Project Structure

```
ai-ids/
├── manager.py                  ← main entry point (run this to start IDS)
├── config.py                   ← ALL configuration — single source of truth
│
├── detectors/                  ← 7 detector classes
│   ├── syn.py                  SYNDetector
│   ├── arp.py                  ARPDetector
│   ├── icmp.py                 ICMPDetector
│   ├── dns.py                  DNSDetector
│   ├── bruteforce.py           BruteForceDetector
│   ├── ftp.py                  FTPDetector
│   └── dhcp.py                 DHCPDetector
│
├── core/
│   ├── alert_store.py          SQLite storage (alerts + traffic tables)
│   ├── alerting.py             alert builder + severity functions
│   ├── correlation.py          cross-detector campaign detection
│   ├── distributed.py          multi-source attack tracker
│   ├── logger.py               JSONL rotating file logger
│   ├── long_window.py          slow attack long-term tracker
│   ├── persistence.py          state save/restore via pickle
│   ├── threat_feed.py          AbuseIPDB async enrichment
│   ├── window.py               sliding window utilities
│   └── worker.py               producer/consumer queue
│
├── ai/
│   ├── load_datasets.py        dataset loading + feature engineering
│   ├── predict.py              RF/XGBoost inference
│   ├── train.py                training pipeline (4 modes)
│   └── retrain.py              intelligent retraining with F1 comparison
│
├── data/
│   ├── ids.db                  SQLite database
│   ├── .state/                 persistence pkl files (7 detectors)
│   └── *.jsonl                 ML training logs per detector
│
├── ai/models/                  trained model files
│   ├── *_model.pkl             one per detector
│   └── metrics.json            training results
│
├── attack_scripts/
│   ├── test_legitimate.py      benign traffic — expect zero alerts
│   ├── test_attacks.py         13 standard attack tests
│   ├── test_ai_evasive.py      sub-threshold evasion tests
│   └── test_ai_trigger.py      AI-only trigger script (demo)
│
└── dashboard/
    ├── frontend/               React app (port 3000)
    └── backend/                Node.js/Express API (port 3001)
```

---

## ⚙️ Installation

### 1. Clone the repository

```bash
git clone <repo_url>
cd ai-ids
```

### 2. Install Python dependencies

```bash
# for regular user
pip install scapy scikit-learn xgboost numpy pandas --break-system-packages

# for sudo (IDS runs as root)
sudo pip install scapy scikit-learn xgboost numpy pandas --break-system-packages
```

> **Note:** `sqlite3` is included in Python — no installation needed.

### 3. Create required directories

```bash
mkdir -p data/.state data ai/models
```

### 4. Train AI models

```bash
# requires datasets in data/datasets/ — see ai/load_datasets.py for paths
python ai/train.py --mode best

# or copy pre-trained models from another machine
scp -r user@<source>:~/ai-ids/ai/models ./ai/
```

### 5. Install dashboard dependencies

```bash
# Backend
cd dashboard/backend
npm install

# Frontend
cd ../frontend
npm install
```

---

## 🚀 Usage

### Start the IDS

```bash
cd ai-ids
sudo python3 manager.py
```

Expected output:
```
   SQLite     : connected ✅ (data/ids.db)
  ✅ State restored from data/.state/syn.pkl
  ...
🚀 AI-IDS MANAGER RUNNING on [eth0]
   Detectors : SYN | ARP | ICMP | DNS | BRUTEFORCE | FTP | DHCP
   IPv6      : supported (rule-based only, no AI for IPv6)
🤖 AI models loaded  : ['syn', 'icmp', 'dns', 'bruteforce', 'ftp']
   Worker    : started ✅
```

### Start the Dashboard

```bash
# Terminal 1 — Backend API
cd dashboard/backend
node server.js

# Terminal 2 — Frontend
cd dashboard/frontend
npm run dev
```

Open browser at `http://localhost:3000`

### Full Stack (all together)

```bash
# Terminal 1 — IDS engine
sudo python3 manager.py

# Terminal 2 — Backend
cd dashboard/backend && node server.js

# Terminal 3 — Frontend
cd dashboard/frontend && npm run dev
```

---

## 🔧 Configuration

All parameters in `config.py` — change here, applies everywhere on next restart.

```python
# === KEY THRESHOLDS ===
SYN_FLOOD_RATE          = 10    # pps to one port
PORT_SCAN_THRESHOLD     = 5     # unique ports in 5s
ICMP_FLOOD_RATE         = 20    # pps
DNS_REQUEST_THRESHOLD   = 30    # requests in window
DNS_FLOOD_MIN_PPS       = 10    # min pps to fire DNS_FLOOD
BRUTE_ATTEMPT_THRESHOLD = 15    # attempts in 10s

# === AI THRESHOLDS (per-detector) ===
AI_THRESHOLD_SYN        = 0.75
AI_THRESHOLD_ICMP       = 0.80
AI_THRESHOLD_DNS        = 0.75
AI_THRESHOLD_BRUTEFORCE = 0.80
AI_THRESHOLD_FTP        = 0.80

# === DATABASE ===
SQLITE_DB_PATH          = "data/ids.db"

# === NETWORK ===
IFACE                   = None   # None = auto-detect, or "eth0"
WHITELIST               = {"127.0.0.1"}
KNOWN_GATEWAYS          = {"192.168.68.1", "192.168.100.1", ...}
DHCP_LEGITIMATE_SERVERS = {"192.168.68.254", "192.168.100.1", ...}
```

### Live Configuration (via Dashboard)

The Configuration page writes thresholds to the `config` SQLite table.
`manager.py` polls this table every 30 seconds and applies changes
**without restarting the IDS**.

---

## 🧪 Test Scripts

All scripts run from the **attacker machine** while `manager.py` runs on the IDS machine.

### Legitimate Traffic Test — expect ZERO alerts
```bash
sudo python3 attack_scripts/test_legitimate.py --target <ids_ip> --iface eth0
```

### Standard Attack Test — expect alert for every attack
```bash
# run all 13 attacks
sudo python3 attack_scripts/test_attacks.py --target <ids_ip> --iface eth0 --attack standard

# run single attack
sudo python3 attack_scripts/test_attacks.py --target <ids_ip> --iface eth0 --attack syn_scan
sudo python3 attack_scripts/test_attacks.py --target <ids_ip> --iface eth0 --attack dns_tunnel
sudo python3 attack_scripts/test_attacks.py --target <ids_ip> --iface eth0 --attack distributed
```

Available attacks: `syn_scan`, `syn_flood`, `icmp_flood`, `icmp_amplification`,
`dns_flood`, `dns_tunnel`, `ssh_brute`, `credential_stuffing`,
`ftp_brute`, `arp_spoof`, `dhcp_starvation`, `rogue_dhcp`, `distributed`

### AI Evasive Test — sub-threshold attacks
```bash
sudo python3 attack_scripts/test_ai_evasive.py --target <ids_ip> --iface eth0
```

### AI Trigger Demo — fire 🤖 AI_ONLY alerts
```bash
# trigger all AI detectors
sudo python3 attack_scripts/test_ai_trigger.py --target <ids_ip> --iface eth0 --attack all

# trigger specific detector
sudo python3 attack_scripts/test_ai_trigger.py --target <ids_ip> --iface eth0 --attack icmp
sudo python3 attack_scripts/test_ai_trigger.py --target <ids_ip> --iface eth0 --attack brute
```

### Save output to file
```bash
sudo python3 manager.py 2>&1 | tee ids_session.log
```

---

## 📈 Test Results

| Test | Result |
|------|--------|
| Legitimate traffic (8 cases) | ✅ **0/8 false positives** |
| Standard attacks (13 types) | ✅ **13/13 detected** |
| AI evasive attacks (6 types) | ✅ **5/6 detected** |
| Queue drop rate | ✅ **0.0% dropped** |

---

## 🔄 Retraining Pipeline

```bash
python ai/retrain.py --check-only   # check readiness (needs 500+ new rows)
python ai/retrain.py                # auto-trigger if enough new data
python ai/retrain.py --force        # force retrain regardless
python ai/retrain.py --detector arp # single detector only
```

Set `USE_OWN_DATA = True` in `config.py` to include your own labeled
lab data in the training mix.

---

## 🛠️ Troubleshooting

| Error | Fix |
|-------|-----|
| `No module named scapy` | `sudo pip install scapy --break-system-packages` |
| `No module named xgboost` | `sudo pip install xgboost --break-system-packages` |
| `No module named sklearn` | `sudo pip install scikit-learn --break-system-packages` |
| `No model for bruteforce/ftp` | Run `python ai/train.py` or copy `ai/models/` folder |
| `Permission denied on sniff` | Must run with `sudo python3 manager.py` |
| DNS false positives on idle | Already fixed — IPv6 multicast filtered, pps minimum added |
| Reset all state | `sudo rm -f data/.state/*.pkl` |

---

## 👥 Team

| Role | Contribution |
|------|-------------|
| **IDS Engine** | Rule-based detectors, AI/ML pipeline, architecture, testing |
| **Dashboard** | React frontend, Node.js backend, SQLite integration, real-time WebSocket |
| **Red Team** | Attack scripts, evasion testing, stealthy attack simulation |

---

## 📄 License

MIT License — free to use, modify, and distribute.

---

<div align="center">

**AI-Powered Network Threat Detection System**  
*Rules Catch the Obvious. AI Catches the Rest.*

</div>
