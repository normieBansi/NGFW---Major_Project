# AI-Augmented Firewall — L2/L3/L4 Anomaly Detection Engine

An ML-driven anomaly detection and automated blocking system that augments
OPNsense with real-time traffic analysis.  Designed as a B.Tech CSE-Cyber
Security major project.

---

## Architecture

```
┌──────────────┐      syslog/UDP       ┌──────────────────────────────────────────────┐
│ OPNsense FW  │ ────────────────────→  │  Ubuntu ML Engine (192.168.50.10)             │
│ 192.168.50.1 │      filterlog        │                                              │
└──────┬───────┘                       │  ┌────────────┐   ┌────────────────┐          │
       │                               │  │ SyslogListener │→│ FeatureEngine  │          │
       │                               │  └────────────┘   └───────┬────────┘          │
       │   ┌───────────────┐           │                           │                   │
       │   │ Kali Attacker │           │                  ┌────────▼─────────┐         │
       │   │ 192.168.60.10 │           │                  │ AnomalyDetector  │         │
       │   └───────┬───────┘           │                  │ (Isolation Forest)│         │
       │           │                   │                  └────────┬─────────┘         │
       │           │ attack traffic    │                           │ alert             │
       │           ▼                   │                  ┌────────▼─────────┐         │
       │     ┌───────────┐            │                  │  DefenseEngine   │         │
       │     │ OPT1 seg  │            │                  │  (API → block)   │         │
       │     └───────────┘            │                  └──────────────────┘         │
       │                               └──────────────────────────────────────────────┘
       │  ◄──── block via REST API ────
```

## Network Topology

| Host | IP | Segment |
|------|-----|---------|
| Kali Linux (Attacker) | 192.168.60.10 | OPT1 (le2) |
| Ubuntu (ML Engine) | 192.168.50.10 | LAN (le1) |
| OPNsense Firewall | LAN: 192.168.50.1, OPT1: 192.168.60.1 | — |

---

## Quick Start

### Prerequisites

- Python 3.10+
- VirtualBox with OPNsense, Ubuntu, Kali VMs
- OPNsense syslog streaming to Ubuntu:5140
- OPNsense API key/secret for firewall alias management

### 1. Install Dependencies (on Ubuntu)

```bash
cd /path/to/NGFW---Major_Project
pip install -r requirements.txt
```

### 2. Configure

Edit `src/config.py`:

```python
OPNSENSE_API_KEY    = "your_actual_api_key"
OPNSENSE_API_SECRET = "your_actual_api_secret"
```

Verify the OPNsense syslog target is `192.168.50.10:5140` (UDP).

### 3. Train the Model

```bash
# From the project root
python -m src.model_trainer
```

This will:
- Generate synthetic baseline traffic profiles (if no log files in `data/`)
- Train an Isolation Forest model
- Save `models/isolation_forest.pkl` and `models/scaler.pkl`
- Run a sanity check against synthetic attack data

**Using real captured logs:**
Place `.log` files (raw syslog captures) in the `data/` directory before
training.  The trainer will auto-detect and use them.

### 4. Start the Detection Engine

```bash
python -m src.main
```

The engine will:
1. Listen for syslog on UDP port 5140.
2. Parse filterlog entries (TCP, UDP, ICMP).
3. Compute 15 features per source IP per 5-second window.
4. Run Isolation Forest inference.
5. Block anomalous IPs via OPNsense REST API.

### 5. Launch Attacks from Kali

See [docs/ATTACK_SIMULATION_GUIDE.md](docs/ATTACK_SIMULATION_GUIDE.md) for
step-by-step attack procedures.

**Quick examples:**

```bash
# SYN flood
sudo hping3 -S --flood -p 80 192.168.50.10

# ICMP flood
sudo hping3 -1 --flood 192.168.50.10

# UDP flood
sudo hping3 -2 --flood -p 53 192.168.50.10
```

### 6. Verify Detection

```bash
# On Ubuntu — watch engine logs
tail -f logs/ngfw_engine.log
```

You should see:
```
ALERT  src=192.168.60.10  score=-0.1234  pps=2500.0  syn_ratio=0.98 …
🛡️  BLOCKED 192.168.60.10  (score=-0.1234, consecutive=2)
```

---

## Project Structure

```
NGFW---Major_Project/
├── src/
│   ├── __init__.py
│   ├── config.py           # All tunable parameters
│   ├── utils.py            # Logging & helper functions
│   ├── log_parser.py       # Syslog listener + filterlog parser
│   ├── feature_engine.py   # Sliding-window feature extraction (15 features)
│   ├── model_trainer.py    # Isolation Forest training & persistence
│   ├── detector.py         # Real-time anomaly detection with consecutive-window logic
│   ├── defense.py          # OPNsense API integration for automated blocking
│   └── main.py             # Orchestrator — wires the full pipeline
├── docs/
│   ├── ATTACK_SIMULATION_GUIDE.md   # Step-by-step attack procedures
│   ├── ATTACK_CLASSIFICATION.md     # L2/L3/L4 attack taxonomy & feature mapping
│   └── ACADEMIC_JUSTIFICATION.md    # Model & architecture justification
├── agent_project_docs/              # Original project planning documents
├── models/                          # Trained .pkl files (generated)
├── data/                            # Training data / log captures
├── logs/                            # Runtime logs (generated)
├── requirements.txt
└── README.md
```

---

## Feature Vector (15 Dimensions)

| # | Feature | Description |
|---|---------|-------------|
| 1 | `pps` | Packets per second in window |
| 2 | `bytes_per_second` | Total throughput |
| 3 | `avg_pkt_len` | Mean packet length |
| 4 | `std_pkt_len` | Standard deviation of packet lengths |
| 5 | `syn_ratio` | SYN flags / TCP packets |
| 6 | `fin_ratio` | FIN flags / TCP packets |
| 7 | `rst_ratio` | RST flags / TCP packets |
| 8 | `ack_ratio` | ACK flags / TCP packets |
| 9 | `tcp_ratio` | TCP packets / total packets |
| 10 | `udp_ratio` | UDP packets / total |
| 11 | `icmp_ratio` | ICMP packets / total |
| 12 | `inter_arrival_mean` | Mean inter-arrival time (ms) |
| 13 | `inter_arrival_std` | Std-dev of inter-arrival time |
| 14 | `unique_dst_ports` | Count of distinct destination ports |
| 15 | `burst_score` | Max packets in any 1-second sub-window |

---

## Detection Pipeline Flow

```
1. OPNsense filterlog → UDP syslog → SyslogListener
2. SyslogListener → parse_filterlog_line() → ParsedPacket
3. ParsedPacket → FeatureEngine (per-IP sliding window buffer)
4. Every 2s: FeatureEngine computes 15-feature vector per active IP
5. FeatureVector → AnomalyDetector → IsolationForest.predict()
6. If anomaly detected for N consecutive windows:
     → AnomalyAlert → DefenseEngine
7. DefenseEngine:
     a. Check cooldown (avoid duplicate blocks)
     b. POST IP to OPNsense alias (ml_blocklist)
     c. POST reconfigure to apply firewall rules
     d. Log block event
```

---

## OPNsense Setup Requirements

1. **Syslog Remote Destination:**
   - System → Settings → Logging → Remote → add `192.168.50.10:5140` (UDP)
   - Enable filterlog in the syslog stream.

2. **Firewall Alias:**
   - Firewall → Aliases → add alias `ml_blocklist` (type: Host(s))
   - Create a block rule referencing this alias on the OPT1 interface.

3. **API Key:**
   - System → Access → Users → edit your user → API keys → generate.
   - Place the key and secret in `src/config.py`.

---

## Documentation

- [Attack Simulation Guide](docs/ATTACK_SIMULATION_GUIDE.md) — Exact commands for every attack
- [Attack Classification](docs/ATTACK_CLASSIFICATION.md) — Taxonomy and feature mapping
- [Academic Justification](docs/ACADEMIC_JUSTIFICATION.md) — Model and architecture rationale

