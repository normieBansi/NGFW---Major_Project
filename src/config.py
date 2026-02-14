"""
config.py — Central configuration for the AI-Augmented Firewall system.

All tunable parameters are defined here. Modify values to match your
network topology and OPNsense deployment.
"""

# ──────────────────────────────────────────────
# Network Topology
# ──────────────────────────────────────────────
ATTACKER_IP = "192.168.60.10"          # Kali Linux
VICTIM_IP = "192.168.50.10"            # Ubuntu (ML Engine)
FIREWALL_LAN_SUBNET = "192.168.50.0/24"
FIREWALL_OPT1_SUBNET = "192.168.60.0/24"

# ──────────────────────────────────────────────
# Syslog Listener
# ──────────────────────────────────────────────
SYSLOG_LISTEN_HOST = "0.0.0.0"         # Bind to all interfaces
SYSLOG_LISTEN_PORT = 5140              # Non-privileged syslog port
SYSLOG_BUFFER_SIZE = 65535             # Max UDP datagram size

# ──────────────────────────────────────────────
# Feature Engineering
# ──────────────────────────────────────────────
WINDOW_SIZE_SECONDS = 5                # Sliding window length (seconds)
WINDOW_SLIDE_SECONDS = 2              # How often the window slides
MIN_PACKETS_FOR_INFERENCE = 3         # Minimum packets to run detection

# ──────────────────────────────────────────────
# ML Model
# ──────────────────────────────────────────────
MODEL_PATH = "models/isolation_forest.pkl"
SCALER_PATH = "models/scaler.pkl"

# Isolation Forest hyper-parameters
IF_N_ESTIMATORS = 150                  # Number of trees
IF_CONTAMINATION = 0.05               # Expected anomaly ratio (5%)
IF_MAX_SAMPLES = "auto"
IF_RANDOM_STATE = 42

# Feature columns (order matters — must match training)
FEATURE_COLUMNS = [
    "pps",                             # Packets per second
    "bytes_per_second",                # Throughput
    "avg_pkt_len",                     # Mean packet length
    "std_pkt_len",                     # Std-dev of packet lengths
    "syn_ratio",                       # SYN flags / total TCP packets
    "fin_ratio",                       # FIN flags / total TCP packets
    "rst_ratio",                       # RST flags / total TCP packets
    "ack_ratio",                       # ACK flags / total TCP packets
    "tcp_ratio",                       # TCP packets / total
    "udp_ratio",                       # UDP packets / total
    "icmp_ratio",                      # ICMP packets / total
    "inter_arrival_mean",              # Mean inter-arrival time (ms)
    "inter_arrival_std",               # Std-dev of inter-arrival time
    "unique_dst_ports",                # Count of distinct dest ports
    "burst_score",                     # Max packets in any 1-sec sub-window
]

# ──────────────────────────────────────────────
# OPNsense Firewall API
# ──────────────────────────────────────────────
OPNSENSE_HOST = "192.168.50.1"         # OPNsense LAN IP
OPNSENSE_API_KEY = "YOUR_API_KEY"      # Replace with real key
OPNSENSE_API_SECRET = "YOUR_API_SECRET" # Replace with real secret
OPNSENSE_ALIAS_NAME = "ml_blocklist"   # Firewall alias for blocked IPs
OPNSENSE_VERIFY_SSL = False            # Self-signed cert in lab

# API Endpoints (OPNsense standard)
OPNSENSE_BASE_URL = f"https://{OPNSENSE_HOST}/api"
ALIAS_LIST_URL = f"{OPNSENSE_BASE_URL}/firewall/alias_util/list/{OPNSENSE_ALIAS_NAME}"
ALIAS_ADD_URL = f"{OPNSENSE_BASE_URL}/firewall/alias_util/add/{OPNSENSE_ALIAS_NAME}"
ALIAS_RECONFIGURE_URL = f"{OPNSENSE_BASE_URL}/firewall/alias/reconfigure"

# ──────────────────────────────────────────────
# Defense
# ──────────────────────────────────────────────
BLOCK_COOLDOWN_SECONDS = 60            # Min time between re-blocking same IP
ANOMALY_THRESHOLD_CONSECUTIVE = 2      # Consecutive anomaly windows to trigger block

# ──────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────
LOG_LEVEL = "INFO"                     # DEBUG | INFO | WARNING | ERROR
LOG_FILE = "logs/ngfw_engine.log"
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"

# ──────────────────────────────────────────────
# Data / Training
# ──────────────────────────────────────────────
TRAINING_DATA_DIR = "data/"
BASELINE_CSV = "data/baseline_traffic.csv"
ATTACK_CSV = "data/attack_traffic.csv"
