# Attack Classification Table

## L2 / L3 / L4 Attack Taxonomy

| Layer | Attack Type | Tool(s) | Behavior Pattern | Primary Detectable Features | Secondary Features |
|-------|-------------|---------|------------------|----------------------------|--------------------|
| **L2** | ARP Flood | Scapy | Burst of ARP broadcast frames saturating the segment | `pps`, `burst_score` | `avg_pkt_len` (small, uniform) |
| **L2** | MAC Spoofing | Scapy | ICMP/ARP with randomized source MACs | `pps`, `icmp_ratio` | `burst_score` |
| **L3** | ICMP Flood | hping3 | Sustained high-rate ICMP echo requests | `icmp_ratio` ≈ 1.0, `pps` | `inter_arrival_mean` (very low) |
| **L3** | Large ICMP Flood | hping3 | High-rate ICMP with oversized payloads | `bytes_per_second`, `avg_pkt_len` | `icmp_ratio`, `pps` |
| **L3** | Fragmentation Anomaly | Scapy | Malformed IP fragments that fail reassembly | `std_pkt_len` (high variance), `pps` | `icmp_ratio` |
| **L4** | SYN Flood | hping3 | Massive TCP SYN packets, no handshake completion | `syn_ratio` ≈ 1.0, `ack_ratio` ≈ 0 | `pps`, `burst_score` |
| **L4** | UDP Flood | hping3, nping | High-rate UDP datagrams to single port | `udp_ratio` ≈ 1.0, `pps` | `bytes_per_second` |
| **L4** | Connection Burst | nping | Rapid-fire full TCP handshakes | `pps`, `burst_score` | `syn_ratio`, `ack_ratio` both elevated |
| **L4** | Christmas Tree | nping | Packets with SYN+FIN+URG+PSH flags (abnormal combo) | `syn_ratio` + `fin_ratio` both high | `rst_ratio` |
| **L4** | UDP Volume Flood | iperf3 | Sustained high-bandwidth UDP stream | `bytes_per_second` (extreme), `pps` | `udp_ratio` ≈ 1.0 |
| **L4** | Port Scan | hping3 | SYN to many sequential/random ports | `unique_dst_ports` (very high), `syn_ratio` | `pps` (moderate) |

---

## Feature Sensitivity Matrix

Shows which features are most discriminative for each attack class:

| Feature | ARP Flood | ICMP Flood | SYN Flood | UDP Flood | Port Scan | Conn Burst |
|---------|:---------:|:----------:|:---------:|:---------:|:---------:|:----------:|
| `pps` | ★★★ | ★★★ | ★★★ | ★★★ | ★★ | ★★★ |
| `bytes_per_second` | ★ | ★★ | ★ | ★★★ | ★ | ★★ |
| `avg_pkt_len` | ★★ | ★★ | ★★ | ★★ | ★★ | ★ |
| `std_pkt_len` | ★ | ★ | ★ | ★ | ★ | ★ |
| `syn_ratio` | — | — | ★★★ | — | ★★★ | ★★ |
| `fin_ratio` | — | — | — | — | — | ★ |
| `rst_ratio` | — | — | ★ | — | ★ | — |
| `ack_ratio` | — | — | ★★★ | — | — | ★★ |
| `tcp_ratio` | — | — | ★★★ | — | ★★★ | ★★★ |
| `udp_ratio` | — | — | — | ★★★ | — | — |
| `icmp_ratio` | ★ | ★★★ | — | — | — | — |
| `inter_arrival_mean` | ★★ | ★★ | ★★ | ★★ | ★ | ★★ |
| `inter_arrival_std` | ★ | ★ | ★ | ★ | ★★ | ★ |
| `unique_dst_ports` | — | — | ★ | — | ★★★ | ★ |
| `burst_score` | ★★★ | ★★★ | ★★★ | ★★ | ★ | ★★★ |

Legend: ★★★ = Primary indicator, ★★ = Strong secondary, ★ = Weak signal, — = Not relevant

---

## Detection Confidence Assessment

| Attack | Expected Detection Rate | Rationale |
|--------|:-----------------------:|-----------|
| SYN Flood | **Very High** | Extreme syn_ratio deviation from baseline trivially separable |
| ICMP Flood | **Very High** | icmp_ratio ≈ 1.0 with high PPS is a strong outlier |
| UDP Flood | **High** | udp_ratio ≈ 1.0 + high PPS clearly anomalous |
| ARP Flood | **High** | PPS spike + small uniform packet sizes |
| Port Scan | **High** | unique_dst_ports dramatically elevated |
| Connection Burst | **Medium-High** | Mixed flags make it less extreme on any single feature |
| Fragmentation | **Medium** | Depends on packet length variance being captured |
