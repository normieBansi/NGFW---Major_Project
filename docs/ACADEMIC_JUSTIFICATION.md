# Academic Justification of Architecture Choices

## AI-Augmented Firewall — L2/L3/L4 Anomaly Detection

---

## 1. Why Isolation Forest?

### 1.1 Theoretical Basis

Isolation Forest (Liu et al., 2008) is an ensemble-based anomaly detection
algorithm that exploits a fundamental property of anomalies: **they are few
and different**.  Unlike distance- or density-based methods (e.g., LOF,
DBSCAN), Isolation Forest directly measures how easily a data point can be
*isolated* by random axis-aligned partitions.

- Anomalous points require **fewer splits** to isolate → shorter average
  path length in the ensemble of isolation trees.
- Normal points sit in dense regions → require **more splits**.

The anomaly score is derived from the expected path length $E(h(x))$
normalised against the average path length of an unsuccessful search
in a Binary Search Tree:

$$
s(x, n) = 2^{-\frac{E(h(x))}{c(n)}}
$$

where $c(n)$ is the average path length of unsuccessful search in a BST
of $n$ samples.  Scores close to 1 indicate anomalies; scores close to
0.5 indicate normal instances.

### 1.2 Practical Advantages for This Project

| Property | Benefit |
|----------|---------|
| **Unsupervised** | No labeled attack data required during training |
| **Sub-linear training** | $O(t \cdot \psi \cdot \log \psi)$ where $t$ = trees, $\psi$ = sub-sample size |
| **Fast inference** | $O(t \cdot \log \psi)$ per sample — suitable for real-time |
| **Low memory** | Each tree uses a sub-sample of 256 points by default |
| **Robust to irrelevant features** | Random sub-space selection provides implicit feature selection |
| **Scikit-learn native** | No external ML framework needed — minimal dependency |

### 1.3 Alternatives Considered

| Model | Reason for Rejection |
|-------|---------------------|
| One-Class SVM | $O(n^2)$–$O(n^3)$ training; poor scalability for streaming |
| DBSCAN | Sensitive to $\varepsilon$; not designed for streaming inference |
| Autoencoders | Requires TensorFlow/PyTorch; excessive compute for VirtualBox |
| LOF | $O(n^2)$ at training; requires storing all training data for inference |
| Random Cut Forest | Not in scikit-learn; requires AWS-specific libraries |

**Conclusion:** Isolation Forest offers the best trade-off between detection
capability, computational cost, and implementation simplicity for an
academic project running inside a constrained virtual environment.

---

## 2. Why Unsupervised Learning?

### 2.1 The Labelling Problem

Supervised classification (e.g., Random Forest, SVM, neural network) requires
**labeled datasets** where each sample is tagged as *normal* or *attack*.  In
a real-world firewall deployment:

- Legitimate traffic profiles are diverse and environment-specific.
- Ground-truth attack labels are expensive to obtain.
- New attack patterns (**zero-day**) have no prior labels.

Unsupervised anomaly detection sidesteps this entirely: the model learns
the distribution of *normal* traffic and flags statistical outliers.  This
is a well-established paradigm in network intrusion detection (Chandola
et al., 2009, "Anomaly Detection: A Survey").

### 2.2 Semi-Supervised Extension

Our implementation follows a **semi-supervised** strategy:

1. **Training phase:** Model is fitted on baseline (normal) traffic only.
2. **Inference phase:** Any sample deviating from the learned normal
   manifold is flagged as anomalous.

This is sometimes called *novelty detection* in the sklearn documentation
and is distinct from fully unsupervised outlier detection.  By training
exclusively on clean data, we ensure the decision boundary tightly
envelopes normal behavior.

### 2.3 Academic Precedent

- Mirsky et al. (2018), *"Kitsune: An Ensemble of Autoencoders for
  Online Network Intrusion Detection"* — demonstrates unsupervised
  approaches for real-time NIDS.
- Ahmed et al. (2016), *"A Survey of Network Anomaly Detection
  Techniques"* — comprehensive review endorsing statistical and
  ML-based anomaly detection for network security.

---

## 3. Why Flow-Level Statistical Features Instead of Payload Analysis?

### 3.1 Encrypted Traffic

Modern networks increasingly use TLS/HTTPS.  Deep Packet Inspection (DPI)
cannot analyse encrypted payloads without decryption proxies, which:

- Introduce latency and complexity.
- Raise privacy and legal concerns.
- Are infeasible in many academic/lab environments.

Flow-level statistical features (**metadata-based detection**) operate on
packet headers and timing, which remain visible regardless of encryption.

### 3.2 Computational Efficiency

| Approach | Cost per Packet | Suitable for Real-Time? |
|----------|:--------------:|:-----------------------:|
| Full DPI (regex on payload) | High | Only with DPDK / hardware offload |
| Statistical flow features | Very Low | Yes, even on VirtualBox |
| ML on raw bytes | Very High | No (requires GPU) |

Our 15-feature vector is computed from **header fields and timing** alone,
requiring only basic arithmetic aggregation over a sliding window.  This
runs comfortably on a single-core VirtualBox VM.

### 3.3 Feature Justification

Each feature in our vector is grounded in network security literature:

| Feature Group | Features | Captures | Reference |
|--------------|----------|----------|-----------|
| Volume | `pps`, `bytes_per_second`, `burst_score` | Volumetric DoS | Mirkovic & Reiher (2004) |
| Size | `avg_pkt_len`, `std_pkt_len` | Protocol anomalies, fragmentation | Lakhina et al. (2004) |
| Protocol | `tcp_ratio`, `udp_ratio`, `icmp_ratio` | Single-protocol floods | CERT advisories |
| TCP Flags | `syn_ratio`, `fin_ratio`, `rst_ratio`, `ack_ratio` | SYN floods, scans | Schuba et al. (1997) |
| Timing | `inter_arrival_mean`, `inter_arrival_std` | Automated tool signatures | Paxson (1999) |
| Diversity | `unique_dst_ports` | Reconnaissance / port scanning | Staniford et al. (2002) |

### 3.4 Why Not Payload?

For this project's scope (L2–L4 detection), all attack signatures manifest
in **header-level behavior**, not in payload content:

- **L2 (ARP):** Identified by packet rate and protocol type.
- **L3 (ICMP):** Identified by protocol ratio and volume.
- **L4 (SYN/UDP):** Identified by flag ratios and volume.

Payload inspection would add complexity without improving detection
for these specific attack classes.

---

## 4. Why This Architecture for a Final-Year Project?

### 4.1 Engineering Rigor

The system demonstrates a **complete end-to-end pipeline**:

```
Syslog Ingestion → Feature Extraction → ML Inference → Automated Response
```

This mirrors how production Network Detection and Response (NDR) systems
operate, showing understanding of:

- Network protocol parsing
- Real-time data pipeline design
- Applied machine learning
- Systems integration (firewall API automation)

### 4.2 Reproducibility

Every component is:

- **Python-based** — no proprietary tools required.
- **Virtualizable** — runs entirely in VirtualBox.
- **Deterministic** — model training uses fixed random seeds.
- **Documented** — attack procedures provide exact commands.

### 4.3 Scope Appropriateness

The project is scoped to be **achievable within an academic timeline**
while still demonstrating:

| Competency | Evidence |
|-----------|---------|
| **Networking** | Custom syslog parsing, protocol-aware features |
| **Security** | Attack taxonomy, automated firewall response |
| **Machine Learning** | Feature engineering, model selection, evaluation |
| **Software Engineering** | Modular Python codebase, configuration management |
| **Systems Integration** | REST API interaction with OPNsense |

### 4.4 Limitations and Honesty

A rigorous academic project must acknowledge limitations:

1. **Not a production IDS** — accuracy is not benchmarked against
   enterprise datasets (e.g., CICIDS2017).
2. **Single-model** — an ensemble of detectors would improve robustness.
3. **No encrypted traffic analysis** — this is a known gap.
4. **VirtualBox performance** — timing features may be noisy due to
   hypervisor scheduling.

These limitations are **intentional trade-offs** given the B.Tech scope
and are clearly documented.

---

## 5. References

1. Liu, F. T., Ting, K. M., & Zhou, Z. H. (2008). *Isolation Forest.*
   IEEE ICDM.
2. Chandola, V., Banerjee, A., & Kumar, V. (2009). *Anomaly Detection:
   A Survey.* ACM Computing Surveys.
3. Mirsky, Y., et al. (2018). *Kitsune: An Ensemble of Autoencoders
   for Online Network Intrusion Detection.* NDSS.
4. Ahmed, M., Mahmood, A. N., & Hu, J. (2016). *A Survey of Network
   Anomaly Detection Techniques.* Journal of Network and Computer
   Applications.
5. Mirkovic, J., & Reiher, P. (2004). *A Taxonomy of DDoS Attack and
   DDoS Defense Mechanisms.* ACM SIGCOMM CCR.
6. Lakhina, A., Crovella, M., & Diot, C. (2004). *Diagnosing Network-Wide
   Traffic Anomalies.* ACM SIGCOMM.
7. Schuba, C. L., et al. (1997). *Analysis of a Denial of Service Attack
   on TCP.* IEEE S&P.
8. Paxson, V. (1999). *Bro: A System for Detecting Network Intruders in
   Real-Time.* Computer Networks.
9. Staniford, S., Hoagland, J., & McAlerney, J. (2002). *Practical
   Automated Detection of Stealthy Portscans.* Journal of Computer
   Security.
