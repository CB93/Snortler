## Snortler

This Python script implements a basic Network Intrusion Detection System (NIDS) using the Scapy library. It can detect and report various network attacks, including:

* **SYN Floods:** Identifies an abnormally high rate of SYN packets from a single source, potentially indicating a denial-of-service attempt.
* **Xmas Tree Attacks:** Detects packets with all three flags (FIN, PSH, URG) set, often used for port scanning or fingerprinting.
* **Null Packets:** Flags packets with no flags set (NULL), which can be a precursor to other attacks.
* **Ping of Death (PoD):** Identifies oversized ICMP packets that could crash vulnerable systems.
* **Port Scans:** Monitors for sequential port scans from a single source, suggesting potential reconnaissance activity.

**Key Features:**

* Utilizes Scapy for efficient packet capture and manipulation.
* Employs multiple detection methods for a comprehensive approach.
* Reports flagged IPs and attack details.
* Includes a background thread for periodic cache cleaning.
* Graceful termination upon receiving SIGINT (Ctrl+C).

**Disclaimer:**

This script is for educational purposes only. Running it on a network without proper authorization may be illegal. It's recommended to test it in a controlled environment.

**Installation:**

1. Install Scapy: `pip install scapy`
2. Save the script as `snortler.py`.
3. Run the script with administrator privileges: `sudo python snortler.py`

**Note:** Running the script with `sudo` is necessary for capturing network packets on most systems.

**Further Enhancements:**

* Consider implementing attack logging or alerting mechanisms.
* Enhance detection logic with more advanced techniques.
* Integrate with existing security infrastructure.

**Additional Considerations:**

* False positives may occur, requiring manual analysis.
* This script may not detect all types of network attacks.
* Regular updates and testing are crucial for maintaining effectiveness.
