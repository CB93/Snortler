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

**hping3 and Network Exploration (Educational Context)**

While this script focuses on NIDS detection using Scapy, it's worth mentioning tools like **hping3**.  hping3 is a command-line utility that allows for crafting and sending custom TCP/IP packets.  In a controlled environment, security professionals can leverage hping3 for various legitimate purposes, such as:

* **Simulating Network Traffic:**  hping3 can be used to simulate different network traffic patterns, helping to test the resilience of firewalls and network devices under various load conditions.
* **Advanced Port Scanning:**  hping3 offers more granular control over port scans compared to basic tools. This can be useful for security professionals to identify open ports and services running on a target system during authorized vulnerability assessments.
* **Network Performance Analysis:**  By sending packets with specific configurations, hping3 can be used to analyze network behavior and measure performance metrics like latency and packet loss.

**Important Considerations:**

* hping3 is a powerful tool, and it's crucial to emphasize responsible use.
* Always obtain proper authorization before using hping3 on any network.
* Misusing hping3 for malicious purposes is illegal and unethical.

**Additional Considerations:**

* False positives may occur, requiring manual analysis.
* This script does not detect all types of network attacks.
