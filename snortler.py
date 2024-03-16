from scapy.all import *
import signal
import threading
import sys
import time

# Define constants for TCP flags
TCP_FLAGS = {
    'NUL': 0,
    'FIN': 0x01,
    'SYN': 0x02,
    'RST': 0x04,
    'PSH': 0x08,
    'ACK': 0x10,
    'URG': 0x20,
    'ECE': 0x40,
    'CWR': 0x80
}

# Global variables
flagged_IPs = {}
syn_counts = {}
port_scan_count = {}
attack_flag = False
attack_flag_lock = threading.Lock()
stop_thread = threading.Event()  # Event to signal thread termination

class PortScan:
    def __init__(self):
        self.port = 0
        self.counter = 0

class ClearCacheThread(threading.Thread):
    def run(self):
        global attack_flag

        while not stop_thread.is_set():
            time.sleep(5)  # Run thread every 5 seconds to check flag status

            with attack_flag_lock:
                if attack_flag:
                    print("Detected attacks:")
                    print(flagged_IPs)

            resetFlags()

def resetFlags():
    global attack_flag

    attack_flag = False
    flagged_IPs.clear()
    syn_counts.clear()
    port_scan_count.clear()

def handle_packet(packet):
    if IP in packet:
        detect_port_scanning(packet)

        if TCP in packet:
            detect_syn_attack(packet)
            detect_xmas_packet(packet)
            detect_null_packet(packet)

        if ICMP in packet:
            detect_ping_of_death(packet)

def detect_syn_attack(packet):
    flag = packet[TCP].flags

    if flag & TCP_FLAGS['SYN']:
        ipsrc = str(packet[IP].src)
        syn_counts[ipsrc] = syn_counts.get(ipsrc, 0) + 1
        if syn_counts[ipsrc] == 50:
            report_bad_IP(packet, "Syn Attack")

def detect_null_packet(packet):
    flag = packet[TCP].flags

    if flag == TCP_FLAGS['NUL']:
        report_bad_IP(packet, "Null Packet Detected")

def detect_port_scanning(packet):
    if TCP in packet or UDP in packet:
        dport = packet[TCP].dport if TCP in packet else packet[UDP].dport
        ipsrc = str(packet[IP].src)
        if dport:
            dport = int(dport)
            port_scan_count[ipsrc] = port_scan_count.get(ipsrc, PortScan())
            if dport == port_scan_count[ipsrc].port + 1:
                port_scan_count[ipsrc].port = dport
                port_scan_count[ipsrc].counter += 1
                if port_scan_count[ipsrc].counter > 20:
                    report_bad_IP(packet, "Port scan detection")

def detect_ping_of_death(packet):
    if len(packet) >= 65535:
        report_bad_IP(packet, "Ping of Death")

def detect_xmas_packet(packet):
    flag = packet[TCP].flags
    if flag & TCP_FLAGS['FIN'] and flag & TCP_FLAGS['PSH'] and flag & TCP_FLAGS['URG']:
        report_bad_IP(packet, "Christmas Tree Packet")

def report_bad_IP(packet, reason):
    global attack_flag

    with attack_flag_lock:
        attack_flag = True
        ipsrc = str(packet[IP].src)
        flagged_IPs[ipsrc] = {
            reason,
            packet
        }

def signal_handler(sig, frame):
    print('Exiting...')
    stop_thread.set()  # Set the stop event
    sys.exit(0)

# Start sniffing packets
print("Starting service")
clear_cache_thread = ClearCacheThread()
clear_cache_thread.start()
signal.signal(signal.SIGINT, signal_handler)
sniff(prn=handle_packet)

# Wait for the clear_cache_thread to finish
clear_cache_thread.join()