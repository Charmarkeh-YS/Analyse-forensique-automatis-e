import lib_forensique
from scapy.all import *
import trame

def main():
    pcap_file = rdpcap('Pcaps/nmap.pcap')
    detect_tcp_port_scan(pcap_file)

def detect_tcp_port_scan(pcap_file):
    ip_origin = []
    ip_target = []
    ports_tested = []
    ports_opened = []
    ports_closed = []

    for i,frame in enumerate(pcap_file):
        layers = frame.layers()
        if layers[2].__name__ == 'TCP':
            # SYN flag
            if frame[TCP].flags.value == 0x2 and frame[TCP].dport not in ports_tested:
                ports_tested.append(frame[TCP].dport)
                if frame[IP].src not in ip_origin:
                    ip_origin.append(frame[IP].src)
                if frame[IP].dst not in ip_target:
                    ip_target.append(frame[IP].dst)
            # SYN ACK flags
            if frame[TCP].flags.value == 0x12 and frame[TCP].sport not in ports_opened:
                ports_opened.append(frame[TCP].sport)
            # RST ACK flags
            if frame[TCP].flags.value == 0x14 and frame[TCP].sport not in ports_closed:
                ports_closed.append(frame[TCP].sport)

    ports_tested.sort()
    ports_closed.sort()
    ports_opened.sort()

    print("\n" + 30*"-" + "WARNING, PORT SCAN DETECTED" + 30*"-")
    print("Target IP : " + " ".join(ip_target))
    print("Origin IP : " + " ".join(ip_origin))

    print(str(len(ports_tested)) + " ports were scanned, "+ str(len(ports_closed)) + " are closed.")
    print("Ports opened : ")
    for i in ports_opened:
        print(str(i))

main()