import lib_forensique
from scapy.all import *
import trame

def main():
    pcap_file = rdpcap('Pcaps/nmap.pcap')
    detect_tcp_port_scan(pcap_file)

def detect_tcp_port_scan(pcap_file):
    ip_origin = []
    ip_target = []
    for i,frame in enumerate(pcap_file):
        layers = frame.layers()
        if layers[2].__name__ == 'TCP':
            print(frame[TCP].flags)

main()