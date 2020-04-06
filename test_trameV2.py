from trameV2 import Trame
from scapy.all import *


def main():
    file_name="./Pcaps/arppoison.pcap"
    packets=rdpcap(file_name)
    for i,packet in enumerate(packets):
        trame = Trame(packet,i+1)
main()
