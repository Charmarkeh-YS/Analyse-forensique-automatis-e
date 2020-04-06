from trameV2 import Trame
from scapy.all import *


def main():
    file_name="./Pcaps/arppoison.pcap"
    packets=rdpcap(file_name)
    list_packets=[]
    for i,packet in enumerate(packets):
        trame = Trame(packet,i+1)
        list_packets.append(trame)
    for packet in list_packets:
        print("Frame {} protocol {}".format(packet.id,packet.protocol))
main()
