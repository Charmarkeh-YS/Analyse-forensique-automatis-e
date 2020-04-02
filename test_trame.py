from trame import Trame
from scapy.all import *
def main():
    file_name="./Pcaps/icmp.pcap"
    packets=rdpcap(file_name)
    mes_trames=[]
    for i,packet in enumerate(packets):
        trame = Trame(packet,i)
        mes_trames.append(trame)
        print(packet.layers())
    for test in mes_trames:
        print(test)
        print(test.protocol)
    
main()
