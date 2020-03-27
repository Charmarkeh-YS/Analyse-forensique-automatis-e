from trame import Trame
from scapy.all import *
def main():
    file_name="./Pcaps/ssh_brute_force_attack.pcap"
    packets=rdpcap(file_name)
    mes_trames=[]
    for packet in packets:
        trame = Trame(packet)
        mes_trames.append(trame)
    for test in mes_trames:
        print(test)
        print(test.protocol)

main()
