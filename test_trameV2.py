from trameV2 import Trame
from scapy.all import *


def main():
    file_name="./Pcaps/smtp.pcap"
    packets=rdpcap(file_name)
    list_packets=[]
    for i,packet in enumerate(packets):
        trame = Trame(packet,i+1)
        list_packets.append(trame) 
    for frame in list_packets:
        if frame.protocol == "SMTP" :

            print("Frame {} protocol {} data {}".format(frame.id,frame.protocol,frame.data))
main()
