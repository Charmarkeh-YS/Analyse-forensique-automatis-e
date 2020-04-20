# Here, we Detect the Mail Bombing attack for Gmail.
# For the exchange of emails, gmail uses TLS.
# We will therefore detect the TLS frames present in the log.

from scapy.all import *
from networkAnalyzer import NetworkAnalyzer

def detectMailBombing():

    # Network analyzer Class call and Inserting attack pcap file
    handler = NetworkAnalyzer("C:/Users/lenovo/Desktop/forensique/fullTrafficMailBombing.pcap")

    pcap_file = rdpcap("C:/Users/lenovo/Desktop/forensique/fullTrafficMailBombing.pcap")
    # Read all frames of the pcap file
    for i, user in enumerate(handler.userList):
        print("User {} : {}".format(i + 1, user.macAddr))
        print("Nombre de trames émises : {}".format(len(user.userTramesList)))
    print("Nombre de trames totales du pcap : {}".format(handler.nbFrame))

    compt=0 # mail counter
    scan_report = dict() #scan_report has this shape : {(ip_origin1, ip_traget1),(ip_origin2, ip_traget2), ..., (ip_originN, ip_tragetN)}
    ref = pcap_file[0].time  # First packet time as IP address reference

    for frame in handler.frameList :
        if ( frame.protocol == "TLS"):
            scan_report.setdefault((frame.ip_src, frame.ip_dst), [set(), set()])
            #print("Mail from {} to {}".format(frame.ip_src, frame.ip_dst))

    for frame in handler.frameList:
        if (frame.protocol == "TLS"):
            if (frame.ip_src,frame.ip_dst ) in scan_report:
                compt=compt+1
                ip_Bomber=frame.ip_src
                ip_target=frame.ip_dst
                tt=frame.time
                if compt > 20 and ((tt-ref) > 0.0003) :# More than 20 emails and in time greater than 0.0003 seconds is suspect.
                   print('\n' + 30 * '-' +'Detected Mail-Bombing !'+ 30 * '-')
                   print("Mail from {} to {}".format(ip_Bomber, ip_target))
                else:
                    print('\n' + 30 * '-' + 'NO MAIL-BOMBING DETECTED '+ 30 * '-')

    print('\nTotal number of emails detected : {}\n'.format(compt))

def main():
    detectMailBombing()
main()
