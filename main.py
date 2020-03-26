import lib_forensique

def main():
    #lib_forensique.detectTcpPortScan(path='Pcaps/nmap2.pcap') # Test the detection of TCP port scan
    lib_forensique.detectUdpPortScan(path='Pcaps/nmap3.pcap') # Test the detection of UDP port scan

main()