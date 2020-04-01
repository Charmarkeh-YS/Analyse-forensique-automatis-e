import lib_forensique
from networkAnalyzer import NetworkAnalyzer

def main():
    #lib_forensique.detectTcpPortScan(path='Pcaps/nmap2.pcap') # Test the detection of TCP port scan
    #lib_forensique.detectUdpPortScan(path='Pcaps/nmap3.pcap') # Test the detection of UDP port scan
    #lib_forensique.detectTcpPortScan2(path='Pcaps/nmap_sX.pcap') # Test the detection of Inverse TCP port scan
    #lib_forensique.detectNetworkArpScan(path='Pcaps/netdiscover.pcap') # Test the detection of network ARP scan

    handler = NetworkAnalyzer("./Pcaps/netdiscover.pcap")
    handler.detectTcpPortScan()
    handler.detectInverseTcpPortScan()
    handler.detectUdpPortScan()
    handler.detectNetworkArpScan()
    #print(handler.nbFrame)
    #print(handler.frameList)
    #print(handler.userList)

main()