import lib_forensique
from networkAnalyzer import NetworkAnalyzer

def main():
    # -------------------- Test lib_forensique ----------------------
    # --------------------  Uncomment to test   ---------------------
    #lib_forensique.detectTcpPortScan(path='Pcaps/nmap2.pcap') # Test the detection of TCP port scan
    #lib_forensique.detectUdpPortScan(path='Pcaps/nmap3.pcap') # Test the detection of UDP port scan
    #lib_forensique.detectTcpPortScan2(path='Pcaps/nmap_sX.pcap') # Test the detection of Inverse TCP port scan
    #lib_forensique.detectNetworkArpScan(path='Pcaps/netdiscover.pcap') # Test the detection of network ARP scan
    #lib_forensique.detectTcpUdpFlood(path='Pcaps/synflood.pcap') # Test the detection of TCP SYN flood
    #lib_forensique.detectTcpUdpFlood(path='Pcaps/udpflood.pcap') # Test the detection of UDP flood
    #lib_forensique.detectDnsRequestFlood(path='Pcaps/dns.pcap') # Test the detection of DNS Queries flood
    #lib_forensique.detectHttpGetFlood(path='Pcaps/httpget.pcap') # Test the detection of HTTP GET flood
    #lib_forensique.detectTcpReset(path='Pcaps/tcprst2.pcap') # Test the detection of TCP Reset
    lib_forensique.showActivity(path='Pcaps/wifi.pcap', ip_src_list=['192.168.1.40', '192.168.1.17'], ip_dst_list=['192.168.1.40', '192.168.1.17'], protocols=['TCP', 'UDP', 'ICMP', 'ARP']) # Test to show the traffic in the network

    # -------------------- Test networkAnalyser ----------------------
    # --------------------  Uncomment to test   ---------------------
    #handler = NetworkAnalyzer("./Pcaps/ssh.pcap")
    #handler.detectSshBruteForceAttack()
    #handler.detectTcpPortScan()
    #handler.detectInverseTcpPortScan()
    #handler.detectUdpPortScan()
    #handler.detectNetworkArpScan()
    #handler.detectTcpPortScanWithTrame()
    #print(handler.nbFrame)
    #print(handler.frameList)
    #print(handler.userList)

    #handler.detectTcpFlood()

main()
