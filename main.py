import lib_forensique
import trame

def main():
    lib_forensique.detectTcpPortScan(path='Pcaps/nmap.pcap')

main()