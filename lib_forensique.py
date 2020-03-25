from scapy.all import *

def detectTcpPortScan(path):
    pcap_file = rdpcap(path)
    scan_report = dict()  # scan_report has this shape : {(ip_origin1, ip_traget1): [scanned_ports1,closed_ports1,opened_ports1], (ip_origin2, ip_traget2): [scanned_ports2,closed_ports2,opened_ports2], ..., (ip_originN, ip_tragetN): [scanned_portsN,closed_portsN,opened_portsN]}

    # Read all frames of the pcap file
    for frame in pcap_file:
        layers = frame.layers()

        if len(layers) > 2 and layers[2].__name__ == 'TCP':
            ip_src = frame[IP].src
            ip_dst = frame[IP].dst
            port_src = frame[TCP].sport
            port_dst = frame[TCP].dport

            # SYN flag
            if frame[TCP].flags.value == 0x02:
                if (ip_src, ip_dst) not in scan_report:
                    scan_report.setdefault((ip_src, ip_dst), [set(),set(),set()])
                scan_report[(ip_src, ip_dst)][0].add(port_dst)
            # SYN ACK flags
            elif frame[TCP].flags.value == 0x12 and (ip_dst, ip_src) in scan_report:
                scan_report[(ip_dst, ip_src)][2].add(port_src)
            # RST ACK flags
            elif frame[TCP].flags.value == 0x14 and (ip_dst, ip_src) in scan_report:
                scan_report[(ip_dst, ip_src)][1].add(port_src)

    # Sort all ports sets for each (ip_origin, ip_target), sorted function return a sorted list
    for k in scan_report:
        for i in range(3):
            scan_report[k][i] = sorted(scan_report[k][i]) # sets become lists
    
    # Display the scan report at the screen
    if scan_report:
        print('\n'+30*'-'+' PORTS SCAN DETECTED '+30*'-')

        for (ip_origin, ip_target) in scan_report:
            scanned_ports = scan_report[(ip_origin, ip_target)][0]
            closed_ports = scan_report[(ip_origin, ip_target)][1]
            opened_ports = scan_report[(ip_origin, ip_target)][2]
            nb_filtered_ports = len(scanned_ports) - len(closed_ports) - len(opened_ports)
            print('Scan of {} ports (SYN flag sended by TCP) to {} from {}'.format(len(scanned_ports), ip_target, ip_origin))
            print('{} port(s) filtered (No reply from {})'.format(nb_filtered_ports, ip_target))
            print('{} port(s) closed (RST, ACK flags)'.format(len(closed_ports)))
            print('{} port(s) opened (SYN ACK flags): {}\n'.format(len(opened_ports), " ".join([str(i) for i in opened_ports])))

    else:
        print('\n'+30*'-'+'NO PORTS SCAN DETECTED '+30*'-')

    return scan_report