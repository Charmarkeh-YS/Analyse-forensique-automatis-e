from scapy.all import *
from time import time

def detectTcpPortScan(path):
    """
    Detect a TCP ports scan captured in a pcap file (Vanilla connect and Half-open SYN flag)

    ---------- VANILLA CONNECT ----------

    Port considered opened:

    attacker -----  SYN  ----> target
    attacker <----SYN-ACK----- target
    attacker -----  ACK  ----> target

    Port considered closed:
    attacker -----  SYN  ----> target
    attacker <----RST-ACK----- target

    Port considered filtered:

    attacker -----  SYN  ----> target

    ---------- HALF-OPEN SYN FLAG ----------

    Port considered opened:

    attacker -----  SYN  ----> target
    attacker <----SYN-ACK----- target
    attacker -----  RST  ----> target

    Port considered closed:
    attacker -----  SYN  ----> target
    attacker <----RST-ACK----- target

    Port considered filtered:
    
    attacker -----  SYN  ----> target

    Return a report :

    {(ip_attacker1, ip_target1): [scanned_ports1,closed_ports1,opened_ports1],
    (ip_attacker2, ip_target2): [scanned_ports2,closed_ports2,opened_ports2],
    ..., 
    (ip_attackerN, ip_targetN): [scanned_portsN,closed_portsN,opened_portsN]}

    scanned_ports is an int list of target ports, port are append into the list
    if the TCP flag is SYN. All SYN flag are considered suspicious.

    closed_ports is an int list of port where TCP flag is RST-ACK

    opened_ports is an int list of port where TCP flag is SYN-ACK
    """
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
            scan_report[k][i] = sorted(scan_report[k][i]) # Sets become list
    
    # Display the scan report at the screen
    if scan_report:
        print('\n'+30*'-'+' TCP PORTS SCAN DETECTED '+30*'-')

        for (ip_origin, ip_target) in scan_report:
            scanned_ports = scan_report[(ip_origin, ip_target)][0]
            closed_ports = scan_report[(ip_origin, ip_target)][1]
            opened_ports = scan_report[(ip_origin, ip_target)][2]
            filtered_ports = sorted(set(scanned_ports).difference(set(closed_ports).union(set(opened_ports))))

            print('\nScan of {} ports (SYN flag sended by TCP) to {} from {}'.format(len(scanned_ports), ip_target, ip_origin))
            print('{} port(s) filtered (No reply from {})'.format(len(filtered_ports), ip_target))
            print('{} port(s) closed (RST, ACK flags)'.format(len(closed_ports)))
            if 0 < len(closed_ports) <= 20:
                print(' '.join([str(i) for i in closed_ports]))
            print('{} port(s) opened (SYN ACK flags)'.format(len(opened_ports)))
            if 0 < len(opened_ports) <= 20:
                print(' '.join([str(i) for i in opened_ports]))

    else:
        print('\n'+30*'-'+'NO TCP PORTS SCAN DETECTED '+30*'-')

    return scan_report


def detectTcpPortScan2(path):
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

            # FIN-PSH-URG-NULL flags
            if frame[TCP].flags.value in [0x00, 0x01, 0x29]: # [NULL, FIN, FIN-PSH-URG]
                if (ip_src, ip_dst) not in scan_report:
                    scan_report.setdefault((ip_src, ip_dst), [set(),set(),set()])
                scan_report[(ip_src, ip_dst)][0].add(port_dst)
            # RST ACK flags
            elif frame[TCP].flags.value == 0x14 and (ip_dst, ip_src) in scan_report:
                scan_report[(ip_dst, ip_src)][1].add(port_src)

    # Sort all ports sets for each (ip_origin, ip_target), sorted function return a sorted list
    for k in scan_report:
        for i in range(3):
            scan_report[k][i] = sorted(scan_report[k][i]) # Sets become list
    
    # Display the scan report at the screen
    if scan_report:
        print('\n'+30*'-'+' INVERSE TCP PORTS SCAN DETECTED '+30*'-')

        for (ip_origin, ip_target) in scan_report:
            scanned_ports = scan_report[(ip_origin, ip_target)][0]
            closed_ports = scan_report[(ip_origin, ip_target)][1]
            op_fil_ports = sorted(set(scanned_ports).difference(set(closed_ports)))
            scan_report[(ip_origin, ip_target)][2] = op_fil_ports

            print('\nScan of {} ports (FIN-PUSH-URG-NULL flag sended by TCP) to {} from {}'.format(len(scanned_ports), ip_target, ip_origin))
            print('{} port(s) closed (RST, ACK flags)'.format(len(closed_ports)))
            if 0 < len(closed_ports) <= 20:
                print(' '.join([str(i) for i in closed_ports]))
            print('{} port(s) opened | filtered (No answer)'.format(len(op_fil_ports)))
            if 0 < len(op_fil_ports) <= 20:
                print(' '.join([str(i) for i in op_fil_ports]))

    else:
        print('\n'+30*'-'+'NO INVERSE TCP PORTS SCAN DETECTED '+30*'-')

    return scan_report


def detectUdpPortScan(path):
    pcap_file = rdpcap(path)
    scan_report = dict()  # scan_report has this shape : {(ip_origin1, ip_traget1): [scanned_ports1,closed_ports1,opened_filtered_ports1], (ip_origin2, ip_traget2): [scanned_ports2,closed_ports2,opened_filtered_ports2], ..., (ip_originN, ip_tragetN): [scanned_portsN,closed_portsN,opened_filtered_portsN]}

    # Read all frames of the pcap file
    for frame in pcap_file:
        layers = frame.layers()

        # Frame sent by the attacker
        if len(layers) > 2 and layers[2].__name__ == 'UDP':
            ip_src = frame[IP].src
            ip_dst = frame[IP].dst
            port_dst = frame[UDP].dport

            if (ip_src, ip_dst) not in scan_report:
                scan_report.setdefault((ip_src, ip_dst), [set(),set(),set()])
            scan_report[(ip_src, ip_dst)][0].add(port_dst)

        # Frame sent by the target in the case of closed port
        elif len(layers) > 2 and layers[2].__name__ == 'ICMP':
            ip_src = frame[IP].src
            ip_dst = frame[IP].dst

            if (scapy.layers.inet.UDPerror in layers):
                port_dst = frame[UDPerror].dport
                scan_report[(ip_dst, ip_src)][1].add(port_dst)

    # Sort all ports sets for each (ip_origin, ip_target), sorted function return a sorted list
    for k in scan_report:
        for i in range(3):
            scan_report[k][i] = sorted(scan_report[k][i]) # Sets become list
    
    # Display the scan report at the screen
    if scan_report:
        print('\n'+30*'-'+' UDP PORTS SCAN DETECTED '+30*'-')

        for (ip_origin, ip_target) in scan_report:
            scanned_ports = scan_report[(ip_origin, ip_target)][0]
            closed_ports = scan_report[(ip_origin, ip_target)][1]
            op_fil_ports = sorted(set(scanned_ports).difference(set(closed_ports)))
            scan_report[(ip_origin, ip_target)][2] = op_fil_ports

            print('\nScan of {} ports to {} from {}'.format(len(scanned_ports), ip_target, ip_origin))
            print('{} port(s) closed (ICMP answer)'.format(len(closed_ports)))
            if 0 < len(closed_ports) <= 20:
                print(' '.join([str(i) for i in closed_ports]))
            print('{} port(s) opened | filtered (No answer)'.format(len(op_fil_ports)))
            if 0 < len(op_fil_ports) <= 20:
                print(' '.join([str(i) for i in op_fil_ports]))

    else:
        print('\n'+30*'-'+'NO UDP PORTS SCAN DETECTED '+30*'-')

    return scan_report


def detectNetworkArpScan(path):
    pcap_file = rdpcap(path)
    scan_report = dict()  # scan_report has this shape : 

    # Read all frames of the pcap file
    for frame in pcap_file:
        layers = frame.layers()

        if len(layers) > 1 and layers[1].__name__ == 'ARP':
            ip_src = frame[ARP].psrc
            ip_dst = frame[ARP].pdst
            op_code = frame[ARP].op

            # ARP request
            if op_code == 1:
                if ip_src not in scan_report:
                    scan_report.setdefault(ip_src, [set(),set()])
                scan_report[ip_src][0].add(ip_dst)

            # ARP reply
            elif op_code == 2 and ip_dst in scan_report:
                scan_report[ip_dst][1].add(ip_src)

    # Display the scan report at the screen
    if scan_report:
        print('\n'+30*'-'+' ARP NETWORK SCAN DETECTED '+30*'-')

        for ip_origin in scan_report:
            request_sent = scan_report[ip_origin][0]
            reply_received = scan_report[ip_origin][1]

            print('\nScan of {} (ARP request sent) IP adresses from {}'.format(len(request_sent), ip_origin))
            print('{} distants hosts spotted (ARP reply received)'.format(len(reply_received)))
            print(' '.join([str(i) for i in reply_received]))

    else:
        print('\n'+30*'-'+'NO ARP NETWORK SCAN DETECTED '+30*'-')

    return scan_report


def detectTcpFlood(path, minTcpFrame=10000, nbIpToShow=10):
    """
    Detect a TCP flood attack (DDoS/DoS) captured in a pcap file

    ---------- NORMAL 3-WAY HAND-SHAKE ----------

    attacker -----  SYN  ----> target
    attacker <----SYN-ACK----- target
    attacker -----  ACK  ----> target

    ---------- SYN FLOOD ATTACK ----------

    Port considered opened:

    attacker -----  SYN  ----> target
    attacker -----  SYN  ----> target
    attacker -----  SYN  ----> target
                    ...
    
    attacker <----SYN-ACK----- target
    attacker <----SYN-ACK----- target
    attacker <----SYN-ACK----- target
                    ...
    
    Others flags can be used in a TCP flood attack.

    Souces IP can be spoofed. Example of command using hping3:
    hping3 -c 1000 -d 120 -S -w 64 -p 22 --flood --rand-source ip_target

    Return a report :

    {(ip_target1, port_target1): [nbTcpFrameRcv1, ip_attacker1, start_line1, end_line1],
    (ip_target2, port_target2): [nbTcpFrameRcv2, ip_attacker2, start_line2, end_line2],
    ..., 
    (ip_targetN, port_targetN): [nbTcpFrameRcvN, ip_attackerN, start_lineN, end_lineN]}

    nbTcpFrameRcv (int) is a counter of TCP frame received by the target from all attackers
    ip_attacker is a list of str, it contains all IP adresses that sent TCP request to the target
    start_line (int) is the first number of the line that use TCP protocol
    end_line (int) is the last number of the line that use TCP protocol
    """
    t = time()
    scan_report = dict()
    pcap_file = rdpcap(path)

    # Read all frames of the pcap file
    for i,frame in enumerate(pcap_file):
        layers = frame.layers()

        if len(layers) > 2 and layers[2].__name__ == 'TCP':
            ip_src = frame[IP].src
            ip_dst = frame[IP].dst
            port_dst = frame[TCP].dport

            if (ip_dst, port_dst) not in scan_report:
                scan_report.setdefault((ip_dst, port_dst), [0, set(), 0, 0]) # key: (ip_dst, port_dst) -> [nb_SYN_flag, ip_attackers, start_line, end_line]
                scan_report[(ip_dst, port_dst)][2] = i+1
            scan_report[(ip_dst, port_dst)][0] += 1
            scan_report[(ip_dst, port_dst)][1].add(ip_src)
            scan_report[(ip_dst, port_dst)][3] = i+1

    # Display the scan report
    if scan_report:
        print('\n'+30*'-'+' TCP FLOOD DETECTED '+30*'-')

        for (ip_dst, port_dst) in scan_report:
            nbTcpFrameRcv = scan_report[(ip_dst, port_dst)][0]
            if nbTcpFrameRcv > minTcpFrame:
                start_line = scan_report[(ip_dst, port_dst)][2]
                end_line = scan_report[(ip_dst, port_dst)][3]
                print('\nTarget : {} on port {}'.format(ip_dst, port_dst))
                print('{} TCP frames received from line {} to {} (wireshark)'.format(nbTcpFrameRcv, start_line, end_line))

                if len(scan_report[(ip_dst, port_dst)][1]) < nbIpToShow:
                    print('IP attacker(s):', ' '.join(scan_report[(ip_dst, port_dst)][1]))

    else:
        print('\n'+30*'-'+' NO TCP FLOOD DETECTED '+30*'-')

    print('Scanning time: ', str(time()-t), ' seconds')

    return scan_report