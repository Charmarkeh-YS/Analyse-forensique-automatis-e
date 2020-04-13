from scapy.all import *
import time
import binascii
import matplotlib.pyplot as plt

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

    Return a report (dict):

    {(ip_attacker1, ip_target1): [scanned_ports1,closed_ports1,opened_ports1],
    (ip_attacker2, ip_target2): [scanned_ports2,closed_ports2,opened_ports2],
    ..., 
    (ip_attackerN, ip_targetN): [scanned_portsN,closed_portsN,opened_portsN]}

    scanned_ports is an int list of target ports, port are append into the list
    if the TCP flag is SYN. All SYN flag are considered suspicious.

    closed_ports is an int list of port where TCP flag is RST-ACK

    opened_ports is an int list of port where TCP flag is SYN-ACK
    """
    t = time.time()
    pcap_file = rdpcap(path) # Take a long time
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

    print('Detecting time: ', str(time.time()-t), ' seconds')

    return scan_report


def detectTcpPortScan2(path):
    """
    Detect a TCP ports scan captured in a pcap file (Inverse TCP flag)

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

    ---------- INVERSE TCP FLAG ----------

    Port considered closed:
    attacker ----- FIN-PSH-URG-NULL ----> target
    attacker <----     RST-ACK      ----- target

    Port considered open | filtered:
    
    attacker ----- FIN-PSH-URG-NULL ----> target

    Other flags can be used like NULL or FIN.

    Return a report (dict):

    {(ip_attacker1, ip_target1): [scanned_ports1,closed_ports1,op_fil_ports1],
    (ip_attacker2, ip_target2): [scanned_ports2,closed_ports2,op_fil_ports2],
    ..., 
    (ip_attackerN, ip_targetN): [scanned_portsN,closed_portsN,op_fil_portsN]}

    scanned_ports is an int list of target ports, port are append into the list
    if the TCP flag is FIN-PSH-URG-NULL or NULL or FIN . All those flags are considered suspicious.

    closed_ports is an int list of port where TCP flag is RST-ACK

    op_fil_ports is an int list of port where target did not send a response
    """
    t = time.time()
    pcap_file = rdpcap(path)
    scan_report = dict()

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

    print('Detecting time: ', str(time.time()-t), ' seconds')

    return scan_report


def detectUdpPortScan(path):
    """
    Detect an UDP ports scan captured in a pcap file (Inverse TCP flag)

    ---------- UDP PORT SCAN ----------

    Port considered closed:
    attacker -------------------- UDP -------------------> target
    attacker <---- ICMP destiantion port unreachable ----- target

    Port considered open | filtered:
    
    attacker ----- UDP ----> target

    Other flags can be used like NULL or FIN.

    Return a report (dict):

    {(ip_attacker1, ip_target1): [scanned_ports1,closed_ports1,op_fil_ports1],
    (ip_attacker2, ip_target2): [scanned_ports2,closed_ports2,op_fil_ports2],
    ..., 
    (ip_attackerN, ip_targetN): [scanned_portsN,closed_portsN,op_fil_portsN]}

    scanned_ports is an int list of target ports, port are append into the list
    if the if the target receives an UDP frame.

    closed_ports is an int list of port where the target send an ICMP port unreachable frame

    op_fil_ports is an int list of port where target did not send a response
    """
    t = time.time()
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

    print('Detecting time: ', str(time.time()-t), ' seconds')

    return scan_report


def detectNetworkArpScan(path):
    """
    Detect a network ARP scan captured in a pcap file

    ---------- NETWORK ARP  SCAN ----------

    ARP request in broadcast :
                                            192.168.1.0
    attacker ----- Who has 192.168.1.1 ? ----> |
    attacker ----- Who has 192.168.1.2 ? ----> |
                            ...                |
    attacker ---- Who has 192.168.1.254 ? ---> |


    ARP reply:

    attacker <--- IP_target1 is at MAC_addr1 ---- target1
    attacker <--- IP_target2 is at MAC_addr2 ---- target2
                            ...
    attacker <--- IP_targetN is at MAC_addrN ---- targetN

    Return a report (dict):

    {ip_attacker1: [ARP_request1, ARP_reply1],
    ip_attacker2: [ARP_request2, ARP_reply2],
    ..., 
    ip_attackerN: [ARP_requestN, ARP_replyN],}

    ARP_request is a list of string, strings are IP addresses sent by the attacker to know its owner

    ARP_reply is a list of string, strings are IP addresses of each machines who reply at the attacker's requests
    """
    t = time.time()
    pcap_file = rdpcap(path)
    scan_report = dict()

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

    print('Detecting time: ', str(time.time()-t), ' seconds')

    return scan_report


def detectTcpUdpFlood(path, minFrame=100000, maxIpToShow=10): # minFrame=100000, maxIpToShow=10
    """
    Detect a TCP/UDP flood attack (DDoS/DoS) captured in a pcap file

    ---------- NORMAL 3-WAY HAND-SHAKE ----------

    attacker -----  SYN  ----> target
    attacker <----SYN-ACK----- target
    attacker -----  ACK  ----> target

    ---------- SYN FLOOD ATTACK ----------

    (For ports considered open)

    attacker -----  SYN  ----> target
    attacker -----  SYN  ----> target
    attacker -----  SYN  ----> target
                    ...
    
    attacker <----SYN-ACK----- target
    attacker <----SYN-ACK----- target
    attacker <----SYN-ACK----- target
                    ...

    Others flags can be used in a TCP flood attack.

    ---------- UDP FLOOD ATTACK ----------

    (For ports considered open)

    attacker ---------> target
    attacker ---------> target
    attacker ---------> target
                ...

    Souces IP can be spoofed. Example of command using hping3 for TCP SYN flood:
    hping3 -c 1000 -d 120 -S -w 64 -p 22 --flood --rand-source ip_target

    Other example for UDP flood:
    hping3 -2 -c 1000 -p 22 --flood ip_target

    Parameters in input:

    minFrame (int) is the minimum of frame recorded to show the report for a target
    maxIpToShow (int) is the maximum number of attackers IP to show for a target

    Return a report :

    {(ip_target1, port_target1): [nbFrameRecord1, ip_attacker1, start_line1, end_line1, protocol_l4],
    (ip_target2, port_target2): [nbFrameRecord2, ip_attacker2, start_line2, end_line2, protocol_l4],
    ..., 
    (ip_targetN, port_targetN): [nbFrameRecordN, ip_attackerN, start_lineN, end_lineN, protocol_l4]}

    nbFrameRecord (int) is a counter of TCP frame received by the target from all attackers
    ip_attacker is a list of str, it contains all IP adresses that sent TCP request to the target
    start_line (int) is the first number of the line that use TCP protocol
    end_line (int) is the last number of the line that use TCP protocol
    protocol_l4 (str) is the protocol of layer 4 used for the (D)DoS attack
    """

    t = time.time()
    scan_report = dict()
    pcap_file = rdpcap(path)

    # Read all frames of the pcap file
    for i,frame in enumerate(pcap_file):
        layers = frame.layers()

        if len(layers) > 2 and layers[2].__name__ in ['TCP', 'UDP'] and layers[1].__name__ == 'IP':
            ip_src = frame[IP].src
            ip_dst = frame[IP].dst
            protocol_l4 = layers[2].__name__ # Protocol of layer 4

            if protocol_l4 == 'TCP':
                port_dst = frame[TCP].dport

            elif protocol_l4 == 'UDP':
                port_dst = frame[UDP].dport

            if (ip_dst, port_dst) not in scan_report:
                scan_report.setdefault((ip_dst, port_dst), [0, set(), 0, 0, protocol_l4]) # key: (ip_dst, port_dst) -> [nb_SYN_flag, ip_attackers, start_line, end_line, protocol_l4]
                scan_report[(ip_dst, port_dst)][2] = i+1
            scan_report[(ip_dst, port_dst)][0] += 1
            scan_report[(ip_dst, port_dst)][1].add(ip_src)
            scan_report[(ip_dst, port_dst)][3] = i+1

    # Display the scan report
    if scan_report:
        print('\n'+30*'-'+' TCP/UDP FLOOD DETECTED '+30*'-')

        for (ip_dst, port_dst) in scan_report:
            nbFrameRecord = scan_report[(ip_dst, port_dst)][0]
            if nbFrameRecord > minFrame:
                start_line = scan_report[(ip_dst, port_dst)][2]
                end_line = scan_report[(ip_dst, port_dst)][3]
                protocol_l4 = scan_report[(ip_dst, port_dst)][4]
                print('\nTarget : {} on port {}'.format(ip_dst, port_dst))
                print('{} {} frames received from line {} to {} (wireshark)'.format(nbFrameRecord, protocol_l4, start_line, end_line))

                if len(scan_report[(ip_dst, port_dst)][1]) < maxIpToShow:
                    print('IP attacker(s):', ' '.join(scan_report[(ip_dst, port_dst)][1]))

    else:
        print('\n'+30*'-'+' NO TCP/UDP FLOOD DETECTED '+30*'-')

    print('Detecting time: ', str(time.time()-t), ' seconds')

    return scan_report


def detectDnsRequestFlood(path, minFrame=100000, maxIpToShow=10): # minFrame=100000, maxIpToShow=10
    """
    Detect a DNS request flood attack (DDoS/DoS) captured in a pcap file

    ---------- STANDART DNS QUERY ----------

    attacker ----- DNS request ----> target
    attacker <----  DNS reply  ----- target

    ---------- DNS REQUEST FLOOD ATTACK ----------

    attacker ----- DNS request ----> target
    attacker ----- DNS request ----> target
    attacker ----- DNS request ----> target
                        ...

    attacker <----  DNS reply  ----- target
    attacker <----  DNS reply  ----- target
    attacker <----  DNS reply  ----- target
                        ...

    Parameters in input:

    minFrame (int) is the minimum of frame recorded to show the report for a target
    maxIpToShow (int) is the maximum number of attackers IP to show for a target

    Return a report :

    {(ip_target1, port_target1): [nbFrameRecord1, ip_attacker1, start_line1, end_line1],
    (ip_target2, port_target2): [nbFrameRecord2, ip_attacker2, start_line2, end_line2],
    ..., 
    (ip_targetN, port_targetN): [nbFrameRecordN, ip_attackerN, start_lineN, end_lineN]}

    nbFrameRecord (int) is a counter of DNS request frame received by the target from all attackers
    ip_attacker is a list of str, it contains all IP adresses that sent DNS request to the target
    start_line (int) is the first number of the line where the frame is a DNS request for a target
    end_line (int) is the last number of the line where the frame is a DNS request for a target
    """
    t = time.time()
    scan_report = dict()
    pcap_file = rdpcap(path)

    # Read all frames of the pcap file
    for i,frame in enumerate(pcap_file):
        layers = frame.layers()

        if len(layers) > 3 and layers[3].__name__ == 'DNS' and frame[DNS].qr == 0 and layers[1].__name__ == 'IP':
            ip_src = frame[IP].src
            ip_dst = frame[IP].dst

            if ip_dst not in scan_report:
                scan_report.setdefault(ip_dst, [0, set(), 0, 0]) # key: ip_dst -> [nb_DNS_request, ip_attackers, start_line, end_line]
                scan_report[ip_dst][2] = i+1
            scan_report[ip_dst][0] += 1
            scan_report[ip_dst][1].add(ip_src)
            scan_report[ip_dst][3] = i+1

    # Display the scan report
    if scan_report:
        print('\n'+30*'-'+' DNS FLOOD DETECTED '+30*'-')

        for ip_dst in scan_report:
            nbFrameRecord = scan_report[ip_dst][0]
            if nbFrameRecord > minFrame:
                start_line = scan_report[ip_dst][2]
                end_line = scan_report[ip_dst][3]
                print('\nTarget : {}'.format(ip_dst))
                print('{} DNS frames received from line {} to {} (wireshark)'.format(nbFrameRecord, start_line, end_line))

                if len(scan_report[ip_dst][1]) < maxIpToShow:
                    print('IP attacker(s):', ' '.join(scan_report[ip_dst][1]))

    else:
        print('\n'+30*'-'+' NO DNS FLOOD DETECTED '+30*'-')

    print('Detecting time: ', str(time.time()-t), ' seconds')

    return scan_report


def detectHttpGetFlood(path, minFrame=0, maxIpToShow=10): # minFrame=100000, maxIpToShow=10
    """
    Detect a HTTP Get flood attack (DDoS/DoS) captured in a pcap file

    ---------- STANDART HTTP QUERY ----------

    attacker -----  HTTP GET  ----> target
    attacker <---- HTTP reply ----- target

    ---------- HTTP GET FLOOD ATTACK ----------

    attacker -----  HTTP GET  ----> target
    attacker -----  HTTP GET  ----> target
    attacker -----  HTTP GET  ----> target
                        ...

    attacker <---- HTTP reply ----- target
    attacker <---- HTTP reply ----- target
    attacker <---- HTTP reply ----- target
                        ...

    Parameters in input:

    minFrame (int) is the minimum of frame recorded to show the report for a target
    maxIpToShow (int) is the maximum number of attackers IP to show for a target

    Return a report :

    {(ip_target1, port_target1): [nbFrameRecord1, ip_attacker1, start_line1, end_line1],
    (ip_target2, port_target2): [nbFrameRecord2, ip_attacker2, start_line2, end_line2],
    ..., 
    (ip_targetN, port_targetN): [nbFrameRecordN, ip_attackerN, start_lineN, end_lineN]}

    nbFrameRecord (int) is a counter of HTTP Get frame received by the target from all attackers
    ip_attacker is a list of str, it contains all IP adresses that sent HTTP Get to the target
    start_line (int) is the first number of the line where the frame is a HTTP Get for a target
    end_line (int) is the last number of the line where the frame is a HTTP Get for a target
    """
    t = time.time()
    scan_report = dict()
    pcap_file = rdpcap(path)

    # Read all frames of the pcap file
    for i,frame in enumerate(pcap_file):
        layers = frame.layers()

        if len(layers) > 3 and layers[3].__name__ == 'Raw':
            data = binascii.hexlify(bytes(frame[Raw].load)) # Get the data
            if data[:6] == b'474554': # If the data begin with a HTTP GET ('GET' = b'474554')
                ip_src = frame[IP].src
                ip_dst = frame[IP].dst

                if ip_dst not in scan_report:
                    scan_report.setdefault(ip_dst, [0, set(), 0, 0]) # key: ip_dst -> [nb_HTTP_GET, ip_attackers, start_line, end_line]
                    scan_report[ip_dst][2] = i+1
                scan_report[ip_dst][0] += 1
                scan_report[ip_dst][1].add(ip_src)
                scan_report[ip_dst][3] = i+1

    # Display the scan report
    if scan_report:
        print('\n'+30*'-'+' HTTP GET FLOOD DETECTED '+30*'-')

        for ip_dst in scan_report:
            nbFrameRecord = scan_report[ip_dst][0]
            if nbFrameRecord > minFrame:
                start_line = scan_report[ip_dst][2]
                end_line = scan_report[ip_dst][3]

                print('\nTarget : {}'.format(ip_dst))
                print('{} HTTP Get frames received from line {} to {} (wireshark)'.format(nbFrameRecord, start_line, end_line))

                if len(scan_report[ip_dst][1]) < maxIpToShow:
                    print('IP attacker(s):', ' '.join(scan_report[ip_dst][1]))

    else:
        print('\n'+30*'-'+' NO HTTP GET FLOOD DETECTED '+30*'-')

    print('Detecting time: ', str(time.time()-t), ' seconds')

    return scan_report


def detectTcpReset(path):
    t = time.time()
    scan_report = dict()
    pcap_file = rdpcap(path)

    # Read all frames of the pcap file
    for i,frame in enumerate(pcap_file):
        layers = frame.layers()

        if len(layers) > 2 and layers[2].__name__ == 'TCP':
            ip_src = frame[IP].src
            ip_dst = frame[IP].dst
            port_src = frame[TCP].sport
            port_dst = frame[TCP].dport

            # RST flag is set at least
            if frame[TCP].flags.value & 0x04 == 0x04:
                scan_report.setdefault(i+1, [ip_src, ip_dst, port_src, port_dst])

    # Display the scan report
    if scan_report:
        print('\n'+30*'-'+' TCP RESTET DETECTED '+30*'-')

        for i in scan_report:
            ip_src = scan_report[i][0]
            ip_dst = scan_report[i][1]
            port_src = scan_report[i][2]
            port_dst = scan_report[i][3]

            print('\nReset flag detected in line {} (wireshark) '.format(i))
            print('{} -> {}     {} -> {}'.format(ip_src, ip_dst, str(port_src), str(port_dst)))

    else:
        print('\n'+30*'-'+' NO TCP RESET DETECTED '+30*'-')

    print('\nDetecting time: ', str(time.time()-t), ' seconds')

    return scan_report


def showActivity(path):
    """
    Display the network activity in frames per seconds.

    Return a pyplot object.
    """
    t = time.time()
    pcap_file = rdpcap(path)
    time_ref = pcap_file[0].time # Set the time origin
    x = list(range(0, int(pcap_file[-1].time - time_ref + 1))) # Abcsise of the graph
    y = [0 for i in x]

    # Read all frames of the pcap file
    for i,frame in enumerate(pcap_file):
        y[int(frame.time - time_ref)] += 1

    print('Time: ', str(time.time()-t), ' seconds')
    
    plt.plot(x,y)
    plt.title('Network activity : Frames/s')
    plt.xlabel('Time (s)')
    plt.ylabel('Frames')
    plt.show()

    return plt