#-*-coding:utf-8-*-

class Trame:

    def __init__(self,packet,identifiant):
        self.poids=0
        self.id=identifiant
        #print("Creating frame {}...".format(self.id))
        self.layers=packet.layers()
        self.protocol="Ethernet"
        #print(self.layers)
        for i,layer in enumerate(self.layers):
            current_layer=layer.__name__

            #---------------------------- Verification functions / Upgrade functions ----------------------- 
            
            if(current_layer!="Ether" and i==0):
                print("First layer of frame {} is not ethernet -> need to be checked".format(identifiant))
            if(current_layer!="IP" and current_layer!="ARP" and i==1):
                print("Second layer of frame {} is not IP or ARP -> need an upgrade".format(self.id))
            
            # ----------------------------------------------------------------------------------------------- 
            functions_layer={
                "Ether" : self.setEthernetAttributs,
                "ARP" : self.setArpAttributs,
                "IP" : self.setIpAttributs,
                "UDP" : self.setUdpAttributs,
                "TCP" : self.setTcpAttributs,
                "Raw" : self.setRawAttributs,
                "Padding" : self.setPaddingAttributs,
                "DNS" : self.setDnsAttributs,
                "ICMP" : self.setIcmpAttributs,
                "BOOTP" : self.setDhcpAttributs,
                "DHCP" : self.doNothing,
                "IPerror": self.setIpErrorAttributs,
                "UDPerror":self.setUdpErrorAttributs,
                "IPv6" : self.doNothing,
                "PPTP" : self.doNothing,
                "Skinny" : self.doNothing,
            }
            try:
                functions_layer[current_layer](packet)
            except Exception as e:
                print("Frame {}".format(self.id))
                print("Error in functons_layer : {} | Probably an unknown protocol {}".format(e,current_layer))
    def setEthernetAttributs(self,packet):
        self.mac_src=packet["Ethernet"].src
        self.mac_dst=packet["Ethernet"].dst
        self.type=packet["Ethernet"].type
    def setIpErrorAttributs(self,packet):
        print("TODO IP ERROR")
    def setUdpErrorAttributs(self,packet):
        print("TODO UDP ERROR")
    def setRawAttributs(self,packet):
        self.data=packet["Raw"].load
        if(hasattr(self,"port_src")):
            if(self.data[1:3]==b'\x03\x03' or self.data[1:3]==b'\x03\x01'):
                self.setTlsAttributs(packet)
            elif(self.port_src==80 or self.port_dst==80):
                self.setHttpAttributs(packet)
            elif(self.port_src==23 or self.port_dst==23):
                self.setTelnetAttributs(packet)
            elif(self.port_src==22 or self.port_dst==22):
                self.setSshAttributs(packet)
            elif(self.port_src==443 or self.port_dst==443):
                self.setHttpsAttributs(packet)
            elif(self.port_src==21 or self.port_dst==21):
                self.setFtpAttributs(packet)
    def setHttpsAttributs(self,packet):
        self.protocol="HTTPS"
    def setDnsAttributs(self,packet):
        opcodes={
            0:"QUERY",
            1:"IQUERY",
            2:"STATUS",
        }
        qrcodes={
            0:"ok",
            1:"format-error",
            2:"server-failure",
            3:"name-error",
            4:"not-implemented",
            5:"refused",
        }
        try:
            self.opcode=opcodes[packet["DNS"].opcode]
        except Exception as e:
            print("Frame {}".format(self.id))
            print("Error in setDnsAttributs : Value incorrect -> fill dict opcodes".format(e,packet["DNS"].opcode))
            packet.show()
        try:
            self.qrcode=qrcodes[packet["DNS"].qr]
        except Exception as e:
            print("Frame {}".format(self.id))
            print("Error in setDnsAttributs : Value incorrect -> fill dict qrcodes".format(e,packet["DNS"].qrcode))
            packet.show()
        self.protocol="DNS"
        
        self.qdcount=packet["DNS"].qdcount  # DNS Question Record
        self.ancount=packet["DNS"].ancount  # DNS Resource Record
        self.nscount=packet["DNS"].nscount  # DNS SOA Resource Record
        self.arcount=packet["DNS"].arcount  # DNS
        self.qd=packet["DNS"].qd
        self.an=packet["DNS"].an
        self.ns=packet["DNS"].ns
        self.ar=packet["DNS"].ar
    def setTlsAttributs(self,packet):
        self.protocol="TLS"
    def setFtpAttributs(self,packet):
        self.protocol="FTP"
        self.ftp_request=str(packet["Raw"].load)
        #print("{} : {}/{} ftp request {}".format(self.protocol,self.ip_src,self.ip_dst,self.ftp_request))
    def setFtpDataAttributs(self,packet):
        print("TODO FTP-Data")
    def setSshAttributs(self,packet):
        self.protocol="SSH"
        self.ssh_key_exchange_init=False
        # On repère le protocol "Key exchange init"
        if(self.data[5]==20):
            self.ssh_key_exchange_init=True
    def setTelnetAttributs(self,packet):
        self.protocol="TELNET"
    def setPaddingAttributs(self,packet):
        self.padding=str(packet["Padding"].load)
    def setDhcpAttributs(self,packet):
        self.protocol="DHCP"
        dhcp_options={
            1 : "Discover",
            2 : "Offer",
            3 : "Request",
            5 : "Ack",
            8 : "Bootrequest",
        }
        try:
            self.option=dhcp_options[packet["DHCP options"].options[0][1]]
        except Exception as e:
            print("Frame {}".format(self.id))
            print("Error : {} | Value {} incorrect -> fill dict dhcp_options".format(e,packet["DHCP options"].options[0][1]))
            packet.show()
    def setArpAttributs(self,packet):
        self.protocol="ARP"
        self.ip_src=packet[self.protocol].psrc
        self.ip_dst=packet[self.protocol].pdst
        arp_op={
                1 : "request",
                2 : "answer",
        }
        try:
            self.op=arp_op[packet[self.protocol].op]
        except Exception as e:
            print("Frame {}".format(self.id))
            print("Error : {} | Value {} incorrect -> fill dict arp_op".format(e,packet[self.protocol].op))
            packet.show()
    def setIpAttributs(self,packet):
        self.protocol="IP"
        self.ip_src=packet["IP"].src
        self.ip_dst=packet["IP"].dst
        self.ip_len=packet["IP"].len

    def setUdpAttributs(self,packet):
        self.protocol="UDP"
        self.port_src=packet["UDP"].sport
        self.port_dst=packet["UDP"].dport
        self.udp_len=packet["UDP"].len

    def setTcpAttributs(self,packet):
        flags= {
            'F': 'FIN',
            'S': 'SYN',
            'R': 'RST',
            'P': 'PSH',
            'A': 'ACK',
            'U': 'URG',
            'E': 'ECE',
            'C': 'CWR',
        }
        self.protocol="TCP"
        self.port_src=packet["TCP"].sport
        self.port_dst=packet["TCP"].dport
        self.flags=[flags[x] for x in str(packet["TCP"].flags)]
        self.ack=packet["TCP"].ack
        self.seq=packet["TCP"].seq
    def setIcmpAttributs(self,packet):
        self.protocol="ICMP"
        icmp_types= {
            0 : "Reply",
            3 : "Destination unreacheable",
            8: "Request",
        }
        try:
            self.icmp_type=icmp_types[packet["ICMP"].type]
        except Exception as e:
            print("Frame {}".format(self.id))
            print("Error : {} | Value {} incorrect -> fill dict icmp_types".format(e,packet["ICMP"].type))

    def setHttpAttributs(self,packet):
        self.protocol="HTTP"
        self.data=packet["Raw"].load
    def doNothing(self,packet):
        pass

