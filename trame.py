#-*-coding:utf-8-*-

class Trame:
#--- Classe qui définit une trame réseau tirée d'un pcap par différents paramètres ---
#--- Prends en paramètre pour la construction UNE trame (pas tout le pcap)


#--- Type : 2048 -> IPv4 ; 2054 -> ARP ; 34525 -> IPv6
    def __init__(self,packet,identifiant):
        print("\nCREATION DE L'OBJET TRAME")
        self.poids=0
        self.id=identifiant
        self.mac_src=packet["Ethernet"].src      # Correspond à l'adresse mac source de la trame
        self.mac_dst=packet["Ethernet"].dst      # Correspond à l'adresse mac destination de la trame
        self.type=packet["Ethernet"].type        # Correspond au protocole de la couche 3 (Pour nous soit ARP / IP)
        if(self.type==2048):                # Si c'est une trame IP
            print("TYPE IP")
            self.type="IP"                  # On le renomme sous forme d'un string pour pouvoir l'utiliser
            self.ip_src=packet["IP"].src      # Correspond à l'adresse ip source de la trame
            self.ip_dst=packet["IP"].dst      # Correspond à l'adresse ip destintation de la trame
            self.size=packet["IP"].len        # Correspond à la taille du protocole IP
            self.proto=packet["IP"].proto  # Correspond au protocole correspondant
            self.find_protocol(packet)           # Cherche le bon protocole correspondant à la trame et assigne les bons attributs 

        elif(self.type==2054):              # Si c'est une trame ARP
            print("TYPE ARP \n")
            self.type="ARP"
            self.protocol="ARP"
            if(packet["ARP"].op==1):          # Repère le type de  requête ARP (Requête/Réponse) assigné à self.req
                self.req="request"         
            elif(packet["ARP"].op==2):
                self.req="answer"
            else:
                self.req="unknown"          
            self.ip_src=packet["ARP"].psrc
            self.ip_dst=packet["ARP"].pdst
        else:
            print("TYPE INCONNU\n")
        print("OBJET {} CREE\n".format(self.id))

    def find_protocol(self,packet):
        try:
            if(self.proto==6):
                self.protocol_tcp(packet)
            elif(self.proto==17):
                self.protocol_udp(packet)
            elif(self.proto==1):
                self.protocol_icmp(packet)
            else:
                print("Protocole inconnu : {} ; à mettre à jour".format(self.proto))
        except Exception as e:
            print("Error : {}".format(e))

    def protocol_tcp(self,packet):
# ---------------- Attributs : protocol | port_src | port_dst | (data) | flags ------
        flags = {
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
        # On repère si les données Raw sont vides :
        # Si c'est vide, c'est juste un protocole TCP simple et on ne fait rien
        try:
            self.data=packet["Raw"].load
            # Signature d'une trame TLS avec les deux versions différentes
            if(self.data[1:3]==b'\x03\x03' or self.data[1:3]==b'\x03\x01'):
                self.protocol_tls(packet)
            # Un paquet TCP avec des datas est une requête FTP
            elif(self.port_src==80 or self.port_dst==80):
                self.protocol_http(packet)
            elif(self.port_src==443 or self.port_dst==443):
                self.protocol_https(packet)
            elif(self.port_src==23 or self.port_dst==23):
                self.protocol_telnet(packet)
            elif(self.port_src==22 or self.port_dst==22):
                self.protocol_ssh(packet)
            elif(packet["TCP"].flags=="A"):
                self.protocol_ftp_data(packet)
            elif(packet["TCP"].flags=="PA"):
                self.protocol_ftp(packet)
            else:
                print("Unknown trame | à mettre à jour")
        except Exception as e:
            print(e)
        if(self.flags=="PA"):
            protocol_ftp(packet)
        elif(self.flags=="A"):
            protocol_ftp_data(packet)
    def protocol_udp(self,packet):
# ---------------- Attributs : protocol | port_src | port_dst ----------------------
        self.protocol="UDP"
        self.port_src=packet["UDP"].sport
        self.port_dst=packet["UDP"].dport
        if(self.port_src==67 or self.port_src==68):
            self.protocol_dhcp(packet)
        elif(self.port_src==53 or self.port_dst==53):
            self.protocol_dns(packet)

    def protocol_dhcp(self,packet):
# ---------------- Attributs : protocol | option -----------------------------------
        self.protocol="DHCP"         # On actualise le protocole
        self.option=packet["DHCP options"].options[0][1]
        if(self.option==1):
            self.option="Discover"
        elif(self.option==2): 
            self.option="Offer"
        elif(self.option==3):
            self.option="Request"
        elif(self.option==5):
            self.option="Ack"
        else:
            print("Option DHCP inconnue : {} | Mettre à jour".format(self.option))
    def protocol_smtp(self,packet):
        print("à faire")

    def protocol_ntlm(self,packet):
        print("à faire")

    def protocol_ssh(self,packet):
        self.protocol="SSH"

    def protocol_telnet(self,packet):
        self.protocol="TELNET"
    def protocol_http(self,packet):
        self.protocol="HTTP"

    def protocol_https(self,packet):
        self.protocol="HTTPS"

    def protocol_icmp(self,packet):
# ---------------- Attributs : protocol | data | icmp_type -------------------------
        self.protocol="ICMP"
        self.data=packet["Raw"].load
        self.icmp_type=packet["ICMP"].type
        if(self.icmp_type==0):
            self.icmp_type="Reply"
        elif(self.icmp_type==8):
            self.icmp_type="Request"
        else:
            print("Unknown ICMP type {} | à mettre à jour".format(self.icmp_type))

    def protocol_ntp(self,packet):
        print("à faire")

    def protocol_ftp(self,packet):
# -------------------- Attributs : protocol ----------------------------------------
        self.protocol="FTP"

    def protocol_ftp_data(self,packet):
# -------------------- Attributs : protocol ----------------------------------------
        self.protocol="FTP-Data"

    def protocol_tls(self,packet):
# -------------------- Attributs : protocol | tls_protocol -------------------------
        self.protocol="TLS"
        self.tls_protocol=self.data[0]
        if(self.tls_protocol==b'\x21'):
            self.tls_protocol="Alert"
        elif(self.tls_protocol==b'\x22'):
            self.tls_protocol="Handshake"
        elif(self.tls_protocol==b'\x23'):
            self.tls_protocol="Application data"
        else:
            print("Unknown TLS protocol number {} | mettre à jour".format(self.tls_protocol))

    def protocol_dns(self,packet):
        self.protocol="DNS"
        self.qdcount=packet["DNS"].qdcount  # DNS Question Record
        self.ancount=packet["DNS"].ancount  # DNS Resource Record
        self.nscount=packet["DNS"].nscount  # DNS SOA Resource Record
        self.arcount=packet["DNS"].arcount  # A compléter
        self.qname=[]
        self.qtype=[]
        self.qclass=[]
        self.an_rrname=[]
        self.an_type=[]
        self.an_rclass=[]
        self.an_ttl=[]
        self.an_rdlen=[]
        self.an_rdata=[]
        self.ns_rrname=[]
        self.ns_type=[]
        self.ns_rclass=[]
        self.ns_ttl=[]
        self.ns_rdlen=[]
        self.ns_mname=[]
        self.ns_rname=[]
        self.ns_serial=[]
        self.ns_refresh=[]
        self.ns_retry=[]
        self.ns_expire=[]
        self.ns_minimum=[]
        for i in range(self.qdcount):
            tempo=packet["DNS"].qd[i]
            self.qname.append(tempo.qname)
            self.qtype.append(tempo.qtype)
            self.qclass.append(tempo.qclass)

        for i in range(self.ancount):
            tempo=packet["DNS"].an[i]
            self.an_rrname.append(tempo.rname)
            self.an_type.append(tempo.type)
            self.an_rclass.append(tempo.rclass)
            self.an_ttl.append(tempo.ttl)
            self.an_rdlen.append(tempo.rdlen)
            self.an_rdata.append(tempo.rdata)
        for i in range(self.nscount):
            tempo=packet["DNS"].ns[i]
            self.ns_rrname.append(tempo.rrname)
            self.ns_type.append(tempo.type)
            self.ns_rclass.append(tempo.rclass)
            self.ns_ttl.append(tempo.ttl)
            self.ns_rdlen.append(tempo.rdlen)
            self.ns_mname.append(tempo.mname)
            self.ns_rname.append(tempo.rname)
            self.ns_serial.append(tempo.serial)
            self.ns_refresh.append(tempo.refresh)
            self.ns_retry.append(tempo.retry)
            self.ns_expire.append(tempo.expire)
            self.ns_minimum.append(tempo.minimum)
        for i in range(self.arcount):
            print("à faire")
    def protocol_ntp(self,packet):
        print("à faire")
    def protocol_snmp(self,packet):
        print("à faire")
    def protocol_kerberos(self,packet):
        print("à faire")
    def protocol_cas(self,packet):
        print("à faire")
    def protocol_pap(self,packet):
        print("à faire")
    def protocol_radius(self,packet):
        print("à faire")

#--- 
