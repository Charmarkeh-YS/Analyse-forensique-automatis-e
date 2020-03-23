from scapy.all import *

class Trame():
#--- Classe qui définit une trame réseau tirée d'un pcap par différents paramètres ---
#--- Prends en paramètre pour la construction UNE trame (pas tout le pcap)
#--- Attributs : "protocole" = Nom du protocole de la trame ; "size" = taille de la trame ;
#--- "


#--- Type : 2048 -> IPv4 ; 2054 -> ARP ; 34525 -> IPv6
    def __init__(self,packet):
        print("\nCREATION DE L'OBJET TRAME \n")
        self.mac_src=packet[Ether].src      # Correspond à l'adresse mac source de la trame
        self.mac_dst=packet[Ether].dst      # Correspond à l'adresse mac destination de la trame
        self.type=packet[Ether].type        # Correspond au protocole de la couche 3 (Pour nous soit ARP / IP)
        if(self.type==2048):                # Si c'est une trame IP
            print("TYPE IP \n")
            self.type="IP"                  # On le renomme sous forme d'un string pour pouvoir l'utiliser
            self.ip_src=packet[IP].src      # Correspond à l'adresse ip source de la trame
            self.ip_dst=packet[IP].dst      # Correspond à l'adresse ip destintation de la trame
            self.size=packet[IP].len        # Correspond à la taille du protocole IP
            self.protocol=packet[IP].proto  # Correspond au protocole correspondant
            find_protocol(packet)           # Cherche le bon protocole correspondant à la trame et assigne les bons attributs 

        elif(self.type==2054):              # Si c'est une trame ARP
            print("TYPE ARP \n")
            if(packet[ARP].op==1):          # Repère le type de requête ARP (Requête/Réponse) assigné à self.req
                self.req="request"         
            elif(packet[ARP].op==2):
                self.req="answer"
            else:
                self.req="unknown"          
            self.ip_src=packet[ARP].psrc
            self.ip_dst=packet[ARP].pdst
        else:
            print("TYPE INCONNU\n")
        print("OBJET CREE\n")
        
    def find_protocol(self,packet):
        try:
            if(self.proto==6):
                protocol_tcp(packet)
            elif(self.proto==17):
                protocol_udp(packet)
            else:
                print("Protocole inconnu : {} ; à mettre à jour".format(self.proto))
        except Exception as e:
            print("Error : {}".format(e))

    def protocol_tcp(self,packet):
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
        self.flags=[flags for x in str(packet["TCP"].flags)]


    def protocol_udp(self,packet):
        self.protocol="UDP"
        self.port_src=packet["UDP"].sport
        self.port_dst=packet["UDP"].dport
        if(self.port_src==67 or self.port_src==68):
            protocol_dhcp(packet)

    def protocol_dhcp(self,packet):
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
        print("à faire")
    def protocol_telnet(self,packet):
        print("à faire")
    def protocol_http(self,packet):
        print("à faire")
    def protocol_https(self,packet):
        print("à faire")
    def protocol_icmp(self,packet):
        print("à faire")
    def protocol_ntp(self,packet):
        print("à faire")
    def protocol_ftp(self,packet):
        print("à faire")
    def protocol_tls(self,packet):
        print("à faire")
    def protocol_dns(self,packet):
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
