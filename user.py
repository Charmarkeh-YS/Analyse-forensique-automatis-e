#-*-coding:utf-8-*-

class User():
#--- Classe qui définit un utilisateur à partir d'une liste d'objets Trames
#--- En paramètre pour le constructeur, donner une liste de trames ayant la même adresse mac en source
    self.tcpCount=0
    self.udpCount=0
    self.ipCount=0
    self.arpCount=0
    self.dhcpCount=0
    self.smtpCount=0
    self.ntlmCount=0
    self.sshCount=0
    self.telnetCount=0
    self.httpCount=0
    self.httpsCount=0
    self.icmpCount=0
    self.ntpCount=0
    self.ftpCount=0
    self.tlsCount=0
    self.dnsCount=0
    self.ntpCount=0
    self.snmpCount=0
    self.userTramesList=[]
    self.suspect=False

    def __init__(self,listTrames):
        self.macAddr=listTrames[0].mac_src
        self.ipAddr=listTrames[0].ip_src             # ATTENTION : LISTE
        protocoles=[("TCP",self.tcpCount),("UDP",self.udpCount),("IP",self.ipCount),("ARP",self.arpCount),
                ("DHCP",self.dhcpCount),("SMTP",self.smptCount),("NTLM",self.ntlmCount),("SMTP",self.smptCount),
                ("SSH",self.sshCount),("TELNET",self.telnetCount),("HTTP",self.httpCount),
                ("HTTPS",self.httpsCount),("ICMP",self.icmpCount),("NTP",self.ntpCount),("FTP",self.ftpCount),
                ("TLS",self.tlsCount),("DNS",self.dnsCount),("NTP",self.ntpCount),("SNMP",self.snmpCount)]
        for trame in listTrames:
            # Ajoute la trame courante dans la liste des trames appartenant à l'utilisateur
            userTramesList.append(trame)
            for proto in protocoles:
                # Parcourt la liste protocoles et ajoute 1 au compteur en fonction du bon protocole
                if(trame.protocole==proto[0]):
                    proto[1]+=1
            # Idée temporaire pour détecter suspiscion de changement suspect d'adresse ip
            if(trame.ip_src!=self.ipAddr):
                self.suspect=True
