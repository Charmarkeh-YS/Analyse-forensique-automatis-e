from networkAnalyzer import NetworkAnalyzer

def main():
    handler= NetworkAnalyzer("./Pcaps/arppoison.pcap")
    
    i=1
    for user in handler.userList:
        
        print("User {} : {}".format(i,user.macAddr))
        print("Nombre de trames émises : {}".format(len(user.userTramesList)))
        i+=1
    print("Nombre de trames totales du pcap : {}".format(handler.nbTrames))
main()
