from networkAnalyzer import NetworkAnalyzer

def main():
    handler= NetworkAnalyzer("./Pcaps/arppoison.pcap")
    
    for i,user in enumerate(handler.userList):
        print("User {} : {}".format(i+1,user.macAddr))
        print("Nombre de trames émises : {}".format(len(user.userTramesList)))
    print("Nombre de trames totales du pcap : {}".format(handler.nbFrame))
main()
