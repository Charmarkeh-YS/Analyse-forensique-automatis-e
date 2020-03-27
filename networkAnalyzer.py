#-*-coding:utf-8-*-
from trame import Trame
from scapy.all import *



class NetworkAnalyzer():

#******************************************** ATTRIBUTS **********************************************

    self.trameList=[]
    self.userList=[]
    self.nbTrames=0

#************************************ CONSTRUCTEUR / DESTRUCTEUR *************************************
    def __init__(self,fileName):
        self.fileName=fileName
        if(self.fileName.split(".")[1]!="pcap"):
            print("Mauvaise extension")
            del self       # STOP LE PROGRAMME
        else:
            print("Reading {}".format(fileName))
            self.initializeTrameList()
            # Initialise la variable userList
            self.defineUserList()

    def __del__(self):
        print("Erreur : Destruction de l'objet")

#*********************************** FONCTIONS D'INITIALISATIONS *************************************
    def initializeTrameList(self):
        try:
            packets=rdpcap(self.fileName)
            for packet in packets:
                trame=Trame(packet)
                self.trameList.append(trame)
                self.nbTrames+=1
        except Exception as e:
            print("Error : {}".format(e))
            del self

    def initializeUserList(self):
        # Création d'une liste temporaire pour remplir les utilisateurs en fonction des adresses MAC 
        # présentes sur le pcap
        
        for trame in self.trameList:
            if(
#****************************************************************************************************

    def __del__(self):
        print("Erreur : fichier donné en paramètre incorrecte")
