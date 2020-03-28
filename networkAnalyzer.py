#-*-coding:utf-8-*-
from trame import Trame
from scapy.all import *
<<<<<<< HEAD
from user import User


class NetworkAnalyzer():
    #---------------- Différents attributs ------------------
    #--- Tous les attributs sont récupérables à la construction de l'objet
    #--- trameList : une liste contenant toutes les trames du pcap (Via la classe Trame) 
    #--- userList : une liste contenant tous les utilisateurs du pcap (On considère un utilisateur = une adresse mac)
    #--- nbTrames : le nombre de trames totales

    #------------- Attributs de la classe User -------------------
    #--- userTramesList : une liste contenant toutes les trames liées à l'adresse mac
    #--- macAddr : la mac adresse de l'utilisateur
    #--- ipAddr : une liste des adresses ip de l'utilisateur (len(ipAddr)>1 : suspect)
    #--- Un compteur pour chaque type de protocole pour cet utilisateur

#************************************ CONSTRUCTEUR / DESTRUCTEUR *************************************
    def __init__(self,fileName):
        self.trameList=[]
        self.userList=[]
        self.nbTrames=0


        self.fileName=fileName
        if(self.fileName[-4:]!="pcap"):
            print(self.fileName[-4:])



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
            print("Inialisation de l'objet...")
            self.initializeTrameList()
            # Initialise la variable userList
            print("Initialisation de la liste des user...")
            self.initializeUserList()
        print("Objet analyser construit")
    def __del__(self):
        print("Destruction de l'objet")
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
                trame=Trame(packet,self.nbTrames+1)
                trame=Trame(packet)
                self.trameList.append(trame)
                self.nbTrames+=1
        except Exception as e:
            print("Error : {}".format(e))
            del self

    def initializeUserList(self):
        # Création d'une liste temporaire pour remplir les utilisateurs en fonction des adresses MAC 
        # présentes sur le pcap

        listCreationUser=[]
        for trame in self.trameList:
            # Si la liste est vide, on la remplit avec un tuple ("Mac",[liste des trames associées])
            if(len(listCreationUser)==0):
                listCreationUser.append((trame.mac_src,[trame]))
                continue
            i=0
            for mac_address,liste_trames_associees in listCreationUser:
            # On parcourt la liste en question
            # Si l'adresse mac n'existe pas, on ajoute un tuple
                for mac_address, liste_trames_associees in listCreationUser:
                    etat=0
                    for a,b in listCreationUser:
                        if(a==trame.mac_src):
                            etat=1

                    if(etat==0):
                        listCreationUser.append((trame.mac_src,[trame]))
            # Sinon, on ajoute la trame à l'adresse mac correspondante
                if(mac_address==trame.mac_src):
                    listCreationUser[i][1].append(trame)
                i+=1
                    
        # Création des objets User via la liste de tuple ("Mac",[Trame_liste_associee])
        for mac_address,liste_trames_associees in listCreationUser:
            user=User(liste_trames_associees,mac_address)
            self.userList.append(user)
#****************************************************************************************************

