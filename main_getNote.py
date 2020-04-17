from getNote import *


def main():
    url1="netflix.com"
    url2="facebook.com"
    url3="google.com"

    # ATTENTION LE RETURN EST EN BYTE TYPE : A CONVERTIR EN STRING SI BESOIN
    
    note1=getNote(url1)
    note2=getNote(url2)
    note3=getNote(url3)
    

    print("url {} note {}".format(url1,note1))
    print("url {} note {}".format(url2,note2))
    print("url {} note {}".format(url3,note3))


    url4="https://www.netflix.com"
    note4=getNote(url4)

    print("url {} note {}".format(url4,note4))

main()
