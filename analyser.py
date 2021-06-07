


def validOffset(offset, prevOffset):
    """Fonction qui compare les deux arguments et rend True si le premier est superieur au second . 
    Arguments : $1 : offset courant, $2 : offset precedant.
    Retourne : True si l'offset courant est valide (il est superieur au precedent)
    Remarque : dans cette fonction,on se contente de les comparer ( on ne verifie pas si la valeur est exacte)
    """
    try:
        off = int(offset, 16) #traduire l'offset en base hexadecimale 
    except:
        return False
    if off == 0 :
        return True
    return off >= prevOffset 

def validByteSequence (ByteSequence, nbrOctets): 
    """Fonction qui lit la sequences d'octets passee en parametres .
    Arguments : $1 : sequence d'octets ( ligne d'une trame), $2 : nombre d'octets.
    Retourne : True si tous les nbrOctets correspondent bien a des caracteres hexadecimaux, False sinon
    """
    stop = False
    ind = 0
    while not stop :
        if nbrOctets == 0 :
            return True
        try:
            int(ByteSequence[ind], 16) #on recupere l'octet a la position i 
        except:
            return False

        ind+=1
        nbrOctets-=1

def parse_file (file):
    """Fonction qui lit le fichier qui contient les trames a analyser.
    Retourne : un dictionnaire des trames correctes, trames erronees ainsi que les lignes qui sont fausses dans ces dernieres.
    Argument : fichier qui se trouve dans le meme repertoire.
    """
    lines = file.readlines()
    validLines, linesPosition = [], {}
    currentOffset = 0

    for index in range(len(lines)):
        line = lines[index].strip().lower() #enlever les espaces a gauche et a droite, et mettre tous les caracteres en minuscule
        if line :
            offset = line.split(maxsplit=1)[0] #lire l'offset qui est en debut de ligne
        else:
            offset = ""
        if validOffset(offset, currentOffset):
            currentOffset = int(offset, 16)
            linesPosition[line] = index
            validLines.append(line) #si l'offset de la ligne est valide, on l'ajoute dans le tableau
        else:
            print("line removed  :  ", lines[index])

    listeTramesCorrectes = []
    listeTramesErronees = []
    lignesErronees = []

    for index in range(len(validLines)):

        currentOffset = int(validLines[index].split(maxsplit=1)[0], 16)
        if index+1 == len(validLines) : #Cas de la dernière ligne où il n'y a pas de suivant
            nextOffset = 0
        else:
            nextOffset = int(validLines[index+1].split(maxsplit=1)[0], 16)
        if currentOffset == 0:
            trame = []
            trameValide = True
        
        splittedLine = validLines[index].split()

        if nextOffset != 0 :
            nbrOctetsSurLaLigne = nextOffset - currentOffset

            if validByteSequence(splittedLine[1:], nbrOctetsSurLaLigne) : 
                trame.extend(splittedLine[1:nbrOctetsSurLaLigne+1])
            else:
                lignesErronees.append(linesPosition[validLines[index]])
                trameValide = False
        else: 
            # Next offset == 0 veut dire c'est la fin de la trame
            # Problème du nombre d'octets dans la dernière ligne
            # on doit calculer la longueur du packet IP pour savoir les charactères qui représentent des octets
            # de ceux qui sont éventuellement ajoutés à la fin cette dernière ligne

            if trame[12]+trame[13] == "0806":   # Cas du protocol ARP
                frameLength = 60-14         #Minimum length of ethernet frame
            else :
                if len(trame) > 18:  
                    frameLength = int(trame[16]+trame[17], 16)
                else:
                    frameLength = -1
                    if len(splittedLine[1:]) > 18 - len(trame) :  
                        try:
                            frameLength = int(splittedLine[17-len(trame)]+splittedLine[18-len(trame)], 16)
                        except: 
                            trameValide = False
                            lignesErronees.append(linesPosition[validLines[index]])
                            print("Champs longueur totale du datagramme IP érroné ligne erronée : numéro :", linesPosition[validLines[index]])
            nbrOctetsSurLaLigne = frameLength + 14 - len(trame)     #frameLength représente la longueur totale de la trame
                                                                    # 14 est la longueur de l'entete ethernet     
            if validByteSequence(splittedLine[1:], nbrOctetsSurLaLigne) :
                print(splittedLine[1:nbrOctetsSurLaLigne+1])
                trame.extend(splittedLine[1:nbrOctetsSurLaLigne+1])
            else:
                trameValide = False
                lignesErronees.append(linesPosition[validLines[index]])

            if trameValide :
                listeTramesCorrectes.append(trame)
            else:
                listeTramesErronees.append(trame)

    return {"trames correctes" : listeTramesCorrectes,
            "trames erronees" : listeTramesErronees,
            "lignes erronees" : lignesErronees,
            }

def couches (dic):
    trames = dic["trames correctes"]
    nbrTrames = len(trames)
    print(Colors.FAIL+Colors.BOLD+"Le nombre de trames erronees est : " + str(len(dic["trames erronees"])) + Colors.ENDC)
    outputFile.write("Le nombre de trames erronees est : " + str(len(dic["trames erronees"]))+"\n")
    for lig in dic["lignes erronees"]:
        print("\tLigne numero {} erronnée ou imcomplète".format(lig))
        outputFile.write("\tLigne numero {} erronnée ou imcomplète\n".format(lig))
    print(Colors.OKGREEN+Colors.BOLD+"Le nombre de trames correctes est : "+ str(nbrTrames)+ Colors.ENDC+"\n")
    outputFile.write("Le nombre de trames correctes est : "+ str(nbrTrames)+"\n"+"\n")
    for trame, i  in zip(trames, range(len(trames))) :
        print(Colors.WARNING+"Trame numero {} : -- {} octets --".format(i, len(trame))+Colors.ENDC)
        outputFile.write("Trame {} : -- {} octets --\n".format(i, len(trame)))
        try :
            ethernet(trame)
        except Exception as e:
            if hasattr(e, 'message'):
                print(e.message)
            else:
                print(e)
            
        print("\n")
        outputFile.write("\n")


def ethernet (trame) : 
    """Fonction qui analyse la trame Ethernet, et affiche tous les champs 
    Argument : trame a analyser
    """
    typeProtocol = {"0800": "IPV4", "0805": "X.25 niveau 3", "0806" : "ARP"}
    adrDestination = trame[0]+":"+trame[1]+":"+trame[2]+":"+trame[3]+":"+trame[4]+":"+trame[5]
    adrSource = trame[6]+":"+trame[7]+":"+trame[8]+":"+trame[9]+":"+trame[10]+":"+trame[11]
    typee = trame[12]+trame[13]
    print("   "+Colors.BOLD+Colors.UNDERLINE+"Protocol Ethernet:"+Colors.ENDC)
    print("\tDestination: {}".format(adrDestination))
    print("\tSource: {}".format(adrSource))

    if(typee in typeProtocol.keys()):
        print("\tType: {} (0x{}) ".format(typeProtocol[typee], typee))
        outputFile.write("\tType: {} (0x{}) \n".format(typeProtocol[typee], typee))
    
    outputFile.write("   Protocol Ethernet:\n")
    outputFile.write("\tDestination: {}\n".format(adrDestination))
    outputFile.write("\tSource: {}\n".format(adrSource))
   
    if typee == "0800":
        IPV4(trame)
    elif typee == "0806":
        ARP(trame)
    else :
        print(Colors.WARNING+Colors.BOLD+"  Protocol numéro {} non supporté".format(typee)+Colors.ENDC)
        outputFile.write("  Protocol numéro {} non supporté\n".format(typee))


def ARP (trame):
    """Fonction qui analyse le datagramme ARP et affiche tous les champs de ce protocole
    Argument : trame a analyser
    Hypothèse :  hardware type == Ethernet
                 protocol type == IPv4
    """
    print("   "+Colors.BOLD+Colors.UNDERLINE+"Adress Resolution Protocol:"+Colors.ENDC)
    outputFile.write("   Adress Resolution Protocol:\n")
    offset = 14  
    hardware = trame[offset]+trame[offset+1]
    protocol = trame[offset+2]+trame[offset+3]
    hlen = trame[offset+4]
    plen = trame[offset+5]
    operation =  trame[offset+6]+trame[offset+7]
    Sha =  trame[offset+8]+":"+trame[offset+9]+":"+trame[offset+10]+":"+trame[offset+11]+":"+trame[offset+12]+":"+trame[offset+13]
    Spa =  ".".join([str(int(oc, 16)) for oc in trame[offset+14:offset+18]])
    Tha =  trame[offset+18]+":"+trame[offset+19]+":"+trame[offset+20]+":"+trame[offset+21]+":"+trame[offset+22]+":"+trame[offset+23]
    Tpa =  ".".join([str(int(oc, 16)) for oc in trame[offset+24:offset+28]])
    if   int(hardware,16) == 1:  
        print("\tHardware type: Ethernet (1)")
        outputFile.write("\tHardware type: Ethernet (1)\n")
        
    if protocol == "0800":
        print("\tProtocol type: IPv4 (0x0800)") 
        outputFile.write("\tProtocol type: IPv4 (0x0800)\n")


    print("\tHardware size: {}".format(int(hlen,16)))
    outputFile.write("\tHardware size: {}\n".format(int(hlen,16)))
    print("\tProtocol size: {}".format(int(plen,16)))
    outputFile.write("\tProtocol size: {}\n".format(int(plen,16)))
    opcode = {"0001" : "request (1)", "0002" : "reply (2)"}
    print("\tOpcode: {}".format(opcode[operation]))
    outputFile.write("\tOpcode: {}\n".format(opcode[operation]))
    print("\tSender Hardware address: {}".format(Sha))
    outputFile.write("\tSender Hardware address: {}\n".format(Sha))
    print("\tSender Protocol adress: {}".format(Spa))
    outputFile.write("\tSender Protocol adress: {}\n".format(Spa))
    print("\tTarget Hardware address: {}".format(Tha))
    outputFile.write("\tTarget Hardware address: {}\n".format(Tha))
    print("\tTarget Protocol adress: {}".format(Tpa))
    outputFile.write("\tTarget Protocol adress: {}\n".format(Tpa))



def IPV4(trame):
    """Fonction qui analyse le datagramme IP version 4, et affiche tous les champs de ce protocole
    Argument : trame a analyser
    Hypothese : on suppose que toutes les trames a analyser sont en version 4
    """
    
    offset = 14     #début du datagramme IPV4 par rapport au début de la trame
    protocols= {1: "ICMP", 2 : "IGMP", 6 : "TCP", 17: "UDP", 36 : "XTP"}

    version = trame[offset+0][0]

    headerLength32 = int(trame[offset+0][1], 16)  
    if headerLength32<5 :
        raise ValueError("Valeur minimum du header IP est 20 octets.")

    Tos =  trame[offset+1]

    totalLength = trame[offset+2]+trame[offset+3]
    

    identification = trame[offset+4]+trame[offset+5]
    firstByte = format(int(trame[offset+6], 16), '08b')
    secondByte = format(int(trame[offset+7], 16), '08b')
    reservedBit = firstByte[0]
    doNotFragment = firstByte[1]
    moreFragment = firstByte[2]
    fragmentOffset = firstByte[3:]+secondByte

    Ttl = trame[offset+8]
    protocol = int(trame[offset+9], 16)
    
    headerChecksum =trame[offset+10]+trame[offset+11]
    source_addr= '.'.join([str(int(x,16)) for x in trame[offset+12:offset+16]])
    dest_addr='.'.join([str(int(x,16)) for x in trame[offset+16:offset+20]])
    optionsType = 1

    print("   "+Colors.BOLD+Colors.UNDERLINE+"Internet Protocol Version 4:"+Colors.ENDC)
    print("\t{} .... = Version: 4 ".format(format(int(version, 16), '04b')))
    print("\t.... {} = Header Length: {} bytes ({}) ".format(format(int(str(headerLength32), 16), '04b'),int(str(headerLength32),16)*4,headerLength32))
    print("\tIdentification: 0x{} ({})".format(identification,int(identification,16)))
    dic_set_not_set={"0":"Not set","1":"Set"}
    print("\tFlags: 0x{} ".format(trame[offset+6]))
    print("\t\t{}... .... = Reserved bit: {} ".format(reservedBit,dic_set_not_set[reservedBit]))
    print("\t\t.{}.. .... = Don't fragment: {} ".format(doNotFragment,dic_set_not_set[doNotFragment]))
    print("\t\t..{}. .... = More fragments: {} ".format(moreFragment,dic_set_not_set[moreFragment]))
    print("\tTotal Length: {}".format(int(totalLength,16)))
    print("\tTime to Live: {}".format(int(Ttl,16)))

    if(protocol in protocols.keys()):
        print("\tProtocol: {} ({})".format(protocols[protocol],protocol))
        outputFile.write("\tProtocol: {} ({})\n".format(protocols[protocol],protocol))

    print("\tHeader Checksum: 0x{}".format(headerChecksum))
    print("\tSource Address: {}".format(source_addr))
    print("\tDestination Address: {}".format(dest_addr))


    outputFile.write("   Internet Protocol Version 4:\n")
    outputFile.write("\t{} .... = Version: 4 \n".format(format(int(version, 16), '04b')))
    outputFile.write("\t.... {} = Header Length: {} bytes ({}) \n".format(format(int(str(headerLength32), 16), '04b'),int(str(headerLength32),16)*4,headerLength32))
    outputFile.write("\tIdentification: 0x{} ({})\n".format(identification,int(identification,16)))
    outputFile.write("\tFlags: 0x{} \n".format(trame[offset+6]))
    outputFile.write("\t\t{}... .... = Reserved bit: {} \n".format(reservedBit,dic_set_not_set[reservedBit]))
    outputFile.write("\t\t.{}.. .... = Don't fragment: {} \n".format(doNotFragment,dic_set_not_set[doNotFragment]))
    outputFile.write("\t\t..{}. .... = More fragments: {} \n".format(moreFragment,dic_set_not_set[moreFragment]))
    outputFile.write("\tTotal Length: {}\n".format(int(totalLength,16)))
    outputFile.write("\tTime to Live: {}\n".format(int(Ttl,16)))
    outputFile.write("\tHeader Checksum: 0x{}\n".format(headerChecksum))
    outputFile.write("\tSource Address: {}\n".format(source_addr))
    outputFile.write("\tDestination Address: {}\n".format(dest_addr))

    #----------------------------OPTIONS IP----------------------------
    #HYPOTHESE : on suppose que toutes les options traitees, contiennent un champs longueur en 2eme position 
    #qui nous donne la longueur de cette option
    #SAUF : les options 0 et 1 qui sont sur 1 octet seulement
    
    if (headerLength32 > 5):#Le header IP contient des options ssi sa longueur est superieur a 20 octets (en decimal)

        nbrOctetsOptions = (headerLength32 - 5) * 4
        print("\tOptions: {} bytes".format(nbrOctetsOptions))
        outputFile.write("\tOptions: {} bytes\n".format(nbrOctetsOptions))
        off = offset+20

        while True : 
            if nbrOctetsOptions == 0 : 
                break
            premierOctetOption = trame[off]#cet octet nous renseigne sur le champ type de l'option

            if (int(premierOctetOption, 16) == 0):
                print("\t  IP Option  -  End of Options List (EOL)")
                outputFile.write("\t  IP Option  -  End of Options List (EOL)\n")
                print("\t\tType: 0")
                outputFile.write("\t\tType: 0\n")
                off+=1
                nbrOctetsOptions -=1
            elif (int(premierOctetOption, 16) == 1):
                print("\t  IP Option  -  No Operation (NOP)")
                outputFile.write("\t  IP Option  -  No Operation (NOP)\n")
                print("\t\tType: 1")
                outputFile.write("\t\tType: 1\n")
                off+=1
                nbrOctetsOptions -=1
            elif (int(premierOctetOption, 16) == 7):
                print("\t  IP Option  -  Record Route (RR)")
                outputFile.write("\t  IP Option  -  Record Route (RR)\n")
                print("\t\tType: 7")
                outputFile.write("\t\tType: 7\n")
                length = int(trame[off+1], 16)
                print("\t\tLength: {}".format(length))
                outputFile.write("\t\tLength: {}\n".format(length))
                pointer = int(trame[off+2], 16)
                print("\t\tPointer: {}".format(pointer))
                outputFile.write("\t\tPointer: {}\n".format(pointer))
                for i in range((length-3)//4):
                    rr= '.'.join([str(int(x,16)) for x in trame[off+3+i*4:off+7+i*4]])
                    print("\t\tRecorded Route: {}".format(rr))
                    outputFile.write("\t\tRecorded Route: {}\n".format(rr))
                
                off+=length
                nbrOctetsOptions -= length
            elif (int(premierOctetOption, 16) == 131):
                print("\t  IP Option  -  Loose Source Route (LSR)")
                outputFile.write("\t  IP Option  -  Loose Source Route (LSR)\n")
                print("\t\tType: 131")
                outputFile.write("\t\tType: 131\n")
                length = int(trame[off+1], 16)
                print("\t\tLength: {}".format(length))
                outputFile.write("\t\tLength: {}\n".format(length))
                pointer = int(trame[off+2], 16)
                print("\t\tPointer: {}".format(pointer))
                outputFile.write("\t\tPointer: {}\n".format(pointer))
                for i in range((length-3)//4):
                    route= '.'.join([str(int(x,16)) for x in trame[off+3+i*4:off+7+i*4]])
                    print("\t\tRoute: {}".format(route)) 
                    outputFile.write("\t\tRoute: {}\n".format(route))
                off+=length
                nbrOctetsOptions -= length
            elif (int(premierOctetOption, 16) == 137):
                print("\t  IP Option  -  Strict Source Route (SSR)")
                outputFile.write("\t  IP Option  -  Strict Source Route (SSR)\n")
                print("\t\tType: 137")
                outputFile.write("\t\tType: 137\n")
                length = int(trame[off+1], 16)
                print("\t\tLength: {}".format(length))
                outputFile.write("\t\tLength: {}\n".format(length))
                pointer = int(trame[off+2], 16)
                print("\t\tPointer: {}".format(pointer))
                outputFile.write("\t\tPointer: {}\n".format(pointer))
                for i in range((length-3)//4):
                    route= '.'.join([str(int(x,16)) for x in trame[off+3+i*4:off+7+i*4]])
                    print("\t\tRoute: {}".format(route)) 
                    outputFile.write("\t\tRoute: {}\n".format(route)) 
                off+=length
                nbrOctetsOptions -= length
            elif (int(premierOctetOption, 16) == 148):
                print("\t  IP Option  -  Router Alert ")
                outputFile.write("\t  IP Option  -  Router Alert \n")
                print("\t\tType: 148")
                outputFile.write("\t\tType: 148\n")
                length = int(trame[off+1], 16)
                print("\t\tLength: {}".format(length))
                outputFile.write("\t\tLength: {}\n".format(length))
                routerAlert = int(trame[off+2]+trame[off+3], 16)
                print("\t\tRouter Alert: Router shall examine packet ({})".format(routerAlert))
                outputFile.write("\t\tRouter Alert: Router shall examine packet ({})\n".format(routerAlert))
                off+=length
                nbrOctetsOptions -= length
            else:
                print("\t  IP Option non supporté ")    # on suppose que toutes les options non supportées ont un champs longueur
                outputFile.write("\t  IP Option non supporté \n")
                length = int(trame[off+1], 16)
                off+=length
                nbrOctetsOptions -= length


    if (protocol == 6):
        
        TCP(trame,int(headerLength32)*4)
    elif protocol == 17 : 
        UDP(trame,int(headerLength32)*4)
    else:
        print("   "+Colors.BOLD+Colors.UNDERLINE+"Protocol numéro {} non supporté".format(protocol)+Colors.ENDC)
        outputFile.write("   Protocol numéro {} non supporté\n".format(protocol))

def UDP (trame, length_IPframe):
    """Fonction qui analyse le segment UDP, et affiche tous ses champs
    Argument : $1 : trame a analyser, $2 : longueur de l'entete IP, pour connaitre a partir de quel octet commence le segment UDP
    """
    offset = 14+length_IPframe #début du packet UDP par rapport au début de la trame
    source_port=trame[offset]+trame[offset+1]
    dest_port=trame[offset+2]+trame[offset+3]
    length = trame[offset+4]+trame[offset+5]
    checksum = trame[offset+6]+trame[offset+7]
    print("   "+Colors.BOLD+Colors.UNDERLINE+"User Datagram Protocol: (UDP)"+Colors.ENDC)

    print("\tSource Port: {}".format(int(source_port,16)))
    outputFile.write("\tSource Port: {}".format(int(source_port,16)))
    print("\tDestination Port : {}".format(int(dest_port,16)))
    outputFile.write("\tDestination Port : {}".format(int(dest_port,16)))
    print("\tLength: {}".format(int(length,16)))
    outputFile.write("\tLength: {}".format(int(length,16)))
    print("\tChecksum: 0x{} [unverified]".format(checksum))
    outputFile.write("\tChecksum: 0x{} [unverified]".format(checksum))

def TCP(trame,length_IPframe):
    """Fonction qui analyse le segment TCP, et affiche tous ses champs avec traitement des options
    Argument : $1 : trame a analyser, $2 : longueur de l'entete IP, pour connaitre a partir de quel octet commence le segment TCP
    """
    offset = 14+length_IPframe  #début du packet TCP par rapport au début de la trame

    source_port=trame[offset]+trame[offset+1]
    dest_port=trame[offset+2]+trame[offset+3]
    sequence_number=trame[offset+4]+trame[offset+5]+trame[offset+6]+trame[offset+7]
    ack_number=trame[offset+8]+trame[offset+9]+trame[offset+10]+trame[offset+11]

    thl= trame[offset+12][0]
    if int(thl,16)<5 :
        raise ValueError("Valeur minimum du header TCP est 20 octets.")
    
    #flags
    rsv=(int (trame[offset+12][1],16) & 14) >> 1
    nonce=int(trame[offset+12][1],16) & 1
    
    cwr=(int(trame[offset+13][0],16) & 8) >> 3
    ecn=(int(trame[offset+13][0],16) & 4) >> 2
    urg=(int(trame[offset+13][0],16) & 2) >> 1
    ack=(int(trame[offset+13][0],16) & 1) 
    push=(int(trame[offset+13][1],16) & 8) >> 3
    reset=(int(trame[offset+13][1],16) & 4) >> 2
    syn=(int(trame[offset+13][1],16) & 2) >> 1
    fin=(int(trame[offset+13][1],16) & 1) 
    
    window=trame[offset+14]+trame[offset+15]
    checksum=trame[offset+16]+trame[offset+17]
    urgent_pointer=trame[offset+18]+trame[offset+19]
    
    print("   "+Colors.BOLD+Colors.UNDERLINE+"Transmission Control Protocol:"+Colors.ENDC)
    outputFile.write("   Transmission Control Protocol:@=\n")
    print("\tSource Port: {}".format(int(source_port,16)))
    outputFile.write("\tSource Port: {}\n".format(int(source_port,16)))
    print("\tDestination Port : {}".format(int(dest_port,16)))
    outputFile.write("\tDestination Port : {}\n".format(int(dest_port,16)))
    print("\tSequence Number: {}".format(int(sequence_number,16)))
    outputFile.write("\tSequence Number: {}\n".format(int(sequence_number,16)))
    print("\tAcknowledgment Number: {} ".format(int(ack_number,16)))
    outputFile.write("\tAcknowledgment Number: {} \n".format(int(ack_number,16)))
    print("\t{} .... = Header Length: {} bytes ({})".format(format(int(thl, 16), '04b'),int(thl,16)*4, int(thl,16)))
    outputFile.write("\t{} .... = Header Length: {} bytes ({})\n".format(format(int(thl, 16), '04b'),int(thl,16)*4, int(thl,16)))
    print("\tFlags: 0x{} ".format(trame[offset+12][1]+trame[offset+13]))
    outputFile.write("\tFlags: 0x{} \n".format(trame[offset+12][1]+trame[offset+13]))
    print("\t\t000. .... .... = Reserved : {} ".format("not set" if not rsv else "set"))
    outputFile.write("\t\t000. .... .... = Reserved : {} \n".format("not set" if not rsv else "set"))
    print("\t\t...{} .... .... = Nonce: {} ".format(nonce, "not set" if not nonce else "set"))
    outputFile.write("\t\t...{} .... .... = Nonce: {} \n".format(nonce, "not set" if not nonce else "set"))
    print("\t\t.... {}... .... = Congestion Window Reduced (CWR): {} ".format(cwr, "not set" if not cwr else "set"))
    outputFile.write("\t\t.... {}... .... = Congestion Window Reduced (CWR): {} \n".format(cwr, "not set" if not cwr else "set"))
    print("\t\t.... .{}.. .... = ECN-Echo: {} ".format(ecn, "not set" if not ecn else "set"))
    outputFile.write("\t\t.... .{}.. .... = ECN-Echo: {} \n".format(ecn, "not set" if not ecn else "set"))
    print("\t\t.... ..{}. .... = Urgent: {} ".format(urg, "not set" if not urg else "set"))
    outputFile.write("\t\t.... ..{}. .... = Urgent: {} \n".format(urg, "not set" if not urg else "set"))
    print("\t\t.... ...{} .... = Acknowledgment: {} ".format(ack, "not set" if not ack else "set"))
    outputFile.write("\t\t.... ...{} .... = Acknowledgment: {} \n".format(ack, "not set" if not ack else "set"))
    print("\t\t.... .... {}... = Push: {} ".format(push, "not set" if not push else "set"))
    outputFile.write("\t\t.... .... {}... = Push: {} \n".format(push, "not set" if not push else "set"))
    print("\t\t.... .... .{}.. = Reset: {} ".format(reset, "not set" if not reset else "set"))
    outputFile.write("\t\t.... .... .{}.. = Reset: {} \n".format(reset, "not set" if not reset else "set"))
    print("\t\t.... .... ..{}. = Syn: {} ".format(syn, "not set" if not syn else "set"))
    outputFile.write("\t\t.... .... ..{}. = Syn: {} \n".format(syn, "not set" if not syn else "set"))
    print("\t\t.... .... ...{} = Fin: {} ".format(fin, "not set" if not fin else "set"))
    outputFile.write("\t\t.... .... ...{} = Fin: {} \n".format(fin, "not set" if not fin else "set"))
    print("\tWindow size value: {}".format(int(window, 16)))
    outputFile.write("\tWindow size value: {}\n".format(int(window, 16)))
    print("\tChecksum: 0x{} [unverified]".format(checksum))
    outputFile.write("\tChecksum: 0x{} [unverified]\n".format(checksum))
    print("\tUrgent pointer: {}".format(int(urgent_pointer,16)))
    outputFile.write("\tUrgent pointer: {}\n".format(int(urgent_pointer,16)))


    #----------------------------OPTIONS TCP----------------------------
    #HYPOTHESE : on suppose que toutes les options traitees, contiennent un champs longueur en 2eme position 
    #qui nous donne la longueur de cette option
    #SAUF : les options 0 et 1 qui sont sur 1 octet seulement
    if (int(thl,16) > 5):
        nbrOctetsOptions = (int(thl,16) - 5) * 4
        print("\tOptions: {} bytes".format(nbrOctetsOptions))
        outputFile.write("\tOptions: {} bytes\n".format(nbrOctetsOptions))
        off = offset+20

        while True : 
            if nbrOctetsOptions == 0 : 
                break
            premierOctetOption = trame[off]

            if (int(premierOctetOption, 16) == 0):
                print("\t  TCP Option  -  End of Options List (EOL)")
                print("\t\tKind: End of Options List (0)")
                outputFile.write("\t  TCP Option  -  End of Options List (EOL)\n")
                outputFile.write("\t\tKind: End of Options List (0)\n")
                off+=1
                nbrOctetsOptions -=1

            elif (int(premierOctetOption, 16) == 1):
                print("\t  TCP Option  -  No-Operation (NOP)")
                print("\t\tKind: No-Operation (1)")
                outputFile.write("\t  TCP Option  -  No-Operation (NOP)\n")
                outputFile.write("\t\tKind: No-Operation (1)\n")
                off+=1
                nbrOctetsOptions -=1

            elif (int(premierOctetOption, 16) == 2):
                print("\t  TCP Option  -  Maximum Segment Size")
                print("\t\tKind: Maximum Segment Size: (2)")
                outputFile.write("\t  TCP Option  -  Maximum Segment Size\n")
                outputFile.write("\t\tKind: Maximum Segment Size: (2)\n")
                length = int(trame[off+1], 16)
                print("\t\tLength: {}".format(length))
                outputFile.write("\t\tLength: {}\n".format(length))
                value=''.join([str(x) for x in trame[off+2:off+length]])
                print("\t\tMSS Value: {}".format(int(value,16)))
                outputFile.write("\t\tMSS Value: {}\n".format(int(value,16)))
                off+=length
                nbrOctetsOptions -= length
             
            elif (int(premierOctetOption, 16) == 3):
                print("\t  TCP Option  -  Windows Scale")
                print("\t\tKind: Windows Scale: (3)")
                outputFile.write("\t  TCP Option  -  Windows Scale\n")
                outputFile.write("\t\tKind: Windows Scale: (3)\n")
                length = int(trame[off+1], 16)
                print("\t\tLength: {}".format(length))
                outputFile.write("\t\tLength: {}\n".format(length))
                value=''.join([str(x) for x in trame[off+2:off+length]])
                print("\t\tShift Count: {}\n".format(int(value,16)))
                outputFile.write("\t\tShift Count: {}\n".format(int(value,16)))
                off+=length
                nbrOctetsOptions -= length

            elif (int(premierOctetOption, 16) == 4):
                print("\t  TCP Option  -  Sack Permitted")
                print("\t\tKind: Sack Permitted: (4)")
                outputFile.write("\t  TCP Option  -  Sack Permitted\n")
                outputFile.write("\t\tKind: Sack Permitted: (4)\n")
                length = int(trame[off+1], 16)
                print("\t\tLength: {}".format(length))
                outputFile.write("\t\tLength: {}\n".format(length))
                off+=length
                nbrOctetsOptions -= length
            
            elif (int(premierOctetOption, 16) == 5):
                print("\t  TCP Option  -  Selective ACK")
                print("\t\tKind: Selective ACK: (5)")
                outputFile.write("\t  TCP Option  -  Selective ACK\n")
                outputFile.write("\t\tKind: Selective ACK: (5)\n")
                length = int(trame[off+1], 16)
                print("\t\tLength: {}".format(length))
                outputFile.write("\t\tLength: {}\n".format(length))
                off+=length
                nbrOctetsOptions -= length

            elif (int(premierOctetOption, 16) == 8):
                
                print("\t  TCP Option  -  Timestamps")
                print("\t\tKind: Time Stamp Option (8)")
                outputFile.write("\t  TCP Option  -  Timestamps\n")
                outputFile.write("\t\tKind: Time Stamp Option (8)\n")
                length = int(trame[off+1], 16)
                print("\t\tLength: {}".format(length))
                outputFile.write("\t\tLength: {}\n".format(length))
                value = ''.join([str(x) for x in trame[off+2 : off+(length//2)+1]])
                print("\t\tTimestamp value: {}".format(int(value,16)))
                outputFile.write("\t\tTimestamp value: {}\n".format(int(value,16)))
                echo_reply =''.join([str(x) for x in trame[off+(length//2)+1:off+length]])
                print("\t\tTimestamp echo reply: {}".format(int(echo_reply,16)))
                outputFile.write("\t\tTimestamp echo reply: {}\n".format(int(echo_reply,16)))
                off+=length
                nbrOctetsOptions -= length

            
            # On suppose que #les options contiennent un champs length en deuxieme 
            # position qui nous renseigne sur leur longueur 
            else:
                print("\t  TCP Option non supporté ")
                outputFile.write("\t  TCP Option non supporté \n")
                length = int(trame[off+1], 16)
                off+=length
                nbrOctetsOptions -= length

    #Le port 80 est le port commun utilise par les serveurs web => Protocole HTTP
    if(int(source_port,16)==80 or int(dest_port,16)==80): 
        HTTP(trame,int(thl,16)*4+offset)


def HTTP(trame,length_TCPpacket):
    """Fonction qui analyse le segment TCP, et affiche tous ses champs avec traitement des options
    Argument : $1 :trame a analyser, $2 : longueur du segment TCP,afin de savoir a partir de quel octet 
    commence le message HTTP
    Renvoie : une chaine de caractere correspondant au message HTTP vehicule
    REMARQUE : si le message est invalide ie: ne correspond pas a des caracteres ASCII, on affiche 'HTTP Invalid"
            Cela se produit par exemple quand la reponse du serveur est trop longue et donc on doit envoyer les data
            dans une trame a part
    """
    print("   "+Colors.BOLD+Colors.UNDERLINE+"Hypertext Transfer Protocol:"+Colors.ENDC)
    outputFile.write("   Hypertext Transfer Protocol:\n")
    offset = length_TCPpacket
    ind=0
    trouv = False
    while ind < len(trame[offset:]) : 
        if trame[offset+ind] == "0d" and trame[offset+ind+1] ==  "0a": 
            if trame[ind+offset+2]== "0d" and trame[ind+offset+3] ==  "0a":
                ind +=4
                trouv = True
                break
        ind+=1
    if trouv :
        list_to_string= ''.join(trame[offset:offset+ind])
        list_to_string.strip()
        bytes_object = bytes.fromhex(list_to_string)
        try:
            ascii_string = bytes_object.decode("ASCII")
        except :
            ind = 0
        else:
            print('\t'+ascii_string.replace('\n','\n\t').strip())
            outputFile.write('\t'+ascii_string.replace('\n','\n\t').strip()+"\n")
    else:
        ind =0
    print(Colors.UNDERLINE+"\tDATA : {} bytes".format(len(trame[offset+ind:]))+Colors.ENDC)
    outputFile.write("\tDATA : {} bytes\n".format(len(trame[offset+ind:])))      
    
class Colors:
	OKGREEN = '\033[92m'
	UNDERLINE = '\033[4m'
	WARNING = '\033[93m'
	FAIL = '\033[91m'
	BOLD = '\033[1m'
	ENDC = '\033[0m'

outputFile = open("resultatAnalyseur.txt", "w")
def main():
    while True:
        fileName = input(Colors.BOLD+"Entrer le nom du fichier contenant la(les) trame(s) : "+Colors.ENDC)
        try:
            file = open(fileName)
        except:
            print("Ce fichier n'existe pas !! ")
        else:
            break
    outputFile.write("Trame(s) extraite(s) du fichier : "+fileName+"\n")
    dic = parse_file(file)
    couches(dic)
    outputFile.close()


if __name__ == "__main__":
    main()



 