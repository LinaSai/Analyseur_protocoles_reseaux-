# Analyseur de protocoles

Ce projet est un analyseur de protocoles réseau offline. Il a été codé en Python. Il permet d'analyser des trames capturées sur un réseau et renvoie les differents champs des entêtes qu'elles contiennent.

## Contenu de l'archive

Cette archive contient : 
1. Le fichier analyser.py, le code source du projet.
2. Le fichier howto qui explique comment lancer le programme. 
3. Des fichiers en .txt, qui contiennent soit les trames à analyser, ou la sortie de la fonction.

## Exécution
D'abord, télécharger l'archive de ce projet.
Ensuite, aller dans le répertoire où il a été téléchargé, et le décompresser.

Pour exécuter notre programme, il suffit de lancer le makefile.
Pour se faire, il faut ouvrir un termimal, et accèder au répertoire résultant du dezippage, puis lancer la commande make.
```bash
make
```

## Usage

Après avoir suivi les étapes de la partie "Exécution" , notre programme devrait vous afficher "Veuillez selectionner un fichier " , vous devez alors taper le nom d'un fichier existant ( vous pouvez donner le chemin absolu ou relatif ). Attention à bien écrire son nom, faute de sensibilité à la casse.

## Résultat
Le programme analyse donc la(les) trace(s) donnée(s) dans le fichier passé en argument et renvoie un autre fichier qui contient le résultat de d'analyse :
- Le nom du fichier passé en parametre. 
- Le nombre de trames correctes.
- Le nombre de trames erronées.
- Analyse des protocoles de chaque trame.

## Protocoles et Options supportés 
1. **Couche Liaison : Ethernet**
- Adresse MAC Destination format aa:bb:cc:dd:ee:ff
- Adresse MAC Source format aa:bb:cc:dd:ee:ff
- Affiche le type du protocol : IPV4 (0800), ARP(0806) ...

2. **Couche Internet :**
**ARP**
- Harware type, exemple Ethernet (1)
- Protocol type, exemple IPv4 (0x8000)
- Hardware size, pour ethernet : 6
- Protocol size, pour IPv4 : 4
- Opcode 
- Sender Harware address
- Sender Protocol address
- Receiver Harware address
- Receiver Protocol address

**IPv4**
Notre programme traite l'IPv4 mais pas l'IPv6. Il affiche tout les champs de l'IPv4 :
- Version, 4 dans notre programme
- Header Length : longueur de l'entete ( valeur entre 20 et 60)
- Les flags :reserved bit, don't fragment, more fragments..
- Total length : longueur totale du datagramme IP
- Time to Live
- Protocl, TCP ou UDP encapsulé dans le datagramme
- Header Checksum
- Source IP address, format 0.0.0.0
- Destination address , format 0.0.0.0

    **Options IPv4**
L'entete du datagramme IP contient des options ssi sa longueur > 20 octets (en decimal), les options traitées sont les options les plus communes et mentionnées dans le cours :
* End of Options List
* No Operation 
* Record Route
* Loose Source Route
* Strict Source Route
* Router Alert
 
En faisant l'hypothese que toutes les autres options ont un champs longueur en deuxième position ( après le numèro du type ), si cette option n'appartient pas à cette liste, nous passons à la suivante en affichant " Option non supportée ".

3. **Couche Transport :**
**UDP**
Si le numéro du protocol encapsulé dans le datagramme IP est égal à 17( valeur decimale), alors il contient un packet UDP.
- On affiche le port source
- Port destination
- Longueur du packet
- Valeur du checksum

**TCP**
Si le numéro du protocol encapsulé dans le datagramme IP est égal à 6( valeur decimale), alors il contient un packet TCP.

- Port source
- Port destination 
    Hypothèse : si l'un d'eux égale 80, encapsule un message HTTP.

- Sequence Number
- Acknowledgment number 
- HeaderLength
- Flags (reserved,Nonce,CWR,ECN,URG,ACK,Push,Reset,SYN,FIN)
- Windows size value
- Checksum 
- Urgent Pointer

    **Options TCP**
L'entete du packet TCP contient des options ssi sa longueur > 20 octets (en decimal), les options traitées sont les options les plus communes et mentionnées dans le cours :
* End of Options List
* No Operation 
* Maximum Segment Length
* Windows Scale
* SACK Permitted
* Selective ACK
* Timestamps
 
En faisant l'hypothese que toutes les autres options ont un champs longueur en deuxième position ( après le numèro du type ), si cette option n'appartient pas à cette liste, nous passons à la suivante en affichant " Option non supportée ".

4. **Couche Application : HTTP**
Ce message est encapsulé dans un packet TCP, le port le plus souvent utilisé par les serveurs Web est le numéro 80.
- On affiche le nombre d'octets qu'il contient.
- Son contenu.

## Auteures
Binôme constitué de : 
- Yacine BRIHMOUCHE.
- Lina SAICHI.