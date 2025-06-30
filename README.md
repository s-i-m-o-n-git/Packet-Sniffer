# Packet Sniffer en C

Ce projet est un **sniffer réseau** écrit en C utilisant la bibliothèque [libpcap](https://www.tcpdump.org/), permettant de capturer, analyser et enregistrer les paquets réseau en temps réel.

## ✨ Fonctionnalités

* Liste les interfaces réseau disponibles
* Capture les paquets sur une interface sélectionnée
* Analyse les paquets Ethernet, IP, TCP, UDP
* Détecte et affiche les requêtes HTTP et DNS
* Sauvegarde :

  * les données brutes au format `.pcap` (`packets.pcap`)
  * une version lisible dans un fichier texte (`packets.list`)
* Interruption propre avec `Ctrl+C`

## 📦 Fichiers générés

* `packets.list` : journal lisible avec les infos des paquets (hex, ASCII, protocoles, etc.)
* `packets.pcap` : capture brute compatible avec Wireshark

## 🛠️ Compilation

Ce programme nécessite `libpcap`. Pour l’installer :

### Debian/Ubuntu :

```bash
sudo apt update
sudo apt install libpcap-dev
```

### Compilation :

```bash
gcc sniffer.c -o sniffer -lpcap
```

## ▶️ Utilisation

```bash
sudo ./sniffer
```

⚠️ L’exécution en tant que **root** est souvent requise pour accéder aux interfaces réseau.

Tu devras ensuite choisir une interface réseau à surveiller parmi celles listées.

## 🧪 Exemple de sortie

```
=== Packet 1 ===
Time: 2025-06-30 14:22:10.123456
Length: 74 bytes
IP src: 192.168.1.100 -> dst: 93.184.216.34
Protocol: 6
TCP src port: 49152 -> dst port: 80
HTTP Data:
GET / HTTP/1.1
Host: example.com
...
Data (hex):
48 54 54 50 ...
ASCII: HTTP...
```

## 🧹 Arrêt

Le programme peut être interrompu proprement avec `Ctrl+C`. La capture s'arrête et les fichiers sont correctement fermés.

## 📄 Licence

Ce projet est open-source, sous licence MIT. N'hésite pas à le modifier et à l'améliorer !
