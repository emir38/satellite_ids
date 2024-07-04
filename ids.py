#!/usr/bin/env python3

from termcolor import colored
from scapy.all import sniff, TCP, IP
import signal
import sys

def def_handler(sig, frame):
    print(colored("\n\nExiting the program...", "yellow"))
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

def banner():
    print(colored("\t\t\t\t\t\t\t    +[+[+[ Intrusion Detection System ]+]+]+", "magenta"))
    print(colored("\t\t\t\t\t\t\t\t +[+[+[ Made with python ]+]+]+", "magenta"))
    print(colored("""
                 ______
              ,\'\"       \"-._
            ,\'              \"-._ _._
            ;              __,-\'/   |
           ;|           ,-' _,\'\"\'._,.
           |:            _,\'      |\ `.
           : \       _,-\'         | \  `.
            \ \   ,-'             |  \   \                .dBBBBP dBBBBBb  dBBBBBBP dBBBP  dBP    dBP    dBP dBBBBBBP dBBBP   
             \ \'.         .-.     |       \               BP           BB                                                      
              \  \         \"      |        :              `BBBBb   dBP BB   dBP   dBBP   dBP    dBP    dBP    dBP   dBBP      
               `. `.              |        |                 dBP  dBP  BB  dBP   dBP    dBP    dBP    dBP    dBP   dBP        
                 `. \"-._          |        ;            dBBBBP'  dBBBBBBB dBP   dBBBBP dBBBBP dBBBBP dBP    dBP   dBBBBP      
                 / |`._ `-._      L       /                                  
                /  | \ `._   "-.___    _,\'                              dBP dBBBBb.dBBBBP                               
               /   |  \_.-\"-.___   \"\"\"\"                                        dB'BP                                     
               \   :            /\"\"\"                                  dBP dBP dB' `BBBBb                               
                `._\_       __.\'_                                    dBP dBP dB"     dBP'                                  
           __,--\'\'_ \' \"--\'\'\'\' \_  `-._                              dBP dBBBBB" dBBBBP''                                  
     __,--'     .\' /_  |   __. `-._   `-._
    <            `.  `-.-\'\'  __,-\'     _,-\'
     `.            `.   _,-\'\"      _,-\'                                                       _  _ 
       `.            \'\'\"       _,-\'                                         /_     _  _ _  ._ _//_/
         `.                _,-\'                                            /_//_/ /_'/ / ///._//_/ 
           `.          _,-\'                                                   _/                   
             `.   __,\'\"
               `'\n\n""", "blue"))

connection_attempts = {}

def process_packet(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        if src_ip not in connection_attempts:
            connection_attempts[src_ip] = []
        connection_attempts[src_ip].append(dst_port)
        
        # Umbral para detección de escaneo de puertos
        if len(set(connection_attempts[src_ip])) > 10:
            attempts = len(set(connection_attempts[src_ip]))
            print(colored(f"Warning, possible scan of ports from, {src_ip}, amounts of attempts to connection: {attempts}", "red"))



def main():
    banner()
    iface = input("Enter the interface to monitor: ")
    print(colored(f"\nInitializing monitoring of interface: {iface}", "cyan"))
    sniff(iface=iface, prn=process_packet, store=False)


if __name__ == '__main__':
    main()
