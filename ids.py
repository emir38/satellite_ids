#!/usr/bin/env python3
#-------------------------
# Satellite IDS 
# Author: emir38
# Year: 2024
# Version: in the works!
#-------------------------

#--------------------------------------------------------------------------------------------------------------------------------
# Satellite is currently a monitor to detect man-in-the-middle attacks, DoS, brute force (SSH - HTTP), possible Command and Control, and also
# network port scans. This tool is used mainly for educational purposes in the practitioner's local network, in order to obtain knowledge of how
# these attacks work behind the scenes and learn how to filter for them.
#--------------------------------------------------------------------------------------------------------------------------------

#--------------------------------------------------------------------------------------------------------------------------------
#                    GNU GENERAL PUBLIC LICENSE
#                      Version 3, 29 June 2007

# Copyright (C) 2007 Free Software Foundation, Inc. <http://fsf.org/>
# Everyone is permitted to copy and distribute verbatim copies
# of this license document, but changing it is not allowed.
#--------------------------------------------------------------------------------------------------------------------------------

from termcolor import colored
from scapy.all import *
import signal
import sys
import os
import re
import subprocess
import time
import threading


def def_handler(sig, frame):
    print(colored("\n\nExiting the program...", "yellow"))
    os._exit(1)

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
ssh_login_attempts = {}
ssh_login_attempts_local = {}
http_login_attempts = {}
packet_counts = defaultdict(lambda: [0, 0])

last_cleanup = 0
THRESHOLD_PACKETS = 300
TIME_WINDOW = 60

ssh_failed_pattern = re.compile(r'Failed password for|authentication failure|Invalid user|authentication failed')
http_failed_pattern = re.compile(r'401 Unauthorized')

#configure known_c2_domains to your neededs
known_c2_domains = [
    "www.youtube.com",
    "malicious-domain.com",
    "another-malicious-domain.org"
]

#confifure known_c2_ips to your neededs
known_c2_ips = [
    "192.168.1.100",
    "192.168.100.1"
]

#Its recommended configure a whitelist to ignore traffic from secure IPs on your network
whitelist = [
    "10.0.0.0",
    "11.0.0.0"
]

def is_whitelisted(ip):
    return ip in whitelist

def enable_promiscuous_mode(interface):

    #enable promiscuous mode
    try:
        subprocess.run(["ip", "link", "set", interface, "promisc", "on"])
        print(f"Promiscuous mode enable")
    except Exception as e:
        print("e")

def load_arp_table_from_file(file_path):
    arp_table = {}

    with open(file_path, 'r') as f:
        for line in f:
            ip, mac = line.strip().split(',')
            arp_table[ip] = mac
    return arp_table

def port_scan(packet):

    #port scan detection
    if packet.haslayer(IP):
        if packet.haslayer(TCP):
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            src_ip=packet[IP].src
            dst_port = packet[UDP].dport
        elif packet.haslayer(SCTP):
            src_ip = packet[IP].src
            dst_port = packet[SCTP].dport
        else:
            return

        try:
            if is_whitelisted(packet[IP].src):
                return
        except Exception as e:
            print(f"{e}")

        if src_ip not in connection_attempts:
            connection_attempts[src_ip] = []
        connection_attempts[src_ip].append(dst_port)

        if len(set(connection_attempts[src_ip])) > 10:
            attempts = len(set(connection_attempts[src_ip]))
            print(colored(f"[!] Warning, possible scan of ports from, {src_ip}, amounts of attempts to connection: {attempts}", "red"))

def brute_force(packet):

    # brute force - SSH login in red, in a few puntuals cases the traffic of the port 22 cant be detected,
    # this could be due to the firewall configuration, brute force tool configuration, iptables, etc
    # therefore, to understand how the SIEM works we also see a way to detect this on the local machine.
    # to this step i recommend setting the ssh_failed_pattern
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        if packet.haslayer(TCP) and packet[TCP].dport == 22 and packet.haslayer(Raw):
            payload = packet[Raw].load.decode(errors='ignore')
            if ssh_failed_pattern.search(payload) or packet[TCP].flags == 'R':
                if src_ip not in ssh_login_attempts:
                    ssh_login_attempts[src_ip] = []
                ssh_login_attempts[src_ip].append("try")

                if len(ssh_login_attempts[src_ip]) > 5:
                    attempts = len(ssh_login_attempts[src_ip])
                    print(colored(f"[!] Warning possible brute force attack from {src_ip} to port 22, amount of failed attempts: {attempts}", "blue"))

    # brute force - HTTP login 
    if packet.haslayer(TCP) and packet[TCP].dport == 80 and packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors='ignore')
        if http_failed_pattern.search(payload):
            if src_ip not in http_login_attempts:
                http_login_attempts[src_ip] = []
            http_login_attempts[src_ip].append("try")

            if len(http_login_attempts[src_ip]) > 5:
                attempts = len(http_login_attempts[src_ip])
                print(colored(f"[!] Warning possible brute force attack from {src_ip} to port 80, amount of failed attempts: {attempts}", "blue"))

def detect_DoS(packet):

    # detect DoS attacks
    global last_cleanup
    current_time = time.time()  

    if packet.haslayer(IP):
        ip_src = packet[IP].src
        packet_counts[ip_src][0] += 1
        packet_counts[ip_src][1] = current_time

        try:
            if is_whitelisted(packet[IP].src):
                return
        except Exception as e:
            print(f"{e}")

        if current_time - last_cleanup > 1:
            last_cleanup = current_time
            for ip in list(packet_counts.keys()):
                if current_time - packet_counts[ip][1] > TIME_WINDOW:
                    del packet_counts[ip]

        # Its recommended to adjust the THRESHOLD_PACKETS to the needs of each network 
        if packet_counts[ip_src][0] > THRESHOLD_PACKETS:
            print(colored(f"[!] Warning possible DoS Attack from IP: {ip_src}", "yellow"))
            packet_counts[ip_src] = [0, current_time]

def detect_c2(packet):

    # detect possible C2 attack
    # for good performance you should need configure known_c2_ips and known_c2_domains with known ips and domains as potential C2
    # you can also use API services that contain dangerous IP records and domains, for example: VirusTotal
    if packet.haslayer(IP):
       ip_dst = packet[IP].dst
       if ip_dst in known_c2_ips:
           print(colored(f"[!] Warning suspect traffic [C2] to ip: {ip_dst}", "cyan"))

    if packet.haslayer(DNS):
        if packet.haslayer(DNSQR):
            for i in range(packet[DNS].qdcount):
                dns_qr = packet[DNSQR].qd[i]
                domain_name = dns_qr.qname.decode('utf-8').rstrip('.')
                if domain_name in known_c2_domains:
                    print(colored(f"[!] Warning suspect traffic [C2] to domain: {domain_name}", "cyan"))

def detect_arp_spoof(packet, arp_table):

    # detect ARP Spoofing, to detect this you must need a file (arp_table.txt) with the directions IP and MAC Address of all the endpoints in the network
    # Example format file:
    # 190.0.0.0,00:00:00:00:00:00
    # 190.0.0.1,11:11:11:11:11:11
    # 190.0.0.2,22:22:22:22:22:22
    if ARP in packet and packet[ARP].op == 2:
        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc

        if ip in arp_table:
            if arp_table[ip] != mac:
                print(colored(f"[!] Warning possible ARP spoofing attack detected to IP: {ip}, actually MAC: {mac}, registered MAC: {arp_table[ip]}", "magenta"))

def sniff_arp_packets(arp_table):

    sniff(filter="arp", prn=lambda packet: detect_arp_spoof(packet, arp_table), store=0)

def check_failed_logins():

    # brute force - SSH login in local
    cmd = "journalctl _COMM=sshd | grep \"authentication failure\""
    ip_regex = re.compile(r'rhost=([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})')

    result = subprocess.run(cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    while True:
        try: 
            new_result = subprocess.run(cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
 
            if result.stdout != new_result.stdout:
                splited_stdout = new_result.stdout.split("\n")

                for i in splited_stdout:
                    ip = re.search(ip_regex, i)

                    if ip:
                        ip_str = ip.group()
                        if ip_str not in ssh_login_attempts_local:
                            ssh_login_attempts_local[ip_str] = 0
                        else:
                            ssh_login_attempts_local[ip_str] += 1

                    if ssh_login_attempts_local[ip_str] > 5:
                        print(colored(f"[!] Warning, failed SSH login attempts for IP: {ip_str} to localhost, amount of failed attempts: {ssh_login_attempts_local[ip_str]}", "blue"))
                        print(f"{i}")
            result = new_result
            time.sleep(3)
        except subprocess.CalledProcessError as e:
            print(f"{e}")

def process_packets(iface, arp_table):

    login_thread = threading.Thread(target=check_failed_logins)
    login_thread.start()

    DoS_thread = threading.Thread(target=sniff, kwargs={"iface": iface, "prn": detect_DoS, "store": False})
    DoS_thread.start()

    bForce_thread = threading.Thread(target=sniff, kwargs={"iface": iface, "prn": brute_force, "store": False})
    bForce_thread.start()

    port_thread = threading.Thread(target=sniff, kwargs={"iface": iface, "prn": port_scan, "store": False})
    port_thread.start()

    c2_thread = threading.Thread(target=sniff, kwargs={"iface": iface, "prn": detect_c2, "store": False, "filter":"udp port 53"})
    c2_thread.start()

    spoof_thread = threading.Thread(target=sniff_arp_packets, args=(arp_table,))
    spoof_thread.start()

    spoof_thread.join()
    login_thread.join()
    DoS_thread.join()
    bForce_thread.join()
    port_thread.join()
    c2_thread.join()

def main():
    banner()
    iface = input("Enter the interface to monitor: ")
    print(colored(f"\nInitializing monitoring of interface: {iface}", "cyan"))
    enable_promiscuous_mode(iface)
    arp_table = load_arp_table_from_file("arp_table.txt")
    process_packets(iface, arp_table)


if __name__ == '__main__':
    main()
