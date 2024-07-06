#!/usr/bin/env python3

from termcolor import colored
from scapy.all import sniff, TCP, UDP, IP, SCTP, Raw
import signal
import sys
import re
import logging
import subprocess
import time
import threading

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
ssh_login_attempts = {}
ssh_login_attempts_local = {}
http_login_attempts = {}

ssh_failed_pattern = re.compile(r'Failed password for|authentication failure|Invalid user')
http_failed_pattern = re.compile(r'401 Unauthorized')

# this function apply procedures to the packet who sniff scapy

def process_packet(packet):

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

        if src_ip not in connection_attempts:
            connection_attempts[src_ip] = []
        connection_attempts[src_ip].append(dst_port)

        if len(set(connection_attempts[src_ip])) > 10:
            attempts = len(set(connection_attempts[src_ip]))
            print(colored(f"Warning, possible scan of ports from, {src_ip}, amounts of attempts to connection: {attempts}", "red"))


    # brute force - SSH login in red, in a few puntuals cases the traffic of the port 22 cant be detected,
    # this could be due to the firewall configuration, brute force tool configuration, iptables, etc
    # therefore, to understand how the SIEM works we also see a way to detect this on the local machine.
    # to this step i recommend setting the ssh_failed_pattern

    elif packet.haslayer(TCP) and packet[TCP].dport == 22 and packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors='ignore')
        if ssh_failed_pattern.search(payload):
            if src_ip not in ssh_login_attempts:
                ssh_login_attempts[src_ip] = []
            ssh_login_attempts[src_ip].append("try")

            if len(ssh_login_attempts[src_ip]) > 5:
                attempts = len(ssh_login_attempts[src_ip])
                print(colored(f"Warning possible brute force attack from {src_ip} to port 22, amount of failed attempts: {attempts}", "red"))

    # brute force - HTTP login 

    elif packet.haslayer(TCP) and packet[TCP].dport == 80 and packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors='ignore')
        if http_failed_pattern.search(payload):
            if src_ip not in http_login_attempts:
                http_login_attempts[src_ip] = []
            http_login_attempts[src_ip].append("try")

            if len(http_login_attempts[src_ip]) > 5:
                attempts = len(http_login_attempts[src_ip])
                print(colored(f"Warning possible brute force attack from {src_ip} to port 80, amount of failed attempts: {attempts}", "red"))

# brute force - SSH login in local
def check_failed_logins():
    global prev_output
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
                        print(colored(f"Warning, failed SSH login attempts from IP: {ip_str} to localhost, amount of failed attempts: {ssh_login_attempts_local[ip_str]}", "red"))
                        print(f"{i}")
            time.sleep(3)
        except subprocess.CalledProcessError as e:
            print(f"{e}")


def main():
    banner()
    iface = input("Enter the interface to monitor: ")
    print(colored(f"\nInitializing monitoring of interface: {iface}", "cyan"))

    login_thread = threading.Thread(target=check_failed_logins)
    login_thread.start()

    sniff_thread = threading.Thread(target=sniff, kwargs={"iface": iface, "prn": process_packet, "store": False})
    sniff_thread.start()

    login_thread.join()
    sniff_thread.join()

if __name__ == '__main__':
    main()
