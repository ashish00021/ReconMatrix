import requests
from datetime import datetime
import sys
import argparse
import nmap
import whois
import socket
from art import text2art
from termcolor import colored
# Define classes for different functionalities

def get_current_datetime():
    now = datetime.now()
    return now.strftime("%Y-%m-%d %H:%M:%S")

class SubdomainScanner:
    def __init__(self, domain, sub_domains):
        self.domain = domain
        self.sub_domains = sub_domains

    def scan(self):
        print(f"[+] Start Scanning for subdomains for {self.domain}")
        i = 0
        for sub in self.sub_domains:
            i += 1
            x = (i/len(self.sub_domains))*100
            url = f"https://{sub}.{self.domain}"
            try:
                r = requests.get(url, timeout=10)
                if r.status_code == 200:
                    print("{} ::: {}%".format(url,round(x)))
            except requests.ConnectionError:
                pass
        print("[+] Subdomain Scanning Finished .... {}%".format(round(x)))


class WhoisWeb:
    def __init__(self, domain):
        self.domain = domain

    def info(self):
        try:
            domain_info = whois.whois(self.domain)
            print("Domain Information:")
            print("===================")
            print(f"Domain Name: {domain_info.domain_name}")
            print(f"Registrar: {domain_info.registrar}")
            print(f"Creation Date: {domain_info.creation_date}")
            print(f"Expiration Date: {domain_info.expiration_date}")
            print(f"Updated Date: {domain_info.updated_date}")
            print(f"Registrant: {domain_info.registrant}")
            print(f"Registrar URL: {domain_info.registrar_url}")
            print(f"WHOIS Server: {domain_info.whois_server}")
            print(f"Name Servers: {domain_info.name_servers}")
            print(f"Status: {domain_info.status}")
        except Exception as e:
            print(f"Failed to retrieve WHOIS information: {e}")


class NmapScan:
    def __init__(self, Domain,ports):
        self.domain = Domain
        self.ports = ports

    def scan(self):
        nm = nmap.PortScanner()
        target = socket.gethostbyname(self.domain)
        nm.scan(target,self.ports,arguments='-sS')
        print(f"[+] Starting Nmap Scan on {target}")

    # Parse the scan results
        for host in nm.all_hosts():
            print(f'Host : {host} ({nm[host].hostname()})')
            print(f'State : {nm[host].state()}')
            for proto in nm[host].all_protocols():
                print('----------')
                print(f'Protocol : {proto}')

                lport = nm[host][proto].keys()
                for port in sorted(lport):
                    print(f'port : {port}\tstate : {nm[host][proto][port]["state"]}')
        print("[+] Nmap Scan Finished ....")
        

class DirScan:
    def __init__(self, domain, dir_wordlist):
        self.domain = domain
        self.wordlist = dir_wordlist

    def find_dir(self):
        i = 0
        for directory in self.wordlist:
            i += 1
            y = (i/len(self.wordlist))*100
            url = f"https://{self.domain}/{directory}"
            try:
                r = requests.get(url, timeout=10)
                if r.status_code == 200:
                    print(f"Found: {url} ::: {round(y)}%")
            except requests.RequestException:
                pass
        print("[+] Directory Scanning Finished ::: {}".format(round(y)))


# Argument parser setup
parser = argparse.ArgumentParser(description="This is a subdomain finder which returns the subdomains of a given domain.")
parser.add_argument("--domain", required=True, help="Target domain")
parser.add_argument("-w", "--whois", action="store_true", help="Use to find info about target")
parser.add_argument("-s", "--onlysub", action="store_true", help="Use if you only need subdomains")
parser.add_argument("-n", "--nmap", action="store_true", help="Use for Nmap scan")
parser.add_argument("-d", "--direc", action="store_true", help="For finding different directories")

args = parser.parse_args()

# Display ASCII art and welcome message
ascii_art = text2art("ReconMatrix")
colored_ascii_art = colored(ascii_art, 'green')
print(colored_ascii_art)
print("="*50)
welcome_message = colored("{+} Welcome on Version: 1.0  ...", 'green')
print(welcome_message)
print("="*50)
c_datetime = get_current_datetime()
current_date=colored(f"[+] Current Date and Time: {c_datetime}","green")
print(current_date)
# Display introduction message
intro_message = colored("[+] This script performs reconnaissance on a target domain, including subdomain enumeration, WHOIS lookup, directory scanning, and Nmap port scanning.","green")
print(intro_message)
# Display disclaimer
disclaimer = colored("[+] Disclaimer: This script should only be used for authorized testing or educational purposes. Unauthorized use may violate applicable laws.","green")
print(disclaimer)
print("="*50)
# Display usage instructions
usage_instructions = colored("Usage: python script_name.py --domain example.com [--whois] [--onlysub] [--nmap] [--direc]","green")
print(usage_instructions)
print("="*50)


Domain = args.domain
ports = "1-1000"

# Read subdomains and directory wordlists from files
with open("sub_list.txt", 'r') as f:
    sub_list = f.read().splitlines()

with open("dir_wordlist.txt", 'r') as f:
    dir_wordlist = f.read().splitlines()

# Function to perform nslookup and start Nmap scan if requested
def nslookup(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        if args.nmap:
            nmap_scan = NmapScan(ip_address)
            nmap_scan.scan()
            print(colored("[+] Starting Nmap Scan...", 'green'))
    except socket.gaierror as e:
        print(f"Failed to resolve domain: {e}")

# Initialize classes with the target domain and lists
subdomain_scanner = SubdomainScanner(Domain, sub_list)
whois_info = WhoisWeb(Domain)
dir_scanner = DirScan(Domain, dir_wordlist)
nmap_Scan = NmapScan(Domain,ports)

# Execute scans based on provided arguments
if args.whois or args.onlysub or args.direc or args.nmap :
    if args.whois:
        whois_info.info()
    if args.onlysub:
        subdomain_scanner.scan()
    if args.direc:
        dir_scanner.find_dir()
    if args.nmap:
        nmap_Scan.scan()
else:
    print("="*30)
    print("[+] WHOIS_INFO ...")
    print("#"*30)
    whois_info.info()
    print("="*30)
    print("[+] SUBDOMAIN SCANNING ...")
    print("#"*30)
    subdomain_scanner.scan()
    print("="*30)
    print("[+] DIRECTORY SCANNING ...")
    print("#"*30)
    dir_scanner.find_dir()
    print("="*30)
    print("[+] PORT SCANNING ..")
    print("#"*30)
    nmap_Scan.scan()

# Perform nslookup and Nmap scan if requested
# nslookup(Domain)
