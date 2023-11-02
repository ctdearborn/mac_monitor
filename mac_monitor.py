#!/usr/bin/python3
#!/usr/bin/python3
# ARP monitor - Logs ARP changes
# Logs to arpchange.log
# Requires python_arptable

from python_arptable import ARPTABLE
from datetime import datetime
#import operator
from scapy.all import *
import subprocess as sp
import json
import os
import sys
import re


smokeping_targets = "/etc/smokeping/config.d/Targets" # smokeping Targets file
target_template = "target_template" # target template filename
maclistfilename = "maclist.txt" # filename with mac addresses to monitor
logfilename = "arpchange.log" # log of ip arp changes.
associationsfilename = "associations.json" #filename to store active IP associations with each MAC address
path = os.path.dirname(os.path.realpath(sys.argv[0]))
logfile = os.path.join(path, logfilename)
mac_list_file = os.path.join(path, maclistfilename)
associations_file = os.path.join(path, associationsfilename)
target_template_file = os.path.join(path, target_template)

DidChange = 0
dev = 0

# use dev options if we're in the "dev" directory
if re.search(r'dev', path):
    dev = 1

if os.geteuid() !=0:
    print("You need to run this script as the root user")
    exit()


# Read in target_template_file and write out target_{mac} with IP and MAC, returns the filename
def create_target_file(mac, ip):
    # remove ":" for filename and for category line of target_{mac}
    mac_name = mac.replace(":","")
    # check if the file exists, and delete it if it does
    filename = f"target_{mac_name}"
    filename = os.path.join(path, filename)
    print("filename =", filename)
    out_data = ""
    if os.path.exists(filename):
        os.remove(filename)
    #read in the file and swap in MAC and IP
    with open(target_template_file, "r") as file:
        for line in file:
            lineout = line.replace('[MAC]', mac_name)
            lineout = lineout.replace('[IP]', ip)
            out_data += lineout
    with open(filename, "w") as file:
        file.write(out_data)
    return(filename)

# read in Targets_template file, remove any include with mac address and add new include
def add_mac_to_Targets(mac, filename):
    out_data = ""
    mac = mac.replace(":","")
    targets_temp_file = os.path.join(path, "Targets_template")
    print("targets_temp_file =", targets_temp_file)
    with open(targets_temp_file, "r") as file:
        for line in file:
            if mac not in line:
                out_data += line
    out_data += f"@include {filename}\n"
    with open(targets_temp_file, "w") as file:
        file.write(out_data)

# Read MAC addresses from the file
def read_mac_addresses(file_path):
    print("file_path = ",file_path)
    mac_addresses = set()
    try:
        with open(file_path, "r") as file:
            for line in file:
                mac = line.strip()
                if is_valid_mac_address(mac):
                    mac_addresses.add(mac)
                else:
                    print(f"Invalid MAC address: {mac}")
    except FileNotFoundError:
        print(f"File not found: {file_path}")
    return mac_addresses

# MAC address validation function
def is_valid_mac_address(mac):
    parts = mac.split(":")
    if len(parts) != 6:
        return False
    for part in parts:
        if len(part) != 2 or not part.isalnum():
            return False
    return True

# Function to send ICMPv6 Echo Request and check for response
def is_ipv6_reachable(ipv6_address):
    print("pinging ipv6 address ",ipv6_address)
    # Define the payload (replace 'Hello' with your desired content)
    payload = b'1234568901234'  # Make sure it's in bytes format

    response = sr1(IPv6(dst=ipv6_address)/ICMPv6EchoRequest()/payload, timeout=1, verbose=False)
    return response is not None

# Function to send ICMP Echo Request and check for response
def is_ipv4_reachable(ipv4_address):
    print("pinging ipv4 address ",ipv4_address)
    # Define the payload
    payload = b'abcdefghijklmnopqrstuvwxyz'  # Make sure it's in bytes format

    response = sr1(IP(dst=ipv4_address)/ICMP()/payload, timeout=1, verbose=False)

    return response is not None


# Read associations from the JSON file
def read_associations(file_path):
    try:
        with open(file_path, "r") as file:
            associations = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        associations = {}
    return associations


# Check if arpchange.log exists. Create it if it doesn't.
if not os.path.isfile(logfile):
    with open(logfile, "w"):
        pass

# Initialize the set of valid MAC addresses
valid_mac_addresses = read_mac_addresses(mac_list_file)

# Initialize the dictionary of known associations (MAC to IPv6)
known_associations = read_associations(associations_file)

# Flush the ARP cache and run a network scan to get all ARPs
os.system('/usr/sbin/ip neigh flush all')
stream = sp.Popen('/usr/bin/nmap -sn 10.0.0.0/24 --max-parallelism 100 --min-hostgroup 100 --disable-arp-ping', shell=True,
                  stdout=sp.PIPE, stderr=sp.PIPE)
res = stream.communicate()

# Open logfile for reading, and read its contents into loglist
with open(logfile) as f:
    loglist = f.readlines()

log_len = len(loglist)

# Convert ARPTABLE to a dictionary for easy access
arp_dict = {entry['IP address']: entry['HW address'] for entry in ARPTABLE if entry['Flags'] == '0x2'}

now = datetime.now()
date_time = now.strftime("%Y-%m-%d_%H:%M:%S")

# Open the logfile for appending
f = open(logfile, "a")

# Iterate through the ARP entries, only deal with the ones we care about.
for ip, mac in arp_dict.items():
    num_entries = list(arp_dict.values()).count(mac)
    if num_entries == 1:
        # is this mac in the maclist?
        if mac in valid_mac_addresses:
            # check if the IP address is already in the association list
            if ip not in known_associations.get(mac, []):
                # check to verify that the IP is reachable via ICMP
                # if it's not reachable, then we don't want to change smokeping yet
                # but do we want to change logging? maybe not, maybe a false hit.
                if is_ipv4_reachable(ip):
                    # Add the IP address as the known IPv4 association for the MAC address
                    known_associations.setdefault(mac, ip)

                    # Update the known associations in the JSON file
                    with open(associations_file, "w") as file:
                        json.dump(known_associations, file, indent=4)

                    # update the log
                    # Search for all lines in loglist that contain the current MAC
                    matches = [line for line in loglist if mac in line]

                    num_matches = len(matches)

                    if num_matches:
                        # Sort the matches list
                        matches.sort()

                        # Split the last list element into its own list
                        values = matches[-1].split()

                        # If the IP from the matches list is not equal to the current IP, log it
                        if values[1] != ip:
                            DidChange = 1
                            f.write(f"{date_time} {ip} {mac} | {values[0]} {values[1]} {values[2]}\n")
                            print(f"{date_time} {ip} {mac} | {values[0]} {values[1]} {values[2]}")

                    # If there were no matches on this MAC, log it
                    if not num_matches:
                        f.write(f"{date_time} {ip} {mac}\n")
                        DidChange=1
                        # Update smokeping targets file
#                    if not dev:
                    if not dev:
                        # create new target file, remove any existing files with this mac from the 
                        # Targets_template and add target file to Targets_template
                        new_target = create_target_file(mac, ip)
                        add_mac_to_Targets(mac, new_target)



if DidChange and not dev:
    # verify {path}/Targets_template is included in smokeping_targets file
    included = 0
    Targets_template_file = os.path.join(path, "Targets_template")
    with open(smokeping_targets, "r") as file:
        for line in file:
            if Targets_template_file in line:
                included = 1
    if not included:
      with open(smokeping_targets, "a") as file:
          file.write(f"\n@include {Targets_template_file}\n")


    # Restart smokeping
    command = "/usr/bin/systemctl restart smokeping"
    stream = os.popen(command)
    output = stream.read()
