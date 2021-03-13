#!/usr/bin/python3

import argparse
import base64
from scapy.all import *

# Global Variables
scans = ("null","fin","xmas","pass","nikto","smb")
detected = list()
PACKET_COUNT = 0
THREAT_COUNT = 0
NULL_COUNT = 0
NULL_PORTS = list()
FIN_COUNT = 0
FIN_PORTS = list()
XMAS_COUNT = 0
XMAS_PORTS = list()
PASS_COUNT = 0
PASS_PAIRS = list()
NIKTO_COUNT = 0
NIKTO_PORTS = list()
SMB_COUNT = 0
USER_STRINGS = list()

def packetcallback(packet):
    # Vars for keeping counts between callbacks
    global PACKET_COUNT
    global THREAT_COUNT
    global NULL_COUNT
    global NULL_PORTS
    global FIN_COUNT
    global FIN_PORTS
    global XMAS_COUNT
    global XMAS_PORTS
    global PASS_COUNT
    global PASS_PAIRS
    global NIKTO_COUNT
    global NIKTO_PORTS
    global SMB_COUNT

    # Vars for parsing plaintext passwords from packets
    global USER_STRINGS
    pass_string = str()
    pair = str()

    # Increment to keep running total of packets scanned
    PACKET_COUNT += 1
    try:
        # For each type of supported scan, perform a check
        for scan in scans:
            # Null scan check
            if scan == "null":
                if packet[TCP].flags == "":
                    NULL_COUNT += 1
                    NULL_PORTS.append(packet[TCP].dport)
                    # Alert only once unless verbose x3
                    if "null" not in detected:
                        # Add to list of detected threat types
                        detected.append("null")
                        THREAT_COUNT += 1
                        alert(THREAT_COUNT,"Null scan",packet[IP].src,
                                str(packet[TCP].sport),packet[TCP].load)
                    elif args.v > 2:
                        THREAT_COUNT += 1
                        alert(THREAT_COUNT,"Null scan",packet[IP].src,
                                str(packet[TCP].sport),packet[TCP].load)
            # FIN scan check
            elif scan == "fin":
                if packet[TCP].flags == "F":
                    FIN_COUNT += 1
                    FIN_PORTS.append(packet[TCP].dport)
                    if "fin" not in detected:
                        detected.append("fin")
                        THREAT_COUNT += 1
                        alert(THREAT_COUNT,"FIN scan",packet[IP].src,
                                str(packet[TCP].sport),packet[TCP].load)
                    elif args.v > 2:
                        THREAT_COUNT += 1
                        alert(THREAT_COUNT,"FIN scan",packet[IP].src,
                                str(packet[TCP].sport),packet[TCP].load)
            # Xmas scan check
            elif scan == "xmas":
                if packet[TCP].flags == "FPU":
                    XMAS_COUNT += 1
                    XMAS_PORTS.append(packet[TCP].dport)
                    if "xmas" not in detected:
                        detected.append("xmas")
                        THREAT_COUNT += 1
                        alert(THREAT_COUNT,"Xmas scan",packet[IP].src,
                                str(packet[TCP].sport),packet[TCP].load)
                    elif args.v > 2:
                        THREAT_COUNT += 1
                        alert(THREAT_COUNT,"Xmas scan",packet[IP].src,
                                str(packet[TCP].sport),packet[TCP].load)
            # Parse out common plaintext password types
            elif scan == "pass":
                # HTTP Authorization Basic
                if packet[TCP].dport == 80:
                    if "Authorization: Basic " in str(packet):
                        pass_string = (str(packet)[(str(packet).find("Authorization: Basic ")
                                        + len("Authorization: Basic ")):-9])
                        pass_string = base64.b64decode(pass_string).decode('utf-8')
                        pair = ("username:"+pass_string[0:pass_string.find(":")] +
                                ", password:"+pass_string[pass_string.find(":")+1:])
                        if not pair in PASS_PAIRS:
                            PASS_PAIRS.append(pair)
                            THREAT_COUNT += 1
                            PASS_COUNT += 1
                            alert(THREAT_COUNT,"Usernames and passwords sent in the clear",
                                    packet[IP].src,"HTTP",pair)
                        if "pass" not in detected:
                            detected.append("pass")
                # IMAP
                elif packet[TCP].dport == 143:
                    if "LOGIN " in str(packet):
                        pass_string = str(packet)[str(packet).find("LOGIN ")+len("LOGIN "):-6]
                        pair = ("username:"+pass_string[0:pass_string.find(" \"")] +
                                ", password:"+pass_string[pass_string.find(" \"")+2:])
                        if not pair in PASS_PAIRS:
                            PASS_PAIRS.append(pair)
                            THREAT_COUNT += 1
                            PASS_COUNT += 1
                            alert(THREAT_COUNT,"Usernames and passwords sent in the clear",
                                    packet[IP].src,"IMAP",pair)
                        if "pass" not in detected:
                            detected.append("pass")
                # FTP
                elif packet[TCP].dport == 21:
                    if "USER" in str(packet):
                        USER_STRINGS.append(str(packet[TCP].load.decode('utf-8'))[5:-2])
                    elif "PASS" in str(packet):
                        pair = ("username:"+USER_STRINGS.pop(0)+", password:"+
                                        str(packet[TCP].load.decode('utf-8'))[5:-2])
                        if not pair in PASS_PAIRS:
                            PASS_PAIRS.append(pair)
                            THREAT_COUNT += 1
                            PASS_COUNT += 1
                        alert(THREAT_COUNT,"Usernames and passwords sent in the clear",
                                packet[IP].src,"FTP",pair)
                        if "pass" not in detected:
                            detected.append("pass")
            # Nikto scan check
            elif scan == "nikto":
                if packet[TCP].dport == 80 and "Nikto" in str(packet):
                    NIKTO_COUNT += 1
                    NIKTO_PORTS.append(packet[TCP].sport)
                    if "nikto" not in detected:
                        detected.append("nikto")
                        THREAT_COUNT += 1
                        alert(THREAT_COUNT,"Nikto scan",packet[IP].src,
                                "HTTP",packet[TCP].load.decode('utf-8'))
                    elif args.v > 2:
                        THREAT_COUNT += 1
                        alert(THREAT_COUNT,"Nikto scan",packet[IP].src,
                                "HTTP",packet[TCP].load.decode('utf-8'))
            # SMB scan check
            elif scan == "smb":
                 if packet[TCP].dport == 445 and "R" in packet[TCP].flags:
                     SMB_COUNT += 1
                     if "smb" not in detected:
                         detected.append("smb")
                         THREAT_COUNT += 1
                         alert(THREAT_COUNT,"SMB scan",packet[IP].src,
                                "SMB2","no payload on RST")
                     elif args.v > 2:
                         THREAT_COUNT += 1
                         alert(THREAT_COUNT,"SMB scan",packet[IP].src,
                                "SMB2","no payload on RST")

    except Exception as e:
        # Print exceptions if we're being super verbose
        if args.v > 3:
            print(e)
        pass

# Standardize the alert format for more concise code
def alert(tcount,inc,source,proto,pay):
    outstring = str.format("ALERT {incident_number}: {inc} is detected from" +
                            " {source} ({proto}) ({pay})!",
                            incident_number=tcount,inc=inc,source=source,proto=proto,pay=pay)
    print(outstring)

# Scanning portion of program
def scanner():
    if args.pcapfile:
        print("Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile})
        try:
            sniff(offline=args.pcapfile, prn=packetcallback)
        except:
            print("Sorry, something went wrong reading PCAP file %(filename)s!"
                    % {"filename" : args.pcapfile})
    else:
        print("Sniffing on %(interface)s... " % {"interface" : args.interface})
        try:
            sniff(iface=args.interface, prn=packetcallback)
        except:
            print("Sorry, can\'t read network traffic. Are you root?")

# Summarize scans and output based on verbosity
def afterparty():
    global PACKET_COUNT
    global THREAT_COUNT
    global NULL_COUNT
    global NULL_PORTS
    global FIN_COUNT
    global FIN_PORTS
    global XMAS_COUNT
    global XMAS_PORTS
    global PASS_COUNT
    global PASS_PAIRS
    global NIKTO_COUNT
    global NIKTO_PORTS

    if len(detected) > 0:
        if args.v :
            print("----------------------")
            print("Scan Summary")
            print("----------------------")
            for scan in detected:
                if scan == "null":
                    print("Null Scan")
                    print("------------------")
                    NULL_PORTS = list(set(NULL_PORTS))
                    print("# Null Packets:\t\t",NULL_COUNT,"\n# Ports Scanned:\t",len(NULL_PORTS))
                    if args.v > 1:
                        NULL_PORTS.sort()
                        print("Scanned Ports:\n",NULL_PORTS)
                    print("----------------------")
                elif scan == "fin":
                    print("FIN Scan")
                    print("------------------")
                    FIN_PORTS = list(set(FIN_PORTS))
                    print("# FIN Packets:\t\t",FIN_COUNT,"\n# Ports Scanned:\t",len(FIN_PORTS))
                    if args.v > 1:
                        FIN_PORTS.sort()
                        print("Scanned Ports:\n",FIN_PORTS)
                    print("----------------------")
                elif scan == "xmas":
                    print("Xmas Scan")
                    print("------------------")
                    XMAS_PORTS = list(set(XMAS_PORTS))
                    print("# Xmas Packets:\t\t",XMAS_COUNT,"\n# Ports Scanned:\t",len(XMAS_PORTS))
                    if args.v > 1:
                        XMAS_PORTS.sort()
                        print("Scanned Ports:\n",XMAS_PORTS)
                    print("----------------------")
                elif scan == "pass":
                    print("Plaintext Auth Pairs")
                    print("------------------")
                    print("# Auth Pairs:\t",PASS_COUNT)
                    for pair in PASS_PAIRS:
                        print(pair)
                    print("----------------------")
                elif scan == "nikto":
                    print("Nikto Scan")
                    print("------------------")
                    NIKTO_PORTS = list(set(NIKTO_PORTS))
                    print("# Nikto Packets:\t",NIKTO_COUNT,"\n# Ports Scanned:\t",len(NIKTO_PORTS))
                    if args.v > 1:
                        NIKTO_PORTS.sort()
                        print("Scanned Port Numbers:\n",NIKTO_PORTS)
                    print("----------------------")
                elif scan == "smb":
                    print("SMB scan")
                    print("------------------")
                    print("# Failed SMB connections:\t",SMB_COUNT)
        else:
            print("For more detailed output try using the -v argument!")
    else:
        print("No Threats Detected!")

# void main() {
parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
parser.add_argument('-v', action='count', default=0, help='Verbose mode; stacks up to -vvvv')
args = parser.parse_args()
scanner()
afterparty()
# }
