# usr/bin/env python
from argparse import Namespace
from typing import Any

import scapy.all as scapy
import argparse


def tgtArgs():
    inputParser = argparse.ArgumentParser
    inputParser.add_argument("-t", "--target", dest="target", help="ENTER A TARGETED SUBNET IP ADDRESS RANGE.")
    options = inputParser.parse_args()
    return options

def ntwrkScnnr(ip):
    arpRqst = scapy.ARP(pdst=ip)
    macBrdcst = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arpBrdcst = macBrdcst / arpRqst
    validList = scapy.srp(arpBrdcst, timeout=1, verbose=False)[0]
    clientList = []


    for element in validList:
        clientKeys = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        print(element[1].psrc + "\t\t" + element[1].hwsrc)
        clientList.append(clientKeys)
    return clientList


def prntResults(trgtResults):
    print("IP\t\t\tMAC Address\n--------------------------------------------------")
    for client in trgtResults():
        print(client["ip"] + "\t\t" + client["mac"])

    # add dictionary here use {} to call it. use "key" to return elements.
    # add ip here make sure to run program 1st.


options = tgtArgs()
scanResult = ntwrkScnnr(options.target)
prntResults(scanResult)
