import sys
import os
import os.path
sys.path.append(os.path.join(os.environ['HOME'],'pox'))
sys.path.append(os.path.join(os.getcwd(),'pox'))
import pox.lib.packet as pktlib
from pox.lib.packet import ethernet,ETHER_BROADCAST,IP_ANY
from pox.lib.packet import arp,ipv4,icmp,unreach,udp,tcp
from pox.lib.addresses import EthAddr,IPAddr,netmask_to_cidr,cidr_to_netmask,parse_cidr
import time
from math import log10, ceil

class Firewall(object):
    def __init__(self):
        # load the firewall_rules.txt file, initialize some data
        # structure(s) that hold the rule representations
        self.rules = load_rules();
        protocols = {'tcp':1,'udp':2,'icmp':3,'ip':4}
        allowdeny = {'allow':0,'deny':1}
    
    def load_rules():
        f = open('firewall_rules.txt','r')
        for rule in f:
            rule = rule.strip()
            if rule[0]=='#':
                continue
            rule = rule.split(' ')
            rulenums = []
            rulenums.append(protocols[rule[1]])
            rulenums.append(allowdeny[rule[0]])
            srcip = parse_cidr(rule[3])
            rulenums.append(srcip[0].toUnsigned + 2**srcip[1])
            

    #concatenate integers x & y, so that cat(10, 234) returns 10234
    def cat(x):
        catnum = 0;
        for el in x:
            try:
                catnum = int(catnum*10**ceil(log10(el))+el)
            except ValueError:
                catnum *= 10
        return catnum

def tests():
    f = Firewall()

    ip = ipv4()
    ip.srcip = IPAddr("172.16.42.1")
    ip.dstip = IPAddr("10.0.0.2")
    ip.protocol = 17
    xudp = udp()
    xudp.srcport = 53
    xudp.dstport = 53
    xudp.payload = "Hello, world"
    xudp.len = 8 + len(xudp.payload)
    ip.payload = xudp

    print len(ip) # print the length of the packet, just for fun

    # you can name this method what ever you like, but you'll
    # need some method that gets periodically invoked for updating
    # token bucket state for any rules with rate limits
    f.update_token_buckets()

    # again, you can name your "checker" as you want, but the
    # idea here is that we call some method on the firewall to
    # test whether a given packet should be permitted or denied.
    assert(f.allow(ip) == True)

    # if you want to simulate a time delay and updating token buckets,
    # you can just call time.sleep and then update the buckets.
    time.sleep(0.5)
    f.update_token_buckets()

if __name__ == '__main__':
    # only call tests() if this file gets invoked directly,
    # not if it is imported.
    tests()

