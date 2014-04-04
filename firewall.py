'''
import sys
import os
import os.path
sys.path.append(os.path.join(os.environ['HOME'],'pox'))
sys.path.append(os.path.join(os.getcwd(),'pox'))
import pox.lib.packet as pktlib
from pox.lib.packet import ethernet,ETHER_BROADCAST,IP_ANY
from pox.lib.packet import arp
from pox.lib.addresses import EthAddr,IPAddr, netmask_to_cidr
from srpy/srpy_common import log_info, log_debug, log_warn, SrpyShutdown, SrpyNoPackets, debugger
from math import floor
#from time import time
'''
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

THISISAGLOBALVARIABLE = 'global variable is best variable <3 <3 <3 \n~Kim Jong Un'


class Rule(object):
    def __init__(self, permit, protocol, srcip, dstip, srcport, dstport, rate):
        self.permit = permit=='permit'
        srccidr = parse_cidr(srcip)
        dstcidr = parse_cidr(dstip)

        self.srcip = srccidr[0].toUnsigned()&cidr_to_netmask(srccidr[1]).toUnsigned()
        self.srcip += 2**(32-srccidr[1])-1
        self.dstip = dstcidr[0].toUnsigned()&cidr_to_netmask(dstcidr[1]).toUnsigned()
        self.dstip += 2**(32-dstcidr[1])-1

        self.protocol = protocol
        self.srcport = srcport
        self.dstport = dstport
        self.rate = rate
        '''
        self.srcmask = cidr_to_netmask(parse_cidr(srcip)[1]).toUnsigned()   
        self.dstmask = cidr_to_netmask(parse_cidr(dstip)[1]).toUnsigned()   
        '''
    def disp(self):
        print '{0} {1} ipsrc {2} ipdst {3} srcport {4} dstport {5} rate {6}'.format(self.permit, self.protocol, IPAddr(self.srcip), IPAddr(self.dstip), self.srcport, self.dstport, self.rate)

    #return True if this rule applies to ip packet pkt
    def matches(self,pkt):
        protocols = {'tcp':pkt.TCP_PROTOCOL, 'udp':pkt.UDP_PROTOCOL, 'ip':pkt.IPv4, 'icmp':pkt.ICMP_PROTOCOL}
        pmatch = pkt.protocol == protocols[self.protocol] or self.protocol == 'ip' 
        ipicmp = self.protocol in ['ip', 'icmp']
        tcpudp = self.protocol in ['tcp','udp'] and pkt.protocol==protocols[self.protocol] 
        portmatch = tcpudp and (self.dstport in [str(pkt.payload.dstport), 'any']) and (self.srcport in [str(pkt.payload.srcport), 'any'])
        srcmatch = pkt.srcip.toUnsigned()&self.srcip == pkt.srcip.toUnsigned()
        dstmatch = pkt.dstip.toUnsigned()&self.dstip == pkt.dstip.toUnsigned()
        return all([srcmatch, dstmatch, pmatch, portmatch or ipicmp])  
                


class Firewall(object):
    def __init__(self):
        # load the firewall_rules.txt file, initialize some data
        # structure(s) that hold the rule representations
        self.updated = time.time() #instance variable to keep track of last time tokens were updated
        self.rules = self.load_rules();
   
    def disp_pkt(self,pkt):
        srcp = dstp = -1
        try:
            dstp, srcp = pkt.payload.dstport, pkt.payload.srcport
        except:
            pass
        print '{0} ipsrc {1} ipdst {2} srcport {3} dstport {4}'.format(pkt.protocol, pkt.srcip, pkt.dstip, srcp, dstp)

    def load_rules(self):
        f = open('firewall_rules.txt','r')
        alldemrules = []
        for line in f:
            rule = line.strip()
            if len(rule)==0 or rule[0]=='#':
                continue
            rule = rule.split(' ')
            srcip=dstip=srcp=dstp = None
            if [i for i in rule if i in ['tcp','udp']]:
                srcp = rule[5]
                dstip = rule[7]
                dstp = rule[9]
            else:
                dstip = rule[5]
                srcp = -1
                dstp = -1
            
            srcip = rule[3]
            #[dstip, srcip] = [i for i in [dstip, srcip] if i!='any' else '255.255.255.255/32']
            dstip = dstip if dstip!='any' else '255.255.255.255/32'
            srcip = srcip if srcip!='any' else '255.255.255.255/32'
            rate = int(rule[len(rule)-1]) if 'ratelimit' in rule else -1
            nextrule = Rule(rule[0], rule[1], srcip, dstip, srcp, dstp, rate)
            alldemrules.append([nextrule, rate])
        f.close()
	return alldemrules	

    #return True if firewall rules (including token buckets) allow for pkt to be forwarded
    #updates tokens.  Should be called by router when packet arrives.  pkt is ip pakcet
    def forward_packet(self, pkt):
        self.update_tokens()
        size = pkt.iplen
        for i, elem in enumerate(self.rules):
            [rule, tokens] = [elem[0], elem[1]]
            if rule.matches(pkt):
                print '\npacket:'
                self.disp_pkt(pkt)
                print 'matched:'
                rule.disp()
                if size<tokens and rule.permit:
                    self.rules[i][1] -= size
                    print 'passed\n'
                    return True
                else:
                    print 'failed\n'
                    return False
        return True	

    def update_tokens(self):
        now = time.time()
        diff = now-self.updated
        if diff<0.5:
            return
        for i, elem in enumerate(self.rules):
            [rule, tokens] = [elem[0], elem[1]]
            if tokens<0:
                continue
            tokens += diff*rule.rate
            if tokens>2*rule.rate:
                tokens = rule.rate
            self.rules[i][1] = tokens
            

def tests():
    f = Firewall()

    ip = ipv4()
    ip.dstip = IPAddr("192.168.100.2")
    ip.srcip = IPAddr("172.16.42.1")
    ip.protocol = ip.TCP_PROTOCOL
    xudp = tcp()
    xudp.srcport = 49662
    xudp.dstport = 80 
    xudp.payload = "Hello, world"
    xudp.len = 8 + len(xudp.payload)
    ip.payload = xudp

    print len(ip) # print the length of the packet, just for fun

    # you can name this method what ever you like, but you'll
    # need some method that gets periodically invoked for updating
    # token bucket state for any rules with rate limits
    f.update_tokens()

    # again, you can name your "checker" as you want, but the
    # idea here is that we call some method on the firewall to
    # test whether a given packet should be permitted or denied.
    print f.forward_packet(ip)
    
    ip2 = ipv4()
    ip2.srcip = IPAddr("192.168.100.2")
    ip2.dstip = IPAddr("172.16.42.1")
    ip2.protocol = ip2.TCP_PROTOCOL
    xudp2 = tcp()
    xudp2.srcport = 80
    xudp2.dstport = 49662
    xudp2.payload = "Hello, world"
    xudp2.len = 8 + len(xudp2.payload)
    ip2.payload = xudp2

    print len(ip2) # print the length of the packet, just for fun

    # you can name this method what ever you like, but you'll
    # need some method that gets periodically invoked for updating
    # token bucket state for any rules with rate limits
    f.update_tokens()

    # again, you can name your "checker" as you want, but the
    # idea here is that we call some method on the firewall to
    # test whether a given packet should be permitted or denied.
    print f.forward_packet(ip2)


    # if you want to simulate a time delay and updating token buckets,
    # you can just call time.sleep and then update the buckets.
    time.sleep(0.5)
    f.update_tokens()

if __name__ == '__main__':
    # only call tests() if this file gets invoked directly,
    # not if it is imported.
    tests()

