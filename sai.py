#! /usr/bin/python3
from kamene.all import *
from arpcache import ARP as arp
import time


class SARP:
    """
    This analyse the arp packet for static environment
    """

    def __init__(self, pkt, my_ip, my_mac, timeout=2000):
        self.pkt = pkt
        self.my_ip = my_ip
        self.my_mac = my_mac
        self.arp_cache = arp()
        self.static_arpcache = self.arp_cache.SARPtable()
        print(self.static_arpcache)

    def inbound_arp_request(self):
        """
        validate arp request sent to us (either by broadcast or unicast
        :return:
        """
        # check if request is an announcement / garp

        # op =1 srcip==dstip dstmac == broadcast
        if self.pkt[ARP].op == 1 and (str(self.pkt[ARP].psrc) == str(self.pkt[ARP].pdst)
                                      and str(self.pkt[ARP].hwdst) is "ff:ff:ff:ff:ff:ff"):
            # now check if this packets source ip is in SARP cache
            if self.pkt[ARP].psrc in self.arp_cache.SARPtable():
                # if yes refresh entry in table
                self.refresh(self.pkt[ARP].psrc, self.pkt[Ether].src)
            else:
                # if no (ie this is a this in not in static config file but is valid so add
                self.allow(self.pkt[ARP].psrc, self.pkt[Ether].src)
        # check if request is a probe
        elif self.pkt[ARP].op is 1 and \
                (str(self.pkt[ARP].psrc) is '0.0.0.0' and str(self.pkt[ARP].hwdst) is '00:00:00:00:00:00' and
                 str(self.pkt[ARP].pdst is self.my_ip)):
            # send a probe reply to source / announce your self again
            sendp(Ether(src=self.my_mac, dst=self.pkt[Ether].src)/ARP(op=2, psrc=self.my_ip, hwsrc=self.my_mac,
                                                                        pdst=self.my_ip, hwdst="ff:ff:ff:ff:ff:ff"))
        # request is a normal arp request
        elif self.pkt[ARP].op == 1 and (self.pkt[Ether].src is self.pkt[ARP].hwsrc):
            # send appropriate reply
            sendp(
                Ether(src=self.my_mac, dst=self.pkt[Ether].src)/ARP(op=2, psrc=self.my_ip, hwsrc=self.my_mac, pdst=self.pkt[ARP].psrc, hwdsr=self.pkt[Ether].src))
            # add source ip and source  mac to entry
            # ensure that we do not have a possible cloning attack
            for ip, mac in self.static_arpcache:
                if str(self.pkt[ARP].psrc) == ip and str(self.pkt[ARP].hwsrc) == mac:
                    self.pkt.summary()

    def inbound_arp_reply(self):
        """
        validate
        :return:
        """

    def refresh(self, ip, mac):
        """
         refresh an entry in the ARP Cache table and also in the static config file
        :param ip:
        :param mac:
        :return:
        """
        # if os.name is "nt":
        #     pass
        # elif os.name is "java":
        #     pass
        print("[*] Refreshing Entry %s - %s"%(ip,mac))

    def allow(self, ip, mac):
        """
        allow a valid arp entry not in static config
        :param ip:
        :param mac:
        :return:
        """
        print("[*] Allowing Entry %s - %s"%(ip,mac))

    def update(self, ip, mac):
        """
        update an entry
        :param ip:
        :param mac:
        :return:
        """
        print("[*] updating Entry %s - %s"%(ip,mac))

    def remove(self, ip):
        """
        remove bad entry from cache
        :param ip:
        :return:
        """
        print("[*] removing Entry %s - %s"%(ip,))

# a = rdpcap('C:\\Users\\Kasa\\Documents\\arp2.pcapng')
# for p in a:
#     if Ether in p and ARP in p:
#         p.show()
#        
# print("---" * 10)
