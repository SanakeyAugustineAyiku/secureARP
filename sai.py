#! /usr/bin/python3
from kamene.all import *
# from arpcache import ARP as arp
from pkt_validation import ARPInspection
import time


class SARP(ARPInspection):
    """
    This analyse the arp packet for static environment
    """

    def __init__(self, pkt, my_ip, my_mac):
        super().__init__(self, pkt)
        self.pkt = pkt
        self.my_ip = my_ip
        self.my_mac = my_mac
        self.static_arpcache = self.arp_cache.SARPtable()
        # print(self.static_arpcache)

    def inbound_arp_request(self):
        """
        validate arp request sent to us (either by broadcast or unicast
        :return:
        """
        # check if request is an announcement / garp

        # srcip==dstip dstmac == broadcast
        if (str(self.pkt[ARP].psrc) == str(self.pkt[ARP].pdst) and str(self.pkt[ARP].hwdst) == "ff:ff:ff:ff:ff:ff"):
            #  check if this packets source ip is in SARP cache
            if self.ip_exists_in_SARPtable(str(self.pkt[ARP].psrc)):
                # if yes refresh entry in table
                self.refresh(self.pkt[ARP].psrc, self.pkt[Ether].src)
                # for debuging
                self.pkt.sprintf("Request: %ARP.psrc%  is announcing itself to %ARP.pdst%")
            else:
                # if no (ie this is a this in not in static config file but is valid so add
                self.allow(self.pkt[ARP].psrc, self.pkt[Ether].src)
                # for debugging
                self.pkt.sprintf("Request: %ARP.psrc%  is announcing itself to %ARP.pdst%")
        # check if request is a probe for our ip
        elif (str(self.pkt[ARP].psrc) is '0.0.0.0' and str(self.pkt[ARP].hwdst) is '00:00:00:00:00:00' and \
            str(self.pkt[ARP].pdst is self.my_ip)):
            # send a probe reply to source / announce your self again
            sendp(Ether(src=self.my_mac, dst=self.pkt[Ether].src)/ARP(op=2, psrc=self.my_ip, hwsrc=self.my_mac,
                                                                        pdst=self.my_ip, hwdst="ff:ff:ff:ff:ff:ff"))
            self.pkt.sprintf("Request: %Ether.src% ,%ARP.hwsrc% is probing %ARP.pdst%")
        # request is a normal arp request
        elif (str(self.pkt[Ether].src) == str(self.pkt[ARP].hwsrc)):
            # send appropriate reply
            sendp(Ether(src=self.my_mac, dst=self.pkt[Ether].src)/ARP(op=2, psrc=self.my_ip, hwsrc=self.my_mac, pdst=self.pkt[ARP].psrc, hwdsr=self.pkt[ARP].hwsrc))
            # add source ip and source  mac to entry
            # ensure that we do not have a possible cloning attack
            for ip, mac in self.static_arpcache:
                if str(self.pkt[ARP].psrc) == ip and str(self.pkt[ARP].hwsrc) == mac:
                    self.pkt.summary()
            self.pkt.sprintf("Request: (%ARP.psrc% ,%ARP.hwsrc%) is asking about %ARP.pdst%")

    def inbound_arp_reply(self):
        """
        validate arp replies sent to us either by broadcast or unicast
        :return:
        """
        # check if reply is an announcement of /garp
        if (str(self.pkt[ARP].psrc) == str(self.pkt[ARP].pdst)) and \
            (str(self.pkt[ARP].hwsrc) == str(self.pkt[ARP].hwdst)):
            #  check if this packets source ip is in SARP cache
            if self.ip_exists_in_SARPtable(str(self.pkt[ARP].psrc)):
                # if yes refresh entry in table
                self.refresh(self.pkt[ARP].psrc, self.pkt[Ether].src)
                # for debuging
                self.pkt.sprintf("Request: %ARP.psrc%  is announcing itself to %ARP.pdst%")
            else:
                # allow
                self.allow(self.pkt[ARP].psrc, self.pkt[Ether].src)
                # for debugging
                self.pkt.sprintf("Request: %ARP.psrc%  is announcing itself to %ARP.pdst%")
        # check if reply is a probe 
        elif (str(self.pkt[ARP].psrc) is '0.0.0.0' and str(self.pkt[ARP].hwdst) is '00:00:00:00:00:00' and \
            str(self.pkt[ARP].pdst is self.my_ip)):
            # ignore this probe reply
            pass

        # if its a normal arp reply
        else:
            # check for address conflict
            if self.address_conflict(self.pkt[ARP].psrc, self.pkt[Ether].src) is False:
                # process packet
                if self.ip_exists_in_SARPtable(str(self.pkt[ARP].psrc)):
                    
                    self.refresh(self.pkt[ARP].psrc, self.pkt[Ether].src)
                else:
                    self.allow(self.pkt[ARP].psrc, self.pkt[Ether].src)


# a = rdpcap('C:\\Users\\Kasa\\Documents\\arp2.pcapng')
# for p in a:
#     if Ether in p and ARP in p:
#         p.show()
#        
# print("---" * 10)
