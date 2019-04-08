#! /usr/bin/python3
from kamene.all import *
# from arpcache import ARP as arp
from pkt_validation import ARPInspection
import time


class SARP(ARPInspection):
    """
    This analyse the arp packet for static environment
    """

    def __init__(self, pkt, my_ip, my_mac,iface):
        ARPInspection.__init__(self, pkt, my_ip, my_mac, iface)
        # self.pkt = pkt
        # self.my_ip = my_ip
        # self.my_mac = my_mac
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
            # for debuging
            self.pkt.sprintf("Request: %ARP.psrc%  is announcing itself to %ARP.pdst%")
            #  check if this packets source ip is in SARP cache
            if self.ip_exists_in_SARPtable(str(self.pkt[ARP].psrc) is True):
                # refresh entry in table
                self.refresh(self.pkt[ARP].psrc, self.pkt[Ether].src)
            else:
                # allow
                self.allow(self.pkt[ARP].psrc, self.pkt[Ether].src)

        # check if request is a probe for our ip
        elif (str(self.pkt[ARP].psrc) is '0.0.0.0' and str(self.pkt[ARP].hwdst) is '00:00:00:00:00:00' and \
            str(self.pkt[ARP].pdst is self.my_ip)):
            self.pkt.sprintf("Request: %Ether.src% ,%ARP.hwsrc% is probing %ARP.pdst%")
            # send a probe reply to source / announce your self again
            self.send_garp_reply(self.my_ip,self.my_mac,self.my_ip,self.my_mac,self.iface)
            # sendp(Ether(src=self.my_mac, dst=self.pkt[Ether].src)/ARP(op=2, psrc=self.my_ip, hwsrc=self.my_mac, \
            # pdst=self.my_ip, hwdst="ff:ff:ff:ff:ff:ff"),iface=self.iface)
           
        # request is a normal arp request
        elif (str(self.pkt[Ether].src) == str(self.pkt[ARP].hwsrc)):
            self.pkt.sprintf("Request: (%ARP.psrc% ,%ARP.hwsrc%) is asking about %ARP.pdst%")
            # send appropriate reply
            self.send_arp_reply(self.my_ip,self.my_mac,self.pkt[ARP].psrc,self.pkt[ARP].hwsrc,self.iface)
            # sendp(Ether(src=self.my_mac, dst=self.pkt[Ether].src)/ARP(op=2, psrc=self.my_ip, hwsrc=self.my_mac, pdst=self.pkt[ARP].psrc, hwdsr=self.pkt[ARP].hwsrc))
            
            #  check for address conflict ensure ,that we do not have a possible cloning attack
            if self.address_conflict(self.pkt[ARP].psrc, self.pkt[Ether].src) is False:
                # process packet
                if self.ip_exists_in_SARPtable(str(self.pkt[ARP].psrc) is True):
                    self.refresh(self.pkt[ARP].psrc, self.pkt[Ether].src)
                else:
                    # allow ,add source ip and source  mac to entry
                    self.allow(self.pkt[ARP].psrc, self.pkt[Ether].src)
            

    def inbound_arp_reply(self):
        """
        validate arp replies sent to us either by broadcast or unicast
        :return:
        """
        # check if reply is an announcement of /garp
        if (str(self.pkt[ARP].psrc) == str(self.pkt[ARP].pdst)) and \
            (str(self.pkt[ARP].hwsrc) == str(self.pkt[ARP].hwdst)):
            # for debuging
            self.pkt.sprintf("Request: %ARP.psrc%  is announcing itself to %ARP.pdst%")
            #  check if this packets source ip is in SARP cache
            if self.ip_exists_in_SARPtable(str(self.pkt[ARP].psrc)):
                # if yes refresh entry in table
                self.refresh(self.pkt[ARP].psrc, self.pkt[Ether].src)
                
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
            # for debugging
            self.pkt.sprintf("Request: %ARP.psrc%  is asking for mac of %ARP.pdst%")
            # check for address conflict
            if self.address_conflict(self.pkt[ARP].psrc, self.pkt[Ether].src) is False:
                # process packet
                if self.ip_exists_in_SARPtable(str(self.pkt[ARP].psrc)):
                    
                    self.refresh(self.pkt[ARP].psrc, self.pkt[Ether].src)
                else:
                    self.allow(self.pkt[ARP].psrc, self.pkt[Ether].src)

    def allow(self, ip, mac):
        if self.is_a_mallformed_packet(self.pkt) is not True:
            print("[*] Allowing Entry %s - %s"%(ip,mac))
            self.arp_cache.SarpTable.append((ip,mac,time.time()))

    def update(self, ip, mac):
        if self.is_a_mallformed_packet(self.pkt) is not True:
            print("[*] updating Entry %s - %s"%(ip,mac))
            for ip_ , mac_, timeout in self.arp_cache.SarpTable:
                if (ip_ == ip and mac_ == mac) and (timeout - time.time()) < self.cache_timeout:
                    pos = self.arp_cache.SarpTable.index((ip_,mac_, timeout))
                    self.arp_cache.SarpTable[pos] = (ip, mac, time.time())
    
    





# a = rdpcap('C:\\Users\\Kasa\\Documents\\arp2.pcapng')
# for p in a:
#     if Ether in p and ARP in p:
#         p.show()
#        
# print("---" * 10)
