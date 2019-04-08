#! /usr/bin/python3
from kamene.all import ARP
from pkt_validation import ARPInspection
# import time

class DARP(ARPInspection):

    def __init__(self, pkt, my_ip, my_mac,iface):
        ARPInspection.__init__(self, pkt, my_ip, my_mac,iface)
        self.dynamic_arpcache = self.arp_cache.DARPtable()

    
    def inbound_arp_request(self):
                # check if request is an announcement / garp
        if self.is_gratuitous_request(self.pkt) is True:
            # for debugging
            self.pkt.sprintf("Request: %ARP.psrc%  is announcing itself to %ARP.pdst%")
            # send a request to source ip
            self.send_arp_request(self.my_ip,self.my_mac,self.my_ip,"ff:ff:ff:ff:ff:ff",self.iface)
            # deny entry 
            self.deny(self.pkt[ARP].psrc)
        
        # check if its a probe
        elif self.is_probe(self.pkt) is True:
            # reply to probe
            self.send_garp_reply(self.my_ip,self.my_mac,self.my_ip,self.my_mac,self.iface)
        
        # normal arp request
        else:
            if self.ip_exists_in_DARPtable(str(self.pkt[ARP].psrc) is False):
                self.send_arp_brequest(self.my_ip,self.my_mac,self.pkt[ARP].psrc,iface=self.iface)
                
            # reply to request
            self.send_arp_reply(self.my_ip,self.my_mac,self.pkt[ARP].psrc,self.pkt[ARP].hwsrc,self.iface)
            # remove 
            self.remove(self.pkt[ARP].psrc)


    def inbound_arp_reply(self):
        # check if reply is an announcement / garp
        if self.is_gratuitous_reply(self.pkt) is True:
            self.pkt.sprintf("Reply: %ARP.psrc%  is announcing itself to %ARP.pdst%")
            # send request 
            self.send_arp_request(self.my_ip,self.my_mac,self.pkt[ARP].psrc,"",self.iface)
            # deny
            self.deny(self.pkt[ARP].psrc)
        # check if its a probe 
        elif self.is_probe(self.pkt) is True:
            self.pkt.sprintf("Reply: %ARP.psrc%  is probing  %ARP.pdst%")
            pass
        # reqular arp reply
        else:
            self.pkt.sprintf("Reply: %ARP.psrc%  is telling %ARP.pdst% ")
            if self.ip_exists_in_DARPtable(str(self.pkt[ARP].psrc) is True):
                # delete non expired entry 
                # allow
                pass
            else:
                # send request for source mac
                self.send_arp_request(self.my_ip, self.my_mac, self.pkt[ARP].psrc, "ff:ff:ff:ff:ff:ff", self.iface)
                # deny
                self.deny(self.pkt[ARP].psrc)

    
    
    
    

    def outbound_arp_request(self):
        pass
    
    def outbound_arp_reply(self):
        pass
    
    def deny(self, ip):
        ARPInspection.deny(self, ip)
    
    def allow(self, ip, mac):
        ARPInspection.allow(self, ip, mac)
    
    def refresh(self, ip, mac):
        ARPInspection.refresh(self, ip, mac)
    
    def remove(self, ip):
        ARPInspection.remove(self, ip)
    
    
    