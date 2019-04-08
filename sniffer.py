#! /usr/bin/python3
from kamene.all import *
from getmac import get_mac_address
from sai import SARP
from dai import DARP
import ifaddr



# elevate.elevate()
#
# def sniff_arp_request(pkt):
#     if ARP in pkt and pkt[ARP].op is 1:
#         return pkt.sprintf("%ARP.hwsrc% -- %ARP.psrc%")
#
# def sniff_arp_reply(pkt):
#     if ARP in pkt and pkt[ARP].op is 2:
#         return pkt.sprintf("%ARP.hwsrc% -- %ARP.psrc% %ARP.hwdst% == %ARP.pdst%")
#
#
# sniff(prn=sniff_arp_reply, filter="arp", store=0)
#

# a = get_windows_if_list()
# for i in a:
#     print(i)
# print("----------" * 10)
# al = ifaddr.get_adapters()
# for adapter in al:
#     print(adapter)
#     print ("IPs of network adapter " + adapter.nice_name)
#     for ip in adapter.ips:
#         print("   %s/%s" % (ip.ip, ip.network_prefix))
# _iface = "Broadcom BCM43142 802.11 bgn Wi-Fi M.2 Adapter"
# _iface = 'eth0'
# adapters = ifaddr.get_adapters()
# iface_ips = []
# for adapter in adapters:
#     if str(adapter.nice_name) == _iface or str(adapter.name) == _iface:
#         for ip in adapter.ips:
#             # if type(ip.ip) is tuple:
#             #     ip.ip = ip.ip[0]
#             #
#             #     print(ip.ip)
#             if ":" in str(ip.ip):
#                 continue
#             iface_ips.append((ip.ip, ip.network_prefix, _iface))
#
# print(iface_ips)
#

class Monitor:
    def __init__(self, interface):

        self.iface = interface
        self.iface_ip_config = self.ip_from_iface(self.iface)
        self.mac = get_mac_address(interface)
        self.ip = None
        if self.iface_ip_config:
            self.ip = self.iface_ip_config[0][0]
        self.welcome()
        self.start(self.iface)

    def welcome(self):
        print("Welcome to secureARP".center(80," "),"\nYour NIC name is %s with MAC address %s and IP address %s \n"
            %(self.iface,self.mac,self.ip))
    def start(self, iface):
        
        sniff(iface=iface, prn=self.sniff_arp_packet, filter='arp', store=0)

    def ip_from_iface(self, iface):
        adapters = ifaddr.get_adapters()
        iface_ips = []
        for adapter in adapters:
            if str(adapter.nice_name) == iface or str(adapter.name) == iface:
                for ip in adapter.ips:
                    if ":" in str(ip.ip):
                        continue
                    iface_ips.append((ip.ip, ip.network_prefix, iface))
        return iface_ips

    def sniff_arp_packet(self, pkt):
        try:
            sarp = SARP(pkt, self.ip, self.mac,self.iface)
            darp = DARP(pkt,self.ip,self.mac,self.iface)
            # if I/O direction of packet is inbound
            if (pkt[Ether].dst == "ff:ff:ff:ff:ff:ff") or str(pkt[Ether].dst) == self.mac:
               
                # check if packet is a request
                if pkt[ARP].op == 1:
                    # sarp.inbound_arp_request()
                    # print(sarp.arp_cache.SARPtable())
                    darp.inbound_arp_request()
                    # return pkt.sprintf("Request: (%ARP.psrc% ,%ARP.hwsrc%) is asking about %ARP.pdst%")
                elif pkt[ARP].op == 2:
                    # sarp.inbound_arp_reply()
                    # print(sarp.arp_cache.SARPtable())
                    darp.inbound_arp_reply()
                # return pkt.sprintf("Request: (%ARP.psrc% ,%ARP.hwsrc%) is asking about %ARP.pdst%")
        except KeyboardInterrupt:
            print("[*] You press Ctrl + C\n")
            print(sarp.arp_cache.SARPtable())
        finally:
            pass
           
        
# def test(pkt):
#     if pkt[ARP].op == 1:
#         return pkt.summary()
# # pboamah1 4wvvop7
# sniff(iface='usb0',prn=test, filter='arp')