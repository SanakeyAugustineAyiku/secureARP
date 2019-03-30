from kamene.all import *
from getmac import  get_mac_address
import ifaddr
import arpcache
import elevate

elevate.elevate()
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
al = ifaddr.get_adapters()
for adapter in al:

    print("IPs of network adapter " + adapter.nice_name)
    for ip in adapter.ips:
        print("   %s/%s -- mac is %s" % (ip.ip, ip.network_prefix,get_mac_address(adapter.nice_name)))
_iface = "Broadcom BCM43142 802.11 bgn Wi-Fi M.2 Adapter"
adapters = ifaddr.get_adapters()
iface_ips = []
for adapter in adapters:
    if str(adapter.nice_name) == _iface or str(adapter.name) == _iface:
        for ip in adapter.ips:
            if type(ip.ip) is tuple:
                ip.ip = ip.ip[0]
            iface_ips.append(ip.ip)
            print("ip address is %s and its associated mac is %s"% (ip.ip, get_mac_address(ip.ip)))
# print(iface_ips)

class Monitor:
    def __init__(self, iface):
        self.iface = iface
        self.iface_ips = self.ip_from_iface(self.iface)

    def ip_from_iface(self, iface):
        adapters = ifaddr.get_adapters()
        iface_ips = []
        for adapter in adapters:
            if str(adapter.nice_name) == iface or str(adapter.name) == iface:
                for ip in adapter.ips:
                    if type(ip.ip) is tuple:
                        ip.ip = ip.ip[0]
                    iface_ips.append(ip.ip)
        return iface_ips

    def SARP(self):
        sniff(iface=self.iface, prn=self.sniff_arp_request, filter='arp', store=0)
        pass

    def is_in_SARPTABLE(self, table, value):
        for tupl in table:
            return value is tupl[0] or tupl[1]

    def sniff_arp_request(self, pkt):
        # check if packet is an arp request
        if ARP in pkt and pkt[ARP].op is 1:
            # check if the request from us
            if pkt[ARP].psrc in self.iface_ips:
                pass
            # check if packet is for us (either unicast or broadcast
            elif pkt[ARP].pdst in self.iface_ips or pkt[ARP].hwdst == 'ff:ff:ff:ff:ff:ff':

                # check if it is a gratuitous request
                if pkt[ARP].psrc == pkt[ARP].pdst:
                    # add entry to table (either refresh or make new entry
                    if self.is_in_SARPTABLE(arpcache.SARPtable(),pkt[ARP].psrc):
                        pass

    def Clean(self, ip, mac):
        '''
        cleans the entry with the <IP,MAC> from the arp cache
        :param ip:
        :param mac:
        :return:
        '''
        pass

    def Update(self, ip, mac):
        '''
        Updates the entry with <IP,MAC>
        :param ip:
        :param mac:
        :return:
        '''
        pass
    def Allow(self, ip , mac):
        '''
        Allows a dynamic entry into the cache
        :param ip:
        :param mac:
        :return:
        '''
        pass

# if os.name == "nt":
#     interfaces = get_windows_if_list()
#     for i in interfaces:
#         if i["name"] is self.iface or i['guid'] is self.iface:
#             sniff(iface=iface, prn=p, filter="arp", store=0)
#
