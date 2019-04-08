#! /usr/bin/python3

from kamene.all import Ether,ARP, sendp
from arpcache import ARP as arp
from os import name as os_name, popen
from sys import platform as os_platform

class ARPInspection:
    """
        Contains utily methods for validating packets
    """
    def __init__(self, pkt, my_ip, my_mac,iface):
        self.pkt = pkt
        self.my_ip = my_ip
        self.my_mac = my_mac
        self.iface  = iface
        self.arp_cache = arp()
        self.cache_timeout = 10
    

    def ip_exists_in_SARPtable(self, ip):
        """"
            Check if there is an entry for the given ip in the static cache
        """
        if ip in  self.arp_cache.SARPtable():
            return True
        return False
    
    def ip_exists_in_DARPtable(self, ip):
        if ip in self.arp_cache.DARPtable():
            return True
        return False

    def address_conflict(self, ip, mac):
        """"
            Check if there is an entry for given ip but the paired mac is not the given mac
        """
        if str(os_name).lower() is 'posix'.lower() or str(os_platform).lower() is 'Linux'.lower():
            for ip_addr , mac_addr,  in self.arp_cache.get_arp_cache_table():
                if ip == ip_addr and mac != mac_addr:
                    return ip_addr, mac_addr
                elif ip != ip_addr and mac == mac_addr:
                    return ip_addr, mac_addr
            if str(os_name).lower() is 'nt'.lower() or str(os_platform).lower() is 'win32'.lower():
                pass
        return False
    
    def is_a_mallformed_packet(self, pkt):
        """
            Checks if the packet is an invalid arp packet (possible spoofing with fake mac)
        """
        if pkt[Ether].src == pkt[ARP].hwsrc:
            return False
        return True
   
    def is_gratuitous_request(self, pkt):
        if (str(pkt[ARP].psrc) == str(pkt[ARP].pdst) and str(pkt[ARP].hwdst) \
            == "ff:ff:ff:ff:ff:ff" or str(pkt[ARP].hwdst) == "00:00:00:00:00:00"):
            return True
        return False

    def is_gratuitous_reply(self, pkt):
        if (str(pkt[ARP].psrc) == str(pkt[ARP].pdst) and str(pkt[ARP].hwsrc) == str(pkt[ARP].hwdst)):
            return True
        return False
    
    def is_probe(self, pkt):
        if (str(pkt[ARP].psrc) is '0.0.0.0' and str(pkt[ARP].hwdst) is '00:00:00:00:00:00' and \
            str(pkt[ARP].pdst) is str(self.my_ip)):
            return True
        return False

    def refresh(self, ip, mac):
        """
         refresh an entry in the ARP Cache table and also in the static config file
        :param ip:
        :param mac:
        :return:
        """
        if self.is_a_mallformed_packet(self.pkt) is not True:
            print("[*] Refreshing Entry %s - %s"%(ip,mac))

    def allow(self, ip, mac):
        """
        allow a valid arp entry not in static config
        :param ip:
        :param mac:
        :return:
        """
        if self.is_a_mallformed_packet(self.pkt) is not True:
            print("[*] Allowing Entry %s - %s"%(ip,mac))

    def update(self, ip, mac):
        """
        update an entry
        :param ip:
        :param mac:
        :return:
        """
        if self.is_a_mallformed_packet(self.pkt) is not True:
            print("[*] updating Entry %s - %s"%(ip,mac))

    def remove(self, ip):
        """
        remove bad entry from cache
        :param ip:
        :return:
        """
        print("[*] removing Entry for %s"%(ip,))
        # if str(os_platform).lower() is "Linux".lower():
        #     try:
        #         popen("arp -d "+ str(ip))
        #     except OSError:
        #         pass
    
    def deny(self, ip):
        if ip in self.arp_cache.get_arp_cache_table():
            self.remove(ip)
    
    def send_arp_brequest(self,my_ip, my_mac, dst_ip, dst_mac="ff:ff:ff:ff:ff:ff",iface=None):
        """
            send a broadcast request for the source ip of a received arp request packet to eliminate cloning
        """
        sendp(Ether(src=self.my_mac,dst="ff:ff:ff:ff:ff:ff")/ARP(op=1,psrc=my_ip,hwsrc=my_mac,pdst=dst_ip,hwdst=dst_mac),iface=iface)
    
    def send_arp_request(self,my_ip, my_mac, dst_ip, dst_mac,iface=None):
        """
            request for the mac address associated with an ip address
        """
        sendp(Ether(src=self.my_mac,dst=dst_mac)/ARP(op=1,psrc=my_ip,hwsrc=my_mac,pdst=dst_ip,hwdst=dst_mac),iface=iface)
    
    def send_arp_reply(self,my_ip, my_mac, dst_ip, dst_mac,iface=None):
        """
            reply to an arp request for our ip address
        """
        sendp(Ether(src=self.my_mac,dst=dst_mac)/ARP(op=2,psrc=my_ip, hwsrc=my_mac, pdst=dst_ip, hwdst=dst_mac),iface=iface)

    def send_garp_request(self,my_ip, my_mac, dst_ip, dst_mac,iface=None):
        """
        send an arp announcement packet as a request
        """
        sendp(Ether(src=self.my_mac,dst="ff:ff:ff:ff:ff:ff")/ARP(op=1,psrc=my_ip,hwsrc=my_mac,pdst=dst_ip,hwdst=dst_mac),iface=iface)
    
    def send_garp_reply(self,my_ip, my_mac, dst_ip, dst_mac,iface=None):
        """
        send an arp announcement packet as a reply
        """
        sendp(Ether(src=self.my_mac,dst="ff:ff:ff:ff:ff:ff")/ARP(op=2,psrc=my_ip,hwsrc=my_mac,pdst=dst_ip,hwdst=dst_mac),iface=iface)
    
    def send_probe_request(self, my_mac, dst_ip, dst_mac, my_ip="0.0.0.0",iface=None):
        """
        send an arp request probe for an ip address
        """
        sendp(Ether(src=self.my_mac,dst=dst_mac)/ARP(op=1,psrc=my_ip,hwsrc=my_mac,pdst=dst_ip,hwdst=dst_mac),iface=iface)
    
    def send_probe_reply(self, my_mac, dst_ip, dst_mac, my_ip="0.0.0.0", iface=None):
        """
        send an arp  probe for an ip address as an arp reply
        """
        sendp(Ether(src=self.my_mac,dst=dst_mac)/ARP(op=2,psrc=my_ip,hwsrc=my_mac,pdst=dst_ip,hwdst=dst_mac),iface=iface)

    def inbound_arp_reply(self):
            """
                process arp replies sent to us
            """
            pass    
    
    def inbound_arp_request(self):
        """
            process arp request sent to us
        """
        pass
    
    def outbound_arp_request(self):
        """
            process arp requests sent by us
        """
        pass
    
    def outbound_arp_reply(self):
        """
            process arp replies sent by us
        """
        pass
