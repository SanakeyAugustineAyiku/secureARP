#! /usr/bin/python3

from kamene.all import Ether,ARP
from arpcache import ARP as arp
from os import name as os_name
from sys import platform as os_platform


class ARPInspection:
    """
        Contains utily methods for validating packets
    """
    def __init__(self, pkt):
        self.arp_cache = arp()
        self.cache_timeout = 2000
        self.pkt = pkt
    

    def ip_exists_in_SARPtable(self, ip):
        """"
            Check if there is an entry for the given ip in the static cache
        """
        if ip in  self.arp_cache.SARPtable():
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