#! /usr/bin/python3
import os
import time
from sys import platform
from python_arptable import get_arp_table


class ARP:

    def __init__(self):
        self.ArpTable = []
        self.SarpTable = []
        self.DarpTable = []
        self.my_arp_cache_table = get_arp_table()
        self.add_static_addresses()
        self.Static_address = self.get_static_config()
    
    def add_static_addresses(self):
        """
            add static arp entries to SarpTable
        """
        s_conf_list = self.get_static_config()
        if not self.SarpTable:
            for ip, mac in s_conf_list:
                self.SarpTable.append((ip, mac,time.time()))
        return self.SarpTable

    def get_static_config(self):
        """
            read statically configured ip,mac addresses
        """
        separator = "/"
        if os.name == 'nt':
            separator = "\\"

        sapconf = "conf%sSARP.conf" % separator
        addressess = []
        with open(sapconf, 'r') as f:
            lines = f.readlines()
            for line in lines:
                if line.startswith('#') or line.startswith('\n'):
                    continue
                else:
                    line = line.strip(" ").rstrip('\n')
                    line = line.split(" ")
                    for i in range(len(line)):
                        for word in line:
                            if word is '' or word is ' ':
                                line.remove(word)
                    ip, mac = line

                    addressess.append((ip, mac))

        return addressess

    def SARPtable(self):
        return self.SarpTable

    def DARPtable(self):
        return self.DarpTable

    def format_arp_table(self):
        """
            Get the arp cache entry for linux system
        """
        if str(platform).lower() == 'Linux'.lower() or str(os.name).lower() == 'posix'.lower():
            for _dict in self.my_arp_cache_table:
                self.ArpTable.append((_dict['IP address'], _dict['HW address'], _dict['Device']))
    
    def get_arp_cache_table(self):
        # for entry in self.SarpTable:
        #     pass
        # for entry in self.DarpTable:
        #     pass
        return self.ArpTable
