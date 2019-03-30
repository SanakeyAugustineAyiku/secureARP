from kamene.all import *
import arpcache
import time


class SARP:
    """
    This analyse the arp packet for static environment
    """

    def __init__(self, pkt):
        self.pkt = pkt


    def inBoundGARP(self):
        '''
        validates Garp request and adds it to the static arp table
        :return:
        '''
        # check if packet is a broadcast
        if Ether in self.pkt and ARP in self.pkt:
            if self.pkt[Ether].dst == "ff:ff:ff:ff:ff:ff":
                # now check if arp is garp request
                if self.pkt[ARP].op is 1 and (self.pkt[ARP].psrc is self.pkt[ARP].pdst):
                    # now check if this packets source ip is in SARP cache
                    if self.pkt[ARP].psrc in arpcache.SARPtable():
                        # if yes refresh entry in table
                        self.refresh(self.pkt[ARP].psrc, self.pkt[Ether].src)
                    else:
                        # if no (ie this is a this in not in static config file but is valid so add
                        self.allow(self.pkt[ARP].psrc, self.pkt[Ether].src)

    def refresh(self, ip, mac):
        '''
        refresh an entry in the ARP Cache table and also in the static config file
        :param ip:
        :return:
        '''
        arpcache.SARPtable().append((ip, mac))
        if os.name is "nt":
            pass
        elif os.name is "java":
            pass

        pass

    def allow(self,ip, mac):
        pass

    def update(self,ip,mac):
        pass

    def remove(self,ip):
        pass
# a = rdpcap('C:\\Users\\Kasa\\Documents\\arp2.pcapng')
# for p in a:
#     if Ether in p and ARP in p:
#         p.show()
#         print("---"*10)
