#! /usr/bin/python3
import argparse
import sys
import os
import threading
from sniffer import Monitor
from elevate import elevate

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("interface", help="the network interface to use", type=str)
    # parser.add_argument("target", help="the ip address of target host", type=str)
    # parser.add_argument("gateway", help="the ip address of target host gateway", type=str)
    # parser.add_argument("-r", "--reset", help="restore arp table after attack", action="store_true")
    # parser.add_argument("-o", "--output", help="specify output file name with [.pcap] extension(default:arper.pcap",
    #                     action="store_true")
    args = parser.parse_args()
    sniff_thread = threading.Thread(target=Monitor, args=(args.interface,))
    sniff_thread.start()


if __name__ == '__main__':
    try:
        main()
    except PermissionError:
        print("Administrative previledges required.\nRunning as an admin")
        elevate()
    finally:
        sys.exit()