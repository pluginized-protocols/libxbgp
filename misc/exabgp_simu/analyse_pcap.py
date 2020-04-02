#! /usr/bin/env python3

import sys

from pcapng.scanner import FileScanner
from pcapng.blocks import EnhancedPacket

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.contrib.bgp import BGP, BGPUpdate, BGPPathAttr, BGPHeader

with open(sys.argv[1], 'rb') as fp:
    scanner = FileScanner(fp)
    dict_attr_42 = dict()
    routes = set()
    count = 0

    time_first = -1

    for block in scanner:
        if isinstance(block, EnhancedPacket):
            if block.interface.link_type != 1:
                print("Not internet frame skip")
                continue
            if time_first == -1:
                time_first = block.timestamp

            eth = Ether(block.packet_data)
            ip_packet = eth.payload

            if not isinstance(ip_packet, IP):
                continue

            ip_src = str(ip_packet.src)
            ip_dst = str(ip_packet.dst)

            tcp_packet = ip_packet.payload

            if not isinstance(tcp_packet, TCP):
                continue

            tcp_payload = tcp_packet.payload

            for layer in tcp_payload.layers():
                if layer == BGPHeader:
                    bgp_update: BGPHeader = tcp_payload.payload

                    if 'nlri' in bgp_update.fields:
                        for prefix in bgp_update.nlri:

                            routes.add(prefix.prefix)

                            if 'path_attr' in bgp_update.fields:
                                for attr in bgp_update.fields['path_attr']:
                                    if attr.type_code == 42:
                                        count += 1

                                        if ip_src not in dict_attr_42:
                                            dict_attr_42[ip_src] = dict()

                                        if ip_dst not in dict_attr_42[ip_src]:
                                            dict_attr_42[ip_src][ip_dst] = set()

                                        converted_nb = int.from_bytes(attr.attribute, byteorder='big')
                                        dict_attr_42[ip_src][ip_dst].add((prefix.prefix, converted_nb))

    print(len(routes))

    for src in dict_attr_42.keys():
        for dst in dict_attr_42[src]:
            print("Update from %s to %s: nb routes %d" % (src, dst, len(dict_attr_42[src][dst])))
