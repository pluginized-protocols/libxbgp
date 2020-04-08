#! /usr/bin/env python3

import sys

from scapy.contrib.bgp import BGP, BGPUpdate
import pcapkit

extraction = pcapkit.extract(fin=sys.argv[1], store=False, nofile=True, tcp=True, strict=True)

updates = dict()


def get_packet_layer(packet):
    counter = 0
    while True:
        layer = packet.getlayer(counter)
        if layer is None:
            break
        yield layer
        counter += 1


for packet in extraction.reassembly.tcp:

    tupl = (str(packet.id.src[0]), packet.id.src[1], str(packet.id.dst[0]), packet.id.dst[1])

    for reassembly in packet.packets:
        tcp_payload = BGP(reassembly.info.packet)

        for bgp in get_packet_layer(tcp_payload):
            if isinstance(bgp, BGPUpdate):

                if tupl[0] not in updates:
                    updates[tupl[0]] = dict()

                if tupl[2] not in updates[tupl[0]]:
                    updates[tupl[0]][tupl[2]] = list()

                for attr in bgp.path_attr:
                    if attr.type_code == 42:

                        for route in bgp.nlri:
                            conv_geo = int.from_bytes(attr.attribute, byteorder='big')
                            updates[tupl[0]][tupl[2]].append((str(route.prefix), conv_geo))

failed = 0
for from_peer in updates.keys():
    for to_peer in updates[from_peer].keys():

        # print(sorted(updates[from_peer][to_peer], key=lambda x: x[0]))
        # print(sorted(updates[to_peer][from_peer], key=lambda x: x[0]))

        a_routes = set([i for i, _ in updates[from_peer][to_peer]])
        b_routes = set([i for i, _ in updates[to_peer][from_peer]])

        a_attr = set([j for _, j in updates[from_peer][to_peer]])
        b_attr = set([j for _, j in updates[to_peer][from_peer]])

        assert len(a_routes) == len(updates[from_peer][to_peer]), \
            "Expected %d, but %d received" % (len(updates[from_peer][to_peer]), len(a_routes))
        assert len(b_routes) == len(updates[to_peer][from_peer]), \
            "Expected %d, but %d received" % (len(updates[to_peer][from_peer]), len(b_routes))

        diff_route = a_routes.difference(b_routes)
        diff_attr = a_attr.difference(b_attr)

        if len(diff_route) != 0:
            print("Missing routes %s <--> %s" % (from_peer, to_peer))
            print("Correct was %s" % a_routes.intersection(b_routes))

        if len(diff_attr) != 0:
            print("Attribute mismatch %s <--> %s (%d)" % (from_peer, to_peer, len(diff_attr)))
            print("Correct was %s" % a_attr.intersection(b_attr))

print(failed)
