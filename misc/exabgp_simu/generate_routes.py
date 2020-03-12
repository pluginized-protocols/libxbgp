#! /usr/bin/env python3

import ipaddress
import itertools
import math
import random
import sys

__MAX_UINT32_ = 4294967295


class ExaList(object):

    def __init__(self, lst):
        assert isinstance(lst, list), "%s is not a list :'(" % lst
        self.lst = lst

    def __str__(self) -> str:
        return "[ %s ]" % ' '.join([str(it) for it in self.lst])

    def __repr__(self):
        return self.__str__()


class BGPAttributeFlags(object):

    @staticmethod
    def to_hex_flags(a, b, c, d):
        return (((a << 3) & 8) | ((b << 2) & 4) | ((c << 1) & 2) | (d & 1)) << 4

    def __init__(self, optional, transitive, partial, extended):
        allowed_vals = {0, 1}
        assert optional in allowed_vals
        assert transitive in allowed_vals
        assert partial in allowed_vals
        assert extended in allowed_vals

        self.optional = optional
        self.transitive = transitive
        self.partial = partial
        self.extended = extended

        self._hex = self.to_hex_flags(self.optional, self.transitive, self.partial, self.extended)

    def __str__(self):
        return f"0X{self._hex:X}"

    def __repr__(self):
        return "BGPAttributeFlags(opt=%d, transitive=%d, partial=%d, ext=%d, _hex=%s (%s))" % (
            self.optional, self.transitive, self.partial, self.extended, hex(self._hex), bin(self._hex))


class BGPAttribute(object):
    def __init__(self, attr_type, val, flags=None):
        self.flags = flags
        self.type = attr_type
        self.val = val

    def __str__(self):
        if self.flags is None:
            return "%s %s" % (self.type, self.val)
        else:
            return "attribute [ %s %s %s ]" % (self.type if isinstance(self.type, str) else f"0X{self.type:X}",
                                               str(self.flags),
                                               str(self.val))

    def __repr__(self) -> str:
        return "BGPAttribute(attr_type=%s, val=%s%s)" % \
               (self.type, self.val,
                " flags=" + str(self.flags) if self.flags is not None else "")


class GeoTags(object):

    @staticmethod
    def encode_number(a):
        if a < 0:
            negative = 1
        else:
            negative = 0

        a = abs(a)

        if len(format(a, 'b')) > 31:
            raise OverflowError("Coordinates must be encoded with at most 31 bits")
        if not negative:
            return a, negative

        return (a | 0x80000000), negative  # put the most significant bit to 1

    def concat_or_die(self):
        if len(format(self.latitude, 'b')) > 32 or len(format(self.latitude, 'b')) > 32:
            raise OverflowError("Coordinate encoding failure: more than 32 bits per coordinates")

        conc = (self.latitude << 32) | (self.longitude & 0xffffffff)

        if len(format(conc, 'b')) > 64:
            raise OverflowError("Coordinate encoding failure: the concatenation of "
                                "coordinates uses more than 64 bits to be represented")

        return conc

    def __init__(self, latitude, longitude):
        assert -180.0 <= latitude <= 180.0
        assert -180.0 <= longitude <= 180.0

        self.latitude, self._lat_neg = self.encode_number(math.floor(latitude * 10000000))
        self.longitude, self._long_neg = self.encode_number(math.floor(longitude * 10000000))

    def __str__(self):
        return "%s" % ('{0:#0{1}X}'.format(self.concat_or_die(), 18))
        # 64 bits are represented with 16 exa decimal number. The first '0X' are counted to the
        # format function. They are two characters long. So 16 + 2 = 18

    def __repr__(self):
        return "GeoTags(latitude=%s%s, longitude=%s%s)" % (self.latitude, "*" if self._lat_neg else "",
                                                           self.longitude, "*" if self._long_neg else "")


class BGPRoute(object):

    def __init__(self, network, attributes):
        self.IPNetwork = network
        self.attributes = attributes

    def __str__(self):
        route = "route %s" % self.IPNetwork
        for attr in self.attributes:
            route += " %s" % attr
        return route


def parse_iptable(file_path):
    iptables = []
    default_rte = ipaddress.IPv4Network('0.0.0.0/0')
    with open(file_path) as f:
        for line in f:
            parsed_net = ipaddress.ip_network(line.strip())
            if default_rte != parsed_net:
                iptables.append(ipaddress.ip_network(line.strip()))

    return iptables


def parse_iptables_stream(stream):
    net_table = []
    default_rte = ipaddress.IPv4Network('0.0.0.0/0')

    for line in stream:
        parsed_net = ipaddress.ip_network(line.strip())
        if default_rte != parsed_net:
            net_table.append(ipaddress.ip_network(line.strip()))

    return net_table


def random_coordinate():
    return random.uniform(-180.0, 180.0), random.uniform(-180.0, 180.0)


def list_of_rnd_lists(nb, max_sub_rnd_list):
    def random_gen(low, high):
        while True:
            yield random.randrange(low, high)

    rnd_lists = []

    for _ in range(0, nb):
        rnd_set = set()
        gen = random_gen(1, 65536)
        rnd_path_len = random.randint(1, max_sub_rnd_list)

        # Try to add elem to set until set length is less than 'rnd_path_len'
        for x in itertools.takewhile(lambda y: len(rnd_set) <= rnd_path_len, gen):
            rnd_set.add(x)

        rnd_lists.append(list(rnd_set))

    return rnd_lists


def rnd_list(max_sub_rnd_list, strict=False):
    def random_gen(low, high):
        while True:
            yield random.randrange(low, high)

    rnd_set = set()
    gen = random_gen(1, 65536)
    rnd_path_len = random.randint(1, max_sub_rnd_list) if not strict else max_sub_rnd_list

    for x in itertools.takewhile(lambda y: len(rnd_set) <= rnd_path_len, gen):
        rnd_set.add(x)

    return list(rnd_set)


def build_bgp_route(ip_networks):
    for ip_network in ip_networks:
        rnd_coord = random_coordinate()

        next_hop = BGPAttribute("next-hop", "self")
        as_path = BGPAttribute("as-path", ExaList(rnd_list(random.randint(1, 25))))
        geo_tags = BGPAttribute(42, GeoTags(rnd_coord[0], rnd_coord[1]), BGPAttributeFlags(1, 0, 0, 0))
        communities = BGPAttribute("community",
                                   ExaList(["%d:%d" % (j, k) for j, k in zip(rnd_list(24, True), rnd_list(24, True))]))
        med = BGPAttribute("med", random.randint(1, __MAX_UINT32_))
        origin = BGPAttribute("origin", random.choice(["igp", "egp", "incomplete"]))

        yield BGPRoute(ip_network, [next_hop, origin, med, as_path, geo_tags, communities])


if __name__ == '__main__':

    if len(sys.argv) != 2:
        exit(1)

    network_table = parse_iptable(sys.argv[1])
    rtes = build_bgp_route(network_table)

    for i in rtes:
        print("announce %s" % i)
