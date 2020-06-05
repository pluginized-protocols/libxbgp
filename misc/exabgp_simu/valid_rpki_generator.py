import json
import math
import random
from ipaddress import ip_network, IPv6Network, IPv4Network
import re


def main(file_path, valid_ratio):
    assert 0 < valid_ratio <= 1.0

    pfxes = set()
    list_rpki_like = []
    formatted_dict = {
        "conf": {
            "allowed_prefixes": {
                "type_arg": "list",
                "arg": list_rpki_like
            }
        }
    }
    pat_re = re.compile(r"{(\d+,)*(?P<last_as>\d+)}")

    with open(file_path, "r") as f:
        for line in f:
            l_strip = line.strip()
            p = l_strip.split('|')

            if p[2] == "A":
                sp = p[6].split()

                m = pat_re.search(sp[-1])

                if m is not None:
                    # I know that the last part of a set is not really
                    # the one that originated the prefix. Let us assume it
                    # now for the sake of simplicity
                    origin_as = int(m.group('last_as'))
                else:
                    origin_as = int(sp[-1])

                pfxes.add((ip_network(p[5]), origin_as))

    real_nb_valid_rte = math.ceil(len(pfxes) * valid_ratio)
    valid_routes = random.sample(pfxes, real_nb_valid_rte)

    for ip_net, origin_as in valid_routes:

        if isinstance(ip_net, IPv4Network):
            ip = {"type_arg": "ipv4_prefix", "arg": str(ip_net)}
        else:
            ip = {"type_arg": "ipv6_prefix", "arg": str(ip_net)}

        list_rpki_like.append({
            "type_arg": "list",
            "arg": [
                {"type_arg": "int", "arg": origin_as},
                ip
            ]
        })

    print("Total Routes %d, valid %d" % (len(pfxes), real_nb_valid_rte))

    with open("rpki_valid", 'w') as out:
        json.dump(formatted_dict, out)


if __name__ == '__main__':
    main("./dump.txt", 0.75)
