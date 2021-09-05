import calendar
import json
import math
import random
import sys
import time
from contextlib import closing
from ipaddress import ip_network, IPv6Network, IPv4Network
import re


def gen_cloudlare_like_json(valided_prefixes):
    roas_list = list()
    counts = 0

    generated_time = calendar.timegm(time.gmtime())
    valid_until = generated_time + 31556926  # valid one year

    rpki_roas = {
        "metadata": {
            "counts": -1,
            "generated": generated_time,
            "valid": valid_until,
            # "signature": "666",
            # "signatureDate": "666"
        },
        "roas": roas_list
    }

    for ip_addr in valided_prefixes:
        counts += 1
        for len_vrp, max_len, origin_as in valided_prefixes[ip_addr]:
            roas_list.append({
                'prefix': "%s/%d" % (str(ip_addr), len_vrp),
                'maxLength': max_len,
                'asn': "AS%d" % origin_as,
                'ta': "FieuNet - Test"
            })

            rpki_roas['metadata']['counts'] = counts

    with closing(open("my_validated_roas.json", 'w')) as f:
        json.dump(rpki_roas, f)


def main(file_path, valid_ratio):
    assert 0 < valid_ratio <= 1.0

    pfxes = set()
    f_dict = dict()
    formatted_dict = {
        "conf": {
            "allowed_prefixes": {
                "type_arg": "dict",
                "arg": f_dict
            }
        }
    }
    pat_re = re.compile(r"{(\d+,)*(?P<last_as>\d+)}")

    agg = 0

    with open(file_path, "r") as f:
        for line in f:
            l_strip = line.strip()
            p = l_strip.split('|')

            if p[2] == "A":
                sp = p[6].split()

                m = pat_re.search(sp[-1])

                if m is not None:
                    # This prefix is originated from an aggregated
                    # AS, don't include them in the RPKI DB
                    agg += 1
                    # origin_as = int(m.group('last_as'))
                else:
                    origin_as = int(sp[-1])

                pfxes.add((ip_network(p[5]), origin_as))

    print("Agg %d" % agg)

    real_nb_valid_rte = math.ceil(len(pfxes) * valid_ratio)
    valid_routes = random.sample(pfxes, real_nb_valid_rte)

    invalid = 0
    dict_form = dict()

    for ip_net, origin_as in valid_routes:
        if ip_net.network_address not in dict_form:
            dict_form[ip_net.network_address] = set()

        dict_form[ip_net.network_address].add((ip_net.prefixlen, ip_net.prefixlen, origin_as))

    for ip_addr in dict_form:
        if str(ip_addr) not in f_dict:
            f_dict[str(ip_addr)] = {
                "type_arg": "list",
                "arg": [
                    {
                        "type_arg": "list",
                        "arg": [
                            {"type_arg": "int", "arg": int(len_vrp)},
                            {"type_arg": "int", "arg": int(max_len)},
                            {"type_arg": "int", "arg": int(origin_as)},
                        ]
                    } for len_vrp, max_len, origin_as in dict_form[ip_addr]
                ]
            }

    print("Total Routes %d, sampled %d, invalid %d" % (len(pfxes), len(valid_routes), invalid))

    with open("rpki_valid", 'w') as out:
        json.dump(formatted_dict, out)

    print("Generating Cloudflare Like json")
    gen_cloudlare_like_json(dict_form)


if __name__ == '__main__':
    main("../experiments/data/updatedump.txt", 0.75)
