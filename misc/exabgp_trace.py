#!/usr/bin/env python3

from mako.template import Template
import random


class Config:
    def __init__(self, d):
        for k, v in d.items():
            if isinstance(v, dict):
                v = Config(v)
            self.__dict__[k] = v


def load_ipv4_table(file):
    table = []
    prefix = 0
    with open(file, 'r') as f:
        for line in f:
            prefix += 1
            table.append(line.strip())

    return prefix, table


def generate_random_list(length, lo, hi, sublist_length_max):
    rnd = []
    for _ in range(length):
        len_sblist = random.randint() % (sublist_length_max + 1)
        rnd.append(random.sample(range(lo, hi + 1), len_sblist))

    return rnd


if __name__ == '__main__':

    lo = 1
    hi = 65536
    max_sbl = 10

    routes = []
    length, table = load_ipv4_table('./v4_full_table_and_default')

    for prefix in table:
        max_l = random.randint(1, max_sbl)
        max_a = random.randint(1, max_sbl)

        v1 = random.sample(range(lo, hi), max_l)
        v2 = random.sample(range(lo, hi), max_l)

        routes.append({
            'prefix': prefix,
            'as_path': '[ %s ]' % ' '.join(str(x) for x in random.sample(range(lo, hi), max_a)),
            'communities': '[ %s ]' % ' '.join(['%s:%s' % (str(i), str(j)) for i, j in zip(v1, v2)])
        })

    mini_routes = random.sample(routes, 10_000)

    template = Template(filename='exabgp.mako')

    with open('exa_mini.conf', 'w') as f:
        f.write(template.render(router=Config({
            'id': '192.168.56.22',
            'ip': '192.168.56.22',
            'asn': '64522',
            'neighbor': {
                'ip': '192.168.56.11',
                'id': '192.168.56.11',
                'asn': '64511'
            },
            'routes': mini_routes
        })))
