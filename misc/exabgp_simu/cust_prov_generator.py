import json


def parse_cust_provider_relation():
    cust_prov = dict()

    with open("./20200501.as-rel2.txt", "r") as f:
        for line in f:
            l_strip = line.strip()
            if l_strip[0] == "#":
                continue

            p = l_strip.split('|')

            if int(p[2]) == -1:
                prov = int(p[0])
                if prov not in cust_prov:
                    cust_prov[prov] = list()
                cust_prov[prov].append(int(p[1]))

    return cust_prov


def generate_json_conf():
    cust_prov_list = dict()
    parse_info = parse_cust_provider_relation()
    formatted_json = {
        "conf": {
            "customer_provider": {
                "type_arg": "dict",
                "arg": cust_prov_list
            }
        }
    }

    stat = 0

    for prov in parse_info:
        stat += 1
        cust_prov_list[prov] = {
            "type_arg": "list",
            "arg": [
                {"type_arg": "int", "arg": cust} for cust in parse_info[prov]
            ]
        }

    print("Total Relation %d" % stat)

    with open("valid_customer_provider", "w") as out:
        json.dump(formatted_json, out)


if __name__ == '__main__':
    generate_json_conf()
