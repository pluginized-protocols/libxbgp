import re
from ipaddress import ip_network


def remove_invalid_prefixes(set_rm, exa_replay_file):
    regexp = re.compile(r"'announce\s*attributes.*nlri\s*(?P<plst>(?:(?:\d{1,3}\.){3}\d{1,3}\/\d{1,2}\s*)+)'")

    with open(exa_replay_file, 'r') as f, open("rm_invalid_fx_trace.py", 'w') as fw:
        for line in f:
            s = re.search(regexp, line)
            if s is not None:
                ip_prefix_list = s.group('plst')
                ip_split = ip_prefix_list.split()

                if len(ip_split) == 1 and ip_network(ip_split[0]) in set_rm:
                    continue

                for ip_pfx in ip_split:
                    if ip_network(ip_pfx) in set_rm:
                        line = line.replace(ip_pfx, '')

            # write to final_file
            fw.write(line)


def main(arg):
    regexp = re.compile(
        r'BGP:\s*RPKI:\s*Validating Prefix\s*(?P<pfx>(?:\d{1,3}\.){3}\d{1,3}\/\d{1,2}).*from asn \d+\s*Result:\s*INVALID')

    invalid_pfxs = set()

    with open(arg, 'r') as f:
        for line in f:
            line = line.strip()
            s = re.search(regexp, line)
            if s is not None:
                ip_prefix = s.group('pfx')
                invalid_pfxs.add(ip_network(ip_prefix))

    print("Nb invalid prefixes %d" % len(invalid_pfxs))

    remove_invalid_prefixes(invalid_pfxs, "announce_full_trace.py")


if __name__ == '__main__':
    main("/home/thomas/Documents/trace_bgp/debug_rpki")
