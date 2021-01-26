#!/usr/bin/env bash

MRT_FILE="mrt_update"
IPV6_NEXTHOP="c1a4:4ad:43::2"

# if [ "$EUID" -ne 0 ]; then
#   echo "Please run as root"
#   exit
# fi

if ! ls /tmp/"$MRT_FILE" &> /dev/null ; then
  gunzip -ck rrc00.updates.20201126.0855.gz > /tmp/"$MRT_FILE"
fi

./mrt2exabgp.py -P -G -6 "$IPV6_NEXTHOP" -4 self /tmp/"$MRT_FILE" > fullbgptable.py

./generate_exabgp_conf.py -P fullbgptable.py -c exabgp_conf.json -o /tmp -p "rt-"