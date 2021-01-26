#!/usr/bin/env bash

if [ "$EUID" -ne 0 ]; then 
  echo "Please run as root"
  exit
fi


BR_NAME="br0"

# namespace -> nb interfaces
declare -A NB_IFACES

# $1: ns name
function inc_iface {
    if [ ! "${NB_IFACES[$1]+isset}" ]; then
        create-ns "$1"
    fi
    __ret="${1}-eth${NB_IFACES[$1]}"
    ((++NB_IFACES[$1]))
}

## $1 interface name
## $2 ip address
## $3 namespace
function provision-iface () {

  local netns_str=""

  if [ -n "${3}" ]; then
    netns_str=("ip netns exec $3")
  fi

  if [ -n "${2}" ]; then
    ${netns_str[0]} ip addr add "${2}" dev "${1}"
  fi

  ${netns_str[0]} ip link set dev "${1}" up
}

## $1 namespace name
function create-ns () {
  NB_IFACES[$1]=0
  ip netns add ${1}
  provision-iface "lo" "" ${1}
}

## $1 veth interface name
## $2 ns name
function mv-ns () {
  ip link set dev "$1" netns "$2"
  ip netns exec "$2" ip link set dev "$1" up
}

## $1 iface name 1
## $2 iface name 2
function make-veth () {
  ip link add dev "$1" type veth peer name "$2"
}

## $1 namespace 1
## $2 namespace 2
function make-link () {

  inc_iface "$1"
  local r1="$__ret"

  inc_iface "$2"
  local r2="$__ret"

  # add veth
  make-veth "$r1" "$r2"

  # set one veth to the first netns
  mv-ns "$r1" "$1"
  # and do the same for the second netns
  mv-ns "$r2" "$2"
}

# $1 bridge interface name
function create-bridge () {
  ip link add name "$1" type bridge
  ip link set dev "$1" up
}

## $1 bridge name
## $2 ns name
## $3 iface name attached to the bridge
## $4 iface name attached to the ns
function ns-to-bridge () {

  make-veth "$3" "$4"

  mv-ns "$4" "$2"

  if ! ip link show dev "$BR" &> /dev/null ; then
    create-bridge "$1"
  fi

  ip link set "$3" master "$1"
  ip link set "$3" up
}


#       +--------+
#       | exabgp |
#       +--------+
#            |eth0 .2
#            |
#            |10.21.43.0/24
#            |
#          .2|eth1
#      +-----------+  10.21.42.0/24  +------+
#      | frrouting +-----------------+ bird |
#      +-----------+eth0         eth0+------+
#    .2 ebr0 |      .1             .2
#            |
#            | 10.21.44.0/24
#            |
#    .1 net0 |
#     +-------------+
#     | bridge host |
#     +-------------+

make-link "bird1" "bird2"

provision-iface "bird1-eth0" "10.21.42.1/24" "bird1"
provision-iface "bird2-eth0" "10.21.42.2/24" "bird2"

exit 0

# create and make links between namespaces
make-link "frrouting" "bird"
make-link "frrouting" "exabgp"

ns-to-bridge "$BR_NAME" "frrouting" "frr-net0" "frrouting-ebr0"


# provision namespaces interfaces
provision-iface "frrouting-eth0" "10.21.42.1/24" "frrouting"
provision-iface "frrouting-eth1" "10.21.43.1/24" "frrouting"
provision-iface "frrouting-ebr0" "10.21.44.2/24" "frrouting"

provision-iface  "frrouting-eth0" "c1a4:4ad:42::1/64" "frrouting"
provision-iface  "frrouting-eth1" "c1a4:4ad:43::1/64" "frrouting"

provision-iface "bird-eth0" "10.21.42.2/24" "bird"
provision-iface "bird-eth0" "c1a4:4ad:42::2/64" "bird"

provision-iface "exabgp-eth0" "10.21.43.2/24" "exabgp"
provision-iface "exabgp-eth0" "c1a4:4ad:43::2/64" "exabgp"

provision-iface "$BR_NAME" "10.21.44.1/24"