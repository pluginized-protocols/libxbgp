#!/usr/bin/env bash

if [ "$EUID" -ne 0 ]; then 
  echo "Please run as root"
  exit
fi

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

NETNS_NAME="frrouting"
BR_NAME="br0"


# add network namespace
ip netns add $NETNS_NAME

# create bridge interface
ip link add name $BR_NAME type bridge
provision-iface $BR_NAME "10.21.42.1/24"


# add veth
ip link add dev frr-net0 type veth peer name frr-eth0
# and set one veth to the netns
ip link set frr-eth0 netns $NETNS_NAME
# put the remaining veth as part of br0
ip link set frr-net0 master $BR_NAME

# assign IP addr to the namespace and activate the interfaces
provision-iface "frr-eth0" "10.21.42.4/24" $NETNS_NAME
provision-iface "lo" "" $NETNS_NAME


# activate the other veth
ip link set dev frr-net0 up

# create second network namespace
ip netns add exabgp
ip link add dev frr-eth1 type veth peer name exa-eth0
ip link set frr-eth1 netns $NETNS_NAME
ip link set exa-eth0 netns exabgp

provision-iface "exa-eth0" "10.21.43.2/24" "exabgp"
provision-iface "frr-eth1" "10.21.43.4/24" "$NETNS_NAME"
