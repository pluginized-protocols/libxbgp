#!/usr/bin/env sh

if [ "$(id -u)" != "0" ]; then
	echo "This script must be run as root" 1>&2
	exit 1
fi



ip link add name br0 type bridge
ip addr add 10.21.42.1/24 broadcast 10.21.42.255 dev br0

# ip link set eth1 master br0
# ip link set dev eth1 up

ip netns add rusty
ip netns add bird

ip link add name birdnet type veth peer name veth0
ip link set veth0 netns rusty


ip link add name rustynet type veth peer name birdnet0
ip link set birdnet0 netns bird


ip netns exec rusty ip addr add 10.21.42.4/24 broadcast 10.21.42.255 dev veth0
ip netns exec rusty ip link set dev lo up
ip netns exec rusty ip link set dev veth0 up

ip netns exec bird ip addr add 10.21.42.5/24 broadcast 10.21.42.255 dev birdnet0
ip netns exec bird ip link set dev lo up
ip netns exec bird ip link set dev birdnet0 up

ip link set rustynet master br0
ip link set birdnet master br0
ip link set dev rustynet up
ip link set dev birdnet up
ip link set dev br0 up
