#!/usr/bin/env bash

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit
fi

ip addr add 10.21.42.3/dev eth1
ip link set dev eth1 up