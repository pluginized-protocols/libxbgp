#! /usr/bin/env python3

import socket

NETWORK_ORDER = 'big'


class Record(object):
    def __init__(self, _type, val):
        self.type = _type

        if _type == 1:
            self.value = int.from_bytes(value[0:4], byteorder=NETWORK_ORDER)
        else:
            self.value = val

    def __str__(self) -> str:
        return "Record(type: %d, value : %s)" % (self.type, self.value)


while True:
    server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('', 6789))
    server.listen(1)
    conn, addr = server.accept()

    print("Connected to [%s]:%d" % (addr[0], addr[1]))

    while True:
        data = conn.recv(4)
        if len(data) == 0:
            print("Connection with [%s]:%d closed" % (addr[0], addr[1]))
            break

        nb_records = int.from_bytes(data, byteorder=NETWORK_ORDER)

        for _ in range(nb_records):
            hdr = conn.recv(8)
            assert len(hdr) == 8, "Mismatch size: expected 8 actual: %d" % len(hdr)
            hdr_type = int.from_bytes(hdr[0:4], byteorder=NETWORK_ORDER)
            hdr_length = int.from_bytes(hdr[4:8], byteorder=NETWORK_ORDER)
            value = conn.recv(hdr_length)
            assert len(value) == hdr_length, "Mismatch size: expected %d, actual: %d" % (hdr_length, len(value))

            print(Record(hdr_type, value))
