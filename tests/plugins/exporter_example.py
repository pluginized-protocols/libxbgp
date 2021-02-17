#! /usr/bin/env python3

import socket
import select

NETWORK_ORDER = 'big'


def make_the_super_calculation(sk: socket):
    # fetch the 32-bits integer from the plugin
    data = sk.recv(4)

    if len(data) == 0:
        return

    remote_int = int.from_bytes(data, byteorder=NETWORK_ORDER)

    # send the value back + 20
    snd_data = int.to_bytes(remote_int + 20, 4, NETWORK_ORDER, signed=False)
    sk.send(snd_data)

    # close the connection
    sk.close()


def main():
    fd_socket = dict()

    def unregister_fd(skfd):
        poll_man.unregister(skfd)
        del fd_socket[skfd]

    poll_man = select.poll()
    server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('::1', 6789))
    server.listen(1)

    poll_man.register(server, select.POLLIN)

    fd_socket[server.fileno()] = server

    while True:
        fd_event = poll_man.poll()
        for sfd, evt in fd_event:
            print(sfd, evt)
            if sfd == server.fileno():
                conn, addr = server.accept()
                poll_man.register(conn.fileno(), select.POLLIN | select.POLLHUP)
                print("Connected to [%s]:%d" % (addr[0], addr[1]))

                # adding new socket to our DB
                fd_socket[conn.fileno()] = conn

            elif evt == select.POLLHUP:
                print("Hang up !")
                unregister_fd(sfd)
            else:
                make_the_super_calculation(fd_socket[sfd])
                unregister_fd(sfd)


if __name__ == '__main__':
    main()
