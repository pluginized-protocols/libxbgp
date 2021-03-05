#! /usr/bin/env python3

import socket
import select

NETWORK_ORDER = 'big'


def make_the_super_calculation(skp: (socket, (str, str))):
    # fetch the 32-bits integer from the plugin
    sk = skp[0]

    try:
        data = sk.recv(4)
    except ConnectionError as e:
        print("peer [%s]:%s has been disconnected (%s)" % (skp[1][0], skp[1][1], e.strerror))
        return

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
        fd_socket[skfd][0].close()
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
            if sfd == server.fileno():
                conn, addr = server.accept()
                poll_man.register(conn.fileno(), select.POLLIN | select.POLLHUP | select.POLLERR)
                print("Connected to [%s]:%d" % (addr[0], addr[1]))

                # adding new socket to our DB
                fd_socket[conn.fileno()] = (conn, addr)

            elif evt & select.POLLHUP:
                print("[%s]:%s has hung up !" % (fd_socket[sfd][1][0], fd_socket[sfd][1][1]))
                unregister_fd(sfd)
            elif evt & select.POLLERR:
                print("Socket error for peer [%s]:%s. Abort connection" %
                      (fd_socket[sfd][1][0], fd_socket[sfd][1][1]))
                unregister_fd(sfd)
            else:
                make_the_super_calculation(fd_socket[sfd])
                unregister_fd(sfd)


if __name__ == '__main__':
    main()
