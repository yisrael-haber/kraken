#!/usr/bin/env python3
import argparse
import socket
import threading


def tcp_peer(listener, errors):
    try:
        connection, address = listener.accept()
        with connection:
            data = b""
            while len(data) < len(b"kraken tcp\n"):
                chunk = connection.recv(len(b"kraken tcp\n") - len(data))
                if not chunk:
                    raise RuntimeError(f"TCP peer closed before its request from {address}")
                data += chunk
            if data != b"kraken tcp\n":
                raise RuntimeError(f"unexpected TCP payload from {address}: {data!r}")
            print(f"TCP request from {address}: {data!r}")
            connection.sendall(b"tcp ok\n")
    except Exception as error:
        errors.append(error)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", required=True, help="host IPv4 address")
    parser.add_argument("--port", type=int, default=19090)
    args = parser.parse_args()

    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind((args.bind, args.port))
    tcp.listen(1)

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind((args.bind, args.port))

    errors = []
    thread = threading.Thread(target=tcp_peer, args=(tcp, errors))
    thread.start()
    print(f"Listening on {args.bind}:{args.port} for TCP and UDP")

    data, address = udp.recvfrom(32 * 1024)
    if data != b"kraken udp":
        raise RuntimeError(f"unexpected UDP payload from {address}: {data!r}")
    print(f"UDP request from {address}: {data!r}")
    udp.sendto(b"udp ok", address)
    thread.join()
    tcp.close()
    udp.close()
    if errors:
        raise errors[0]
    print("socket experiment passed")


if __name__ == "__main__":
    main()
