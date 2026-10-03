#!/usr/bin/env python3
"""The host's end of the TFTP experiment, with the standard library only: run it with no
arguments, then run tftp.lua in Kraken.

First it serves Kraken's client requests. When all six have been answered it becomes the
client: it reads kraken.bin from Kraken's server and writes incoming.bin to it, retrying
until Kraken is listening. Every file is a repeating byte pattern (the same one tftp.lua
uses), so each side can check what it received. Option negotiation covers blksize only.
"""
import socket, struct, sys, threading

BIND = "192.168.122.1"
SERVE_PORT = 6969
FILES = {"download.bin": 2500, "exact.bin": 1024}          # name -> size, served on request
UPLOADS = {"upload.bin": 3000, "incoming.bin": 2200}       # name -> size expected back
KRAKEN = {"kraken.bin": 1500}                              # what Kraken serves
KRAKEN_SERVER = ("192.168.122.5", 6970)
REQUESTS = 6                                               # Kraken's client stage: 4 reads (1 refused), 2 writes
finished = threading.Semaphore(0)


def pattern(size):
    return bytes((i * 7 + 3) % 251 for i in range(size))


def op_of(packet):
    return struct.unpack("!H", packet[:2])[0]


def number_of(packet):
    return struct.unpack("!H", packet[2:4])[0]


def ack(block):
    return struct.pack("!HH", 4, block & 0xFFFF)


def error(code, text):
    return struct.pack("!HH", 5, code) + text.encode() + b"\0"


def strings(body):
    return [part.decode() for part in body.split(b"\0")[:-1]]


def oack(options):
    return struct.pack("!H", 6) + b"".join(k.encode() + b"\0" + v.encode() + b"\0" for k, v in options.items())


def new_socket(timeout=3):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((BIND, 0))
    sock.settimeout(timeout)
    return sock


def send_blocks(sock, peer, data, blksize):
    """Lock-step DATA blocks; a final short (possibly empty) block ends the transfer."""
    block, offset = 1, 0
    while True:
        chunk = data[offset:offset + blksize]
        packet = struct.pack("!HH", 3, block & 0xFFFF) + chunk
        for _ in range(5):
            sock.sendto(packet, peer)
            try:
                reply, source = sock.recvfrom(65536)
            except socket.timeout:
                continue
            if source != peer:
                continue
            if op_of(reply) == 5:
                raise RuntimeError(reply[4:-1].decode())
            if op_of(reply) == 4 and number_of(reply) == block & 0xFFFF:
                break
        else:
            raise RuntimeError("no ACK for block %d" % block)
        if len(chunk) < blksize:
            return
        offset, block = offset + blksize, block + 1


def receive_blocks(sock, peer, blksize, first=None):
    """Acknowledge lock-step DATA blocks until a short one; `first` is a packet already read."""
    data, block = b"", 1
    while True:
        if first is not None:
            packet, first = first, None
        else:
            try:
                packet, source = sock.recvfrom(65536)
            except socket.timeout:
                raise RuntimeError("timed out waiting for block %d" % block)
            if source != peer:
                continue
        if op_of(packet) == 5:
            raise RuntimeError(packet[4:-1].decode())
        if op_of(packet) != 3:
            continue
        if number_of(packet) == block & 0xFFFF:
            data += packet[4:]
            sock.sendto(ack(block), peer)
            if len(packet) - 4 < blksize:
                return data
            block += 1
        else:
            sock.sendto(ack(block - 1), peer)


def options_of(fields):
    return {k.lower(): v for k, v in zip(fields[2::2], fields[3::2])}


def handle(request, client):
    """One transfer, from a new socket: its port is this transfer's TID."""
    sock = new_socket()
    op, (name, _mode) = op_of(request), strings(request[2:])[:2]
    options = options_of(strings(request[2:]))
    blksize = int(options.get("blksize", 512))
    reply = {"blksize": str(blksize)} if "blksize" in options else None
    try:
        if op == 1 and name in FILES:
            if reply:
                sock.sendto(oack(reply), client)
                while True:
                    packet, source = sock.recvfrom(65536)
                    if source == client and op_of(packet) == 4 and number_of(packet) == 0:
                        break
            send_blocks(sock, client, pattern(FILES[name]), blksize)
            print("served %s (%d bytes, blksize %d)" % (name, FILES[name], blksize))
        elif op == 1:
            sock.sendto(error(1, "File not found"), client)
            print("refused %s: not found" % name)
        elif op == 2 and name in UPLOADS:
            sock.sendto(oack(reply) if reply else ack(0), client)
            data = receive_blocks(sock, client, blksize)
            status = "OK" if data == pattern(UPLOADS[name]) else "WRONG CONTENT"
            print("stored %s: %d bytes %s" % (name, len(data), status))
        else:
            sock.sendto(error(2, "Access violation"), client)
            print("refused %s" % name)
    except (RuntimeError, socket.timeout) as problem:
        print("transfer of %s failed: %s" % (name, problem))
    finally:
        sock.close()
        finished.release()


def serve():
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind((BIND, SERVE_PORT))
    print("TFTP server on %s:%d; files %s" % (BIND, SERVE_PORT, ", ".join(FILES)))
    while True:
        request, client = listener.recvfrom(65536)
        if op_of(request) in (1, 2):
            threading.Thread(target=handle, args=(request, client), daemon=True).start()


def client(action, name):
    sock = new_socket(timeout=2)
    request = struct.pack("!H", 1 if action == "get" else 2) + name.encode() + b"\0octet\0blksize\0001024\0"
    for _ in range(60):                       # Kraken's server may not be listening yet
        sock.sendto(request, KRAKEN_SERVER)
        try:
            packet, peer = sock.recvfrom(65536)
            break
        except socket.timeout:
            print("waiting for Kraken's server to answer a %s of %s ..." % (action, name))
    else:
        sys.exit("Kraken's server never answered")
    blksize = 512
    if op_of(packet) == 5:
        sys.exit("server: " + packet[4:-1].decode())
    if op_of(packet) == 6:
        blksize = int(options_of(["", ""] + strings(packet[2:]))["blksize"])
    if action == "get":
        if op_of(packet) == 6:
            sock.sendto(ack(0), peer)
            packet = None
        data = receive_blocks(sock, peer, blksize, packet)
        status = "OK" if data == pattern(KRAKEN[name]) else "WRONG CONTENT"
        print("got %s from Kraken: %d bytes %s" % (name, len(data), status))
    else:
        send_blocks(sock, peer, pattern(UPLOADS[name]), blksize)
        print("sent %s to Kraken: %d bytes" % (name, UPLOADS[name]))


if __name__ == "__main__":
    threading.Thread(target=serve, daemon=True).start()
    for _ in range(REQUESTS):
        finished.acquire()
    print("Kraken's client stage is done; now acting as the client of Kraken's server")
    client("get", "kraken.bin")
    client("put", "incoming.bin")
