#!/usr/bin/env python3
"""Host peer for the protocols/http experiment, over HTTP and HTTPS.

Serves /plain and /chunked to the Kraken identity on a TCP port and a TLS port,
then sends one POST to each of the identity's servers and checks the replies.
TLS uses the lab certificate from src/protocols/testdata (CN and SAN
kraken.test); each side verifies the other's certificate against it. Exits once
both POSTs succeed.
"""

import argparse
import http.server
import pathlib
import socket
import ssl
import threading
import time

TESTDATA = pathlib.Path(__file__).resolve().parents[2] / "src" / "protocols" / "testdata"
CERTIFICATE = TESTDATA / "lab_cert.pem"
KEY = TESTDATA / "lab_key.pem"
# (host server port, Kraken server port) for each transport.
HTTP_PORTS = (19091, 19092)
HTTPS_PORTS = (19093, 19094)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.path == "/plain":
            body = b"plain ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Kraken", "1")
            self.send_header("X-Kraken", "2")
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/chunked":
            self.send_response(200)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for part in (b"chunked ", b"ok"):
                self.wfile.write(b"%x\r\n%s\r\n" % (len(part), part))
            self.wfile.write(b"0\r\n\r\n")
        else:
            self.send_error(404)
            return
        print(f"served {self.path} to {self.client_address[0]}", flush=True)

    def log_message(self, *_):
        pass


def serve(bind, port, context=None):
    server = http.server.ThreadingHTTPServer((bind, port), Handler)
    if context:
        server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()


def post(connect, name):
    """POSTs over the socket `connect()` opens, retrying until Kraken answers."""
    deadline = time.monotonic() + 120
    while True:
        try:
            with connect() as connection:
                connection.sendall(b"POST /echo HTTP/1.1\r\nHost: kraken.test\r\nX-Test: a\r\n"
                                   b"Content-Length: 4\r\nConnection: close\r\n\r\nping")
                reply = b""
                while chunk := connection.recv(4096):
                    reply += chunk
            break
        except OSError:  # includes ssl.SSLError
            if time.monotonic() > deadline:
                raise SystemExit(f"timed out waiting for the Kraken {name} server")
            time.sleep(0.5)
    assert reply.startswith(b"HTTP/1.1 200 ") and reply.endswith(b"\r\n\r\npong"), reply
    print(f"kraken answered over {name}", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", required=True, help="host address the identity can reach")
    parser.add_argument("--kraken", required=True, help="the Kraken identity's IPv4 address")
    args = parser.parse_args()

    server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_tls.load_cert_chain(CERTIFICATE, KEY)
    server_tls.set_alpn_protocols(["http/1.1"])
    client_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_tls.load_verify_locations(CERTIFICATE)
    client_tls.set_alpn_protocols(["http/1.1"])

    serve(args.bind, HTTP_PORTS[0])
    serve(args.bind, HTTPS_PORTS[0], server_tls)
    print(f"serving HTTP on {args.bind}:{HTTP_PORTS[0]} and HTTPS on {args.bind}:{HTTPS_PORTS[0]}; "
          "run the Kraken script now", flush=True)
    post(lambda: socket.create_connection((args.kraken, HTTP_PORTS[1]), timeout=5), "http")
    post(lambda: client_tls.wrap_socket(socket.create_connection((args.kraken, HTTPS_PORTS[1]), timeout=5),
                                        server_hostname="kraken.test"), "https")
    print("http experiment passed (host side)", flush=True)


if __name__ == "__main__":
    main()
