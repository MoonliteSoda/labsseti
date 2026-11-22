"""Проверка передачи файла для ЛР-2 через УПВ-1."""
from __future__ import annotations

import argparse
import hashlib
import logging
import os
import socket
import time

from .protocol import FLAG_ACK, MAX_CHUNK, decode, fragment


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination")
    parser.add_argument("file")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--timeout", type=float, default=0.5,
                        help="ожидание подтверждения блока, секунд")
    parser.add_argument("--retries", type=int, default=10,
                        help="число повторов при потере пакета или подтверждения")
    args = parser.parse_args()
    if args.timeout <= 0 or args.retries < 0:
        parser.error("--timeout must be positive and --retries must be non-negative")
    digest_builder = hashlib.sha256()
    with open(args.file, "rb") as source:
        while block := source.read(1024 * 1024):
            digest_builder.update(block)
    digest = digest_builder.hexdigest()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    file_size = os.path.getsize(args.file)
    logging.info("source bytes=%d sha256=%s", file_size, digest)
    family, socktype, proto, _, target = socket.getaddrinfo(
        args.destination, args.port, family=socket.AF_INET, type=socket.SOCK_DGRAM
    )[0]
    sock = socket.socket(family, socktype, proto)
    sock.bind(("0.0.0.0", 0))
    sock.settimeout(args.timeout)
    sent_bytes = sequence = 0
    try:
        with open(args.file, "rb") as source:
            while chunk := source.read(MAX_CHUNK):
                datagram = fragment(chunk, sequence, sequence,
                                    int(time.monotonic() * 1000), reliable=True)[0]
                acked = False
                for attempt in range(args.retries + 1):
                    sock.sendto(datagram, target)
                    deadline = time.monotonic() + args.timeout
                    while True:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            break
                        sock.settimeout(remaining)
                        try:
                            response, address = sock.recvfrom(2048)
                        except socket.timeout:
                            break
                        try:
                            ack = decode(response)
                        except ValueError:
                            continue
                        if (address[0] == target[0] and ack.flags == FLAG_ACK
                                and ack.packet_id == sequence
                                and ack.access_unit_id == sequence and not ack.payload):
                            acked = True
                            break
                    if acked:
                        break
                if not acked:
                    raise TimeoutError(f"no ACK for block {sequence} after {args.retries + 1} attempts")
                sent_bytes += len(chunk)
                sequence += 1
                if sequence % 256 == 0:
                    logging.info("confirmed %d blocks (%d bytes)", sequence, sent_bytes)
    finally:
        sock.close()
    logging.info("transfer complete: bytes=%d blocks=%d", sent_bytes, sequence)


if __name__ == "__main__":
    main()
