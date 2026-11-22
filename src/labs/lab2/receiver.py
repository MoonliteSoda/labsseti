"""Приёмник УПВ-1: собирает access unit и передаёт полные единицы декодеру."""
from __future__ import annotations

import argparse
from collections import deque
import logging
import resource
import socket
import subprocess
import time

from .assembly import AccessUnitAssembler, CompleteUnit
from .protocol import FLAG_ACK, FLAG_RELIABLE, Packet, decode, encode

LOG = logging.getLogger("upv1.receiver")


def _send_ack(sock: socket.socket, address: tuple, packet: Packet) -> None:
    ack = Packet(FLAG_ACK, packet.packet_id, packet.access_unit_id,
                 packet.fragment_index, packet.fragment_count,
                 packet.timestamp_ms, b"")
    try:
        sock.sendto(encode(ack), address)
    except OSError as exc:
        LOG.warning("could not send ACK to %s:%s: %s", *address[:2], exc)


def serve(host: str, port: int, output: str, timeout: float,
          decode_video: bool = False) -> None:
    assembler = AccessUnitAssembler(timeout)
    reliable_completed: set[tuple[str, int, int]] = set()
    reliable_history: deque[tuple[str, int, int]] = deque()
    received = completed = invalid = received_bytes = 0
    highest_packet_id = -1
    missing_packet_ids: set[int] = set()
    expired_gaps = 0
    started = last_report = time.monotonic()
    def start_decoder() -> subprocess.Popen:
        process = subprocess.Popen(
            ["ffmpeg", "-nostdin", "-loglevel", "error", "-f", "h264",
             "-i", "pipe:0", "-f", "null", "-"], stdin=subprocess.PIPE,
            start_new_session=True,
        )
        LOG.info("FFmpeg decoder started")
        return process

    decoder = start_decoder() if decode_video else None
    try:
        with open(output, "wb") as stream, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))
            sock.settimeout(0.2)
            LOG.info("listening on %s:%d -> %s", host, port, output)

            def deliver(units: list[CompleteUnit]) -> None:
                nonlocal completed, received_bytes, decoder
                for unit in units:
                    stream.write(unit.data)
                    stream.flush()
                    if decode_video and decoder is not None and decoder.poll() is not None:
                        decoder = None
                    if decode_video and decoder is None and unit.keyframe:
                        decoder = start_decoder()
                    if decoder is not None and decoder.stdin is not None:
                        try:
                            decoder.stdin.write(unit.data)
                            decoder.stdin.flush()
                        except BrokenPipeError:
                            LOG.warning("decoder pipe closed; waiting for next keyframe")
                            decoder = None
                    completed += 1
                    received_bytes += len(unit.data)

            while True:
                now = time.monotonic()
                if now - last_report >= 10.0:
                    usage = resource.getrusage(resource.RUSAGE_SELF)
                    elapsed = max(now - started, 0.001)
                    LOG.info("UDP_received=%d UDP_missing_estimate=%d AU_complete=%d AU_incomplete=%d invalid=%d H264_bytes=%d fps=%.2f useful_bps=%.0f cpu_s=%.2f maxrss_kib=%d Ethernet=receiving LoRa=not_configured",
                             received, expired_gaps + len(missing_packet_ids), completed,
                             assembler.incomplete_dropped, invalid,
                             received_bytes, completed / elapsed, received_bytes * 8 / elapsed,
                             usage.ru_utime + usage.ru_stime, usage.ru_maxrss)
                    last_report = now
                before = assembler.incomplete_dropped
                deliver(assembler.tick(now))
                if assembler.incomplete_dropped != before:
                    LOG.warning("incomplete AU discarded: total=%d",
                                assembler.incomplete_dropped)
                try:
                    datagram, address = sock.recvfrom(65535)
                except socket.timeout:
                    continue
                except OSError as exc:
                    LOG.warning("UDP receive failed: %s", exc)
                    time.sleep(0.2)
                    continue
                try:
                    packet = decode(datagram)
                except ValueError as exc:
                    invalid += 1
                    LOG.warning("invalid datagram: %s", exc)
                    continue
                if packet.flags == FLAG_ACK:
                    continue
                if highest_packet_id >= 0 and packet.packet_id > highest_packet_id + 1:
                    start = highest_packet_id + 1
                    if packet.packet_id - start > 4096:
                        expired_gaps += packet.packet_id - start - 4096
                        start = packet.packet_id - 4096
                    missing_packet_ids.update(range(start, packet.packet_id))
                highest_packet_id = max(highest_packet_id, packet.packet_id)
                missing_packet_ids.discard(packet.packet_id)
                cutoff = highest_packet_id - 4096
                old_gaps = {number for number in missing_packet_ids if number < cutoff}
                expired_gaps += len(old_gaps)
                missing_packet_ids.difference_update(old_gaps)
                received += 1
                if (packet.flags == FLAG_RELIABLE and packet.access_unit_id == 0xFFFFFFFF
                        and not packet.payload):
                    _send_ack(sock, address, packet)
                    continue
                sender_key = (address[0], address[1], packet.access_unit_id)
                if packet.flags & FLAG_RELIABLE and sender_key in reliable_completed:
                    _send_ack(sock, address, packet)
                    continue
                units = assembler.accept(packet, now)
                deliver(units)
                if packet.flags & FLAG_RELIABLE and any(
                    unit.number == packet.access_unit_id for unit in units
                ):
                    reliable_completed.add(sender_key)
                    reliable_history.append(sender_key)
                    if len(reliable_history) > 4096:
                        reliable_completed.discard(reliable_history.popleft())
                    _send_ack(sock, address, packet)
                if received % 1000 == 0:
                    LOG.info("packets=%d complete_AU=%d incomplete_dropped=%d pending=%d",
                             received, completed, assembler.incomplete_dropped,
                             len(assembler.partial))
    finally:
        elapsed = max(time.monotonic() - started, 0.001)
        LOG.info("SESSION duration_s=%.3f UDP_received=%d UDP_missing_estimate=%d AU_complete=%d AU_incomplete=%d invalid=%d H264_bytes=%d fps=%.2f useful_bps=%.0f",
                 elapsed, received, expired_gaps + len(missing_packet_ids),
                 completed, assembler.incomplete_dropped, invalid, received_bytes,
                 completed / elapsed, received_bytes * 8 / elapsed)
        if decoder is not None:
            if decoder.stdin is not None:
                try:
                    decoder.stdin.close()
                except BrokenPipeError:
                    pass
            return_code = decoder.wait()
            LOG.info("FFmpeg decoder stopped with exit code %d", return_code)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--output", default="received.h264")
    parser.add_argument("--assembly-timeout", type=float, default=2.0)
    parser.add_argument("--decode", action="store_true",
                        help="передавать полные access unit FFmpeg-декодеру в реальном времени")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        serve(args.host, args.port, args.output, args.assembly_timeout, args.decode)
    except KeyboardInterrupt:
        LOG.info("receiver stopped")


if __name__ == "__main__":
    main()
