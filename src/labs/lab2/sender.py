"""Отправитель H.264: FFmpeg кодирует вход, УПВ-1 передает access unit по UDP."""
from __future__ import annotations

import argparse
import logging
import resource
import select
import socket
import subprocess
import time
from typing import BinaryIO, Iterator

from .protocol import FLAG_ACK, FLAG_RELIABLE, Packet, decode, encode, fragment

LOG = logging.getLogger("upv1.sender")


def access_units(data: bytes) -> list[bytes]:
    """Разделяет Annex-B поток по AUD NAL (FFmpeg запускается с aud=1)."""
    starts: list[tuple[int, int]] = []
    i = 0
    while i + 4 < len(data):
        if data[i:i + 4] == b"\0\0\0\1":
            starts.append((i, 4)); i += 4
        elif data[i:i + 3] == b"\0\0\1":
            starts.append((i, 3)); i += 3
        else:
            i += 1
    boundaries = [pos for pos, n in starts if pos + n < len(data) and data[pos + n] & 0x1F == 9]
    if not boundaries:
        raise ValueError("H.264 stream has no AUD NAL units; use FFmpeg encoder with aud=1")
    units = [data[boundaries[j]:boundaries[j + 1]] for j in range(len(boundaries) - 1)]
    units.append(data[boundaries[-1]:])
    return [unit for unit in units if unit]


def iter_access_units(stream: BinaryIO, chunk_size: int = 65536) -> Iterator[bytes]:
    """Потоково выделяет access unit Annex-B по AUD, не читая весь файл в память."""
    buffer = bytearray()
    scan = 0
    found_aud = False
    while chunk := stream.read(chunk_size):
        buffer.extend(chunk)
        while scan + 4 < len(buffer):
            if buffer[scan:scan + 4] == b"\0\0\0\1":
                prefix = 4
            elif buffer[scan:scan + 3] == b"\0\0\1":
                prefix = 3
            else:
                scan += 1
                continue
            nal = scan + prefix
            if nal >= len(buffer):
                break
            if buffer[nal] & 0x1F == 9:
                if found_aud and scan:
                    yield bytes(buffer[:scan])
                    del buffer[:scan]
                    scan = 0
                    found_aud = False
                    continue
                found_aud = True
            scan = nal + 1
        # The loop stops before the unscanned tail. Keep scan at that position:
        # moving it backwards can see the 3-byte suffix of a 4-byte start code
        # a second time and produce a spurious one-byte access unit.
    if found_aud and buffer:
        yield bytes(buffer)


def has_idr(unit: bytes) -> bool:
    """True when an access unit contains an IDR slice NAL."""
    i = 0
    while i + 3 < len(unit):
        if unit[i:i + 4] == b"\0\0\0\1":
            start = i + 4
        elif unit[i:i + 3] == b"\0\0\1":
            start = i + 3
        else:
            i += 1
            continue
        if start < len(unit) and unit[start] & 0x1F == 5:
            return True
        i = start
    return False


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", help="IPv4 адрес приемника")
    parser.add_argument("input", help="входное видео или устройство, понятное FFmpeg")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--fps", type=int, default=25)
    parser.add_argument("--width", type=int, default=1280)
    parser.add_argument("--height", type=int, default=720)
    parser.add_argument("--loop", action="store_true", help="повторять файл до Ctrl+C")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    command = ["ffmpeg", "-nostdin", "-loglevel", "error", "-re", "-i", args.input,
               "-an", "-vf", f"scale={args.width}:{args.height}:force_original_aspect_ratio=decrease,pad={args.width}:{args.height}:(ow-iw)/2:(oh-ih)/2",
               "-r", str(args.fps), "-c:v", "libx264", "-preset", "ultrafast",
               "-tune", "zerolatency", "-x264-params", "aud=1", "-f", "h264", "pipe:1"]
    destination = (socket.gethostbyname(args.destination), args.port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    packet_id = au_id = 0
    sent_packets = failed_packets = 0
    total_units = total_bytes = 0
    session_started = time.monotonic()
    last_probe = 0.0
    last_ack = time.monotonic()
    ethernet_available: bool | None = None
    try:
        while True:
            process = subprocess.Popen(command, stdout=subprocess.PIPE,
                                       start_new_session=True)
            assert process.stdout is not None
            count = byte_count = 0
            stream_started = time.monotonic()
            try:
                for unit in iter_access_units(process.stdout):
                    now = time.monotonic()
                    stamp = int(now * 1000) & 0xFFFFFFFF
                    if now - last_probe >= 1.0:
                        probe = encode(Packet(FLAG_RELIABLE, packet_id, 0xFFFFFFFF,
                                              0, 1, stamp, b""))
                        try:
                            sock.sendto(probe, destination)
                        except OSError as exc:
                            LOG.warning("Ethernet probe failed: %s", exc)
                        packet_id += 1
                        last_probe = now
                    while select.select([sock], [], [], 0)[0]:
                        response, address = sock.recvfrom(2048)
                        if address != destination:
                            continue
                        try:
                            ack = decode(response)
                        except ValueError:
                            continue
                        if ack.flags == FLAG_ACK and ack.access_unit_id == 0xFFFFFFFF:
                            last_ack = now
                            if ethernet_available is not True:
                                ethernet_available = True
                                LOG.info("ПРОВОДНОЙ_КАНАЛ_ДОСТУПЕН")
                    if now - last_ack > 3.0 and ethernet_available is not False:
                        ethernet_available = False
                        LOG.warning("ПРОВОДНОЙ_КАНАЛ_ПОТЕРЯН")
                    datagrams = fragment(unit, au_id, packet_id, stamp, has_idr(unit))
                    for datagram in datagrams:
                        try:
                            sock.sendto(datagram, destination)
                            sent_packets += 1
                        except OSError as exc:
                            failed_packets += 1
                            if failed_packets == 1 or failed_packets % 100 == 0:
                                LOG.warning("UDP send failed (%d total): %s", failed_packets, exc)
                    packet_id += len(datagrams)
                    au_id += 1
                    count += 1
                    byte_count += len(unit)
                    total_units += 1
                    total_bytes += len(unit)
                    if count % max(1, args.fps * 10) == 0:
                        elapsed = max(time.monotonic() - stream_started, 0.001)
                        usage = resource.getrusage(resource.RUSAGE_SELF)
                        LOG.info("AU=%d AU_total=%d H264_bytes=%d H264_bytes_total=%d fps=%.2f useful_bps=%.0f UDP_sent=%d UDP_failed=%d cpu_s=%.2f maxrss_kib=%d Ethernet=%s LoRa=not_configured",
                                 count, total_units, byte_count, total_bytes,
                                 count / elapsed, byte_count * 8 / elapsed,
                                 sent_packets, failed_packets, usage.ru_utime + usage.ru_stime,
                                 usage.ru_maxrss, ethernet_available)
            except KeyboardInterrupt:
                process.terminate()
                raise
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait()
                process.stdout.close()
            return_code = process.wait()
            if return_code:
                raise subprocess.CalledProcessError(return_code, command)
            LOG.info("input ended: sent %d access units (%d H.264 bytes)", count, byte_count)
            if not args.loop:
                break
    except KeyboardInterrupt:
        LOG.info("sender stopped")
    except subprocess.CalledProcessError as exc:
        LOG.error("FFmpeg failed with exit code %d", exc.returncode)
    finally:
        elapsed = max(time.monotonic() - session_started, 0.001)
        LOG.info("SESSION duration_s=%.3f AU_total=%d H264_bytes_total=%d fps=%.2f useful_bps=%.0f UDP_sent=%d UDP_failed=%d",
                 elapsed, total_units, total_bytes, total_units / elapsed,
                 total_bytes * 8 / elapsed, sent_packets, failed_packets)
        sock.close()


if __name__ == "__main__":
    main()
