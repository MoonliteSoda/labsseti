"""УПВ-1: учебный протокол ЛР-2 для передачи access unit H.264 поверх UDP."""
from __future__ import annotations

import struct
import binascii
from dataclasses import dataclass

MAGIC = b"UP"
VERSION = 1
FLAG_START = 0x01
FLAG_END = 0x02
FLAG_KEYFRAME = 0x04
FLAG_RELIABLE = 0x08
# ACK is only used by the reliable file-check mode; combined flags distinguish
# acknowledgements from ordinary keyframe packets.
FLAG_ACK = FLAG_RELIABLE | FLAG_KEYFRAME
MAX_DATAGRAM = 1400
# 2s magic, H version/flags, I packet, I access unit, H index, H count,
# I timestamp, H payload length, H CRC-16; all multibyte fields are big-endian.
HEADER = struct.Struct("!2sHIIHHIHH")
MAX_CHUNK = MAX_DATAGRAM - HEADER.size


@dataclass(frozen=True)
class Packet:
    flags: int
    packet_id: int
    access_unit_id: int
    fragment_index: int
    fragment_count: int
    timestamp_ms: int
    payload: bytes


def encode(packet: Packet) -> bytes:
    if not 1 <= packet.fragment_count <= 0xFFFF:
        raise ValueError("fragment_count must be in [1, 65535]")
    if not 0 <= packet.fragment_index < packet.fragment_count:
        raise ValueError("invalid fragment_index")
    if len(packet.payload) > MAX_CHUNK:
        raise ValueError(f"payload exceeds {MAX_CHUNK} bytes")
    if packet.flags & ~0x0F:
        raise ValueError("unknown packet flags")
    prefix = HEADER.pack(
        MAGIC, (VERSION << 8) | packet.flags,
        packet.packet_id & 0xFFFFFFFF,
        packet.access_unit_id & 0xFFFFFFFF,
        packet.fragment_index, packet.fragment_count,
        packet.timestamp_ms & 0xFFFFFFFF, len(packet.payload), 0,
    )
    checksum = binascii.crc_hqx(prefix[:-2] + packet.payload, 0xFFFF)
    return prefix[:-2] + struct.pack("!H", checksum) + packet.payload


def decode(datagram: bytes) -> Packet:
    if len(datagram) > MAX_DATAGRAM:
        raise ValueError("datagram exceeds protocol limit")
    if len(datagram) < HEADER.size:
        raise ValueError("truncated header")
    magic, version_flags, pid, auid, index, count, stamp, size, checksum = HEADER.unpack_from(datagram)
    payload = datagram[HEADER.size:]
    flags = version_flags & 0xFF
    if magic != MAGIC or version_flags >> 8 != VERSION or flags & ~0x0F:
        raise ValueError("unknown protocol or version")
    if size != len(payload) or count == 0 or index >= count:
        raise ValueError("invalid packet lengths or fragment numbering")
    expected = binascii.crc_hqx(datagram[:HEADER.size - 2] + payload, 0xFFFF)
    if checksum != expected:
        raise ValueError("CRC mismatch")
    return Packet(flags, pid, auid, index, count, stamp, payload)


def fragment(data: bytes, access_unit_id: int, first_packet_id: int,
             timestamp_ms: int, keyframe: bool = False,
             reliable: bool = False) -> list[bytes]:
    if not data:
        raise ValueError("access unit must not be empty")
    count = (len(data) + MAX_CHUNK - 1) // MAX_CHUNK
    if count > 0xFFFF:
        raise ValueError("access unit is too large")
    packets = []
    for index in range(count):
        flags = (FLAG_START if index == 0 else 0) | (FLAG_END if index == count - 1 else 0)
        if keyframe:
            flags |= FLAG_KEYFRAME
        if reliable:
            flags |= FLAG_RELIABLE
        packets.append(encode(Packet(flags, first_packet_id + index, access_unit_id,
                                     index, count, timestamp_ms,
                                     data[index * MAX_CHUNK:(index + 1) * MAX_CHUNK])))
    return packets
