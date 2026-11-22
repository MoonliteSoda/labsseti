"""Локальная проверка упаковки, разбора и сборки данных УПВ-1."""

import hashlib
import unittest

from labs.lab2.protocol import (
    FLAG_END,
    FLAG_KEYFRAME,
    FLAG_START,
    HEADER,
    MAX_CHUNK,
    MAX_DATAGRAM,
    decode,
    fragment,
)


class ProtocolTest(unittest.TestCase):
    def test_fragment_roundtrip_and_sha256(self) -> None:
        # Несколько фрагментов и неполный последний пакет.
        original = bytes(range(256)) * 200 + b"\x00\xff\x10"
        datagrams = fragment(
            original,
            access_unit_id=42,
            first_packet_id=100,
            timestamp_ms=123456,
            keyframe=True,
        )

        self.assertEqual(HEADER.size, 24)
        self.assertEqual(len(datagrams), (len(original) + MAX_CHUNK - 1) // MAX_CHUNK)
        self.assertTrue(all(len(datagram) <= MAX_DATAGRAM for datagram in datagrams))

        # Подаём пакеты в обратном порядке, чтобы сборка зависела от fragment_index.
        packets = [decode(datagram) for datagram in reversed(datagrams)]
        self.assertEqual({packet.access_unit_id for packet in packets}, {42})
        self.assertEqual({packet.fragment_count for packet in packets}, {len(datagrams)})
        self.assertEqual({packet.timestamp_ms for packet in packets}, {123456})
        self.assertEqual(
            {packet.packet_id for packet in packets},
            set(range(100, 100 + len(datagrams))),
        )
        self.assertTrue(all(packet.flags & FLAG_KEYFRAME for packet in packets))
        self.assertTrue(next(p for p in packets if p.fragment_index == 0).flags & FLAG_START)
        self.assertTrue(
            next(p for p in packets if p.fragment_index == len(packets) - 1).flags & FLAG_END
        )

        restored = b"".join(
            packet.payload for packet in sorted(packets, key=lambda packet: packet.fragment_index)
        )
        source_sha256 = hashlib.sha256(original).hexdigest()
        restored_sha256 = hashlib.sha256(restored).hexdigest()
        print(f"source SHA-256:   {source_sha256}")
        print(f"restored SHA-256: {restored_sha256}")
        self.assertEqual(len(restored), len(original))
        self.assertEqual(restored_sha256, source_sha256)
        self.assertEqual(restored, original)

    def test_crc_rejects_corrupted_payload(self) -> None:
        datagram = bytearray(fragment(b"binary\x00data", 1, 1, 1)[0])
        datagram[-1] ^= 0x01
        with self.assertRaisesRegex(ValueError, "CRC mismatch"):
            decode(datagram)


if __name__ == "__main__":
    unittest.main()
