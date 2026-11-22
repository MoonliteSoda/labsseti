"""Проверка границ H.264 access unit и сборки перед декодированием."""
import io
import subprocess
import unittest

from labs.lab2.assembly import AccessUnitAssembler
from labs.lab2.protocol import decode, fragment
from labs.lab2.sender import iter_access_units


class VideoPipelineTest(unittest.TestCase):
    def test_complete_units_reach_ffmpeg_in_order(self) -> None:
        source = subprocess.run(
            ["ffmpeg", "-v", "error", "-f", "lavfi", "-i",
             "testsrc=size=160x120:rate=8:duration=1", "-an", "-c:v", "libx264",
             "-preset", "ultrafast", "-tune", "zerolatency", "-x264-params",
             "aud=1", "-f", "h264", "pipe:1"],
            check=True, capture_output=True,
        ).stdout
        units = list(iter_access_units(io.BytesIO(source), chunk_size=17))
        self.assertEqual(len(units), 8)
        self.assertEqual(b"".join(units), source)
        assembler = AccessUnitAssembler(timeout=1.0)
        delivered = []
        # AU 1 приходит раньше AU 0, а фрагменты AU 0 приходят в обратном порядке.
        for datagram in fragment(units[1], 1, 100, 0):
            delivered.extend(assembler.accept(decode(datagram), 0.0))
        self.assertEqual(delivered, [])
        for datagram in reversed(fragment(units[0], 0, 0, 0)):
            delivered.extend(assembler.accept(decode(datagram), 0.1))
        for number, unit in enumerate(units[2:], start=2):
            for datagram in fragment(unit, number, 200 + number * 100, 0):
                delivered.extend(assembler.accept(decode(datagram), 0.2))
        self.assertEqual([unit.number for unit in delivered], list(range(8)))
        rebuilt = b"".join(unit.data for unit in delivered)
        self.assertEqual(rebuilt, source)
        decoder = subprocess.run(
            ["ffmpeg", "-v", "error", "-f", "h264", "-i", "pipe:0",
             "-f", "null", "-"], input=rebuilt, capture_output=True,
        )
        self.assertEqual(decoder.returncode, 0, decoder.stderr.decode())

    def test_incomplete_unit_is_discarded(self) -> None:
        assembler = AccessUnitAssembler(timeout=0.5)
        datagrams = fragment(b"x" * 4000, 0, 0, 0)
        self.assertGreater(len(datagrams), 1)
        for datagram in datagrams[:-1]:
            self.assertEqual(assembler.accept(decode(datagram), 0.0), [])
        self.assertEqual(assembler.tick(0.6), [])
        self.assertEqual(assembler.incomplete_dropped, 1)
        for datagram in fragment(b"complete", 1, 10, 0):
            self.assertEqual(assembler.accept(decode(datagram), 0.7), [])
        delivered = assembler.tick(1.3)
        self.assertEqual([unit.data for unit in delivered], [b"complete"])


if __name__ == "__main__":
    unittest.main()
