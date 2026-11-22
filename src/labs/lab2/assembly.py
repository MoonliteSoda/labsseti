"""Сборка полных H.264 access unit из пакетов УПВ-1 с сохранением порядка."""
from __future__ import annotations

from dataclasses import dataclass, field

from .protocol import FLAG_END, FLAG_KEYFRAME, FLAG_START, MAX_CHUNK, Packet

MAX_INFLIGHT_UNITS = 64
MAX_UNIT_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True)
class CompleteUnit:
    number: int
    data: bytes
    keyframe: bool


@dataclass
class _Partial:
    count: int
    updated: float
    parts: dict[int, bytes] = field(default_factory=dict)
    start: bool = False
    end: bool = False
    keyframe: bool = False


class AccessUnitAssembler:
    def __init__(self, timeout: float = 2.0) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self.timeout = timeout
        self.partial: dict[int, _Partial] = {}
        self.ready: dict[int, CompleteUnit] = {}
        self.next_number = 0
        self.gap_since: float | None = None
        self.incomplete_dropped = 0

    def accept(self, packet: Packet, now: float) -> list[CompleteUnit]:
        """Возвращает только полные единицы в порядке их номеров."""
        if packet.access_unit_id < self.next_number:
            return []
        if packet.fragment_count * MAX_CHUNK > MAX_UNIT_BYTES:
            self.incomplete_dropped += 1
            return []
        if packet.access_unit_id in self.ready:
            return []
        if bool(packet.flags & FLAG_START) != (packet.fragment_index == 0):
            return []
        if bool(packet.flags & FLAG_END) != (packet.fragment_index == packet.fragment_count - 1):
            return []
        item = self.partial.get(packet.access_unit_id)
        if item is None:
            if len(self.partial) >= MAX_INFLIGHT_UNITS:
                oldest = min(self.partial, key=lambda number: self.partial[number].updated)
                del self.partial[oldest]
                self.incomplete_dropped += 1
            item = _Partial(packet.fragment_count, now)
            self.partial[packet.access_unit_id] = item
        if item.count != packet.fragment_count:
            del self.partial[packet.access_unit_id]
            self.incomplete_dropped += 1
            return []
        item.parts.setdefault(packet.fragment_index, packet.payload)
        item.updated = now
        item.start |= bool(packet.flags & FLAG_START)
        item.end |= bool(packet.flags & FLAG_END)
        item.keyframe |= bool(packet.flags & FLAG_KEYFRAME)
        if len(item.parts) == item.count and item.start and item.end:
            unit = CompleteUnit(packet.access_unit_id,
                                b"".join(item.parts[i] for i in range(item.count)),
                                item.keyframe)
            self.ready[unit.number] = unit
            del self.partial[unit.number]
            if len(self.ready) > MAX_INFLIGHT_UNITS:
                self.next_number = min(self.ready)
                self.gap_since = None
        return self._drain(now)

    def tick(self, now: float) -> list[CompleteUnit]:
        """Удаляет неполные единицы и пропускает пробел после тайм-аута."""
        for number, item in list(self.partial.items()):
            if now - item.updated >= self.timeout:
                del self.partial[number]
                self.incomplete_dropped += 1
        return self._drain(now)

    def _drain(self, now: float) -> list[CompleteUnit]:
        result = []
        while True:
            unit = self.ready.pop(self.next_number, None)
            if unit is not None:
                result.append(unit)
                self.next_number += 1
                self.gap_since = None
                continue
            if not self.ready:
                self.gap_since = None
                break
            if self.gap_since is None:
                self.gap_since = now
                break
            if now - self.gap_since < self.timeout:
                break
            self.next_number = min(self.ready)
            self.gap_since = None
        return result
