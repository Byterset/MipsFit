"""ares-64 CPU execution traces (P64XTRC1 files written by ares.cpuTraceStart).

Import maps every executed range onto the placement unit containing it, so one
capture replays against any order of those units (cachesim.py). The emulator's
own icache fills are kept as ground truth for calibrating the replay.
"""
from __future__ import annotations

from array import array
import bisect
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

from .elf import Elf
from .mips import transfer

MAGIC = b"P64XTRC1"
LINES = 512
HEADER_BYTES = 8 + 4 * 4 + 8 + 4 * LINES
RANGE, FRAME, FILL, UNCACHED, RESET, TOTALS = 0, 1, 2, 3, 4, 15
EXCEPTION_VECTORS = frozenset((0x80000000, 0x80000080, 0x80000100, 0x80000180))
ARRAYS = ("segments", "frames", "fills", "resets")


def parse_spec(spec):
    """'capture.xtrace=2.5' -> (path, 2.5); a plain path has weight 1."""
    path, sep, weight = spec.rpartition("=")
    if not sep:
        return spec, 1.0
    try:
        value = float(weight)
    except ValueError:
        return spec, 1.0
    if not value > 0:
        raise ValueError(f"trace weight must be positive: {spec}")
    return path, value


def read_header(data):
    if len(data) < HEADER_BYTES or data[:8] != MAGIC:
        raise ValueError("not a P64XTRC1 CPU trace (record one with ares.cpuTraceStart)")
    version, header_bytes, lines, flags = struct.unpack_from("<4I", data, 8)
    if version != 1 or header_bytes != HEADER_BYTES or lines != LINES:
        raise ValueError(f"unsupported CPU trace version {version}")
    cycles, = struct.unpack_from("<Q", data, 24)
    return dict(recompiler=bool(flags & 1), start_cycles=cycles, initial=struct.unpack_from(f"<{LINES}I", data, 32))


def records(path, block=1 << 22):
    """Yield arrays of u32 words (three per record) after the header."""
    with open(path, "rb") as f:
        f.seek(HEADER_BYTES)
        while True:
            data = f.read(block * 12)
            if not data:
                return
            if len(data) % 12:
                raise ValueError(f"{Path(path).name}: trace ends inside a record")
            words = array("I")
            words.frombytes(data)
            if sys.byteorder == "big":
                words.byteswap()
            yield words


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 22), b""):
            digest.update(block)
    return digest.hexdigest()


class Locator:
    """Split address ranges at placement-unit boundaries."""

    def __init__(self, units):
        self.fixed = len(units)
        self.starts = [u["address"] for u in units]
        self.ends = [u["address"] + u["size"] for u in units]
        self.lo, self.hi = min(self.starts), max(self.ends)
        table = array("i", [-1]) * ((self.hi - self.lo + 3) // 4)
        for i, (a, b) in enumerate(zip(self.starts, self.ends)):
            first, last = (a - self.lo) // 4, (b - self.lo + 3) // 4
            table[first:last] = array("i", [i]) * (last - first)
        self.table = table

    def split(self, a, b):
        """[a, b) -> ((unit, start, end), ...). Code outside every unit keeps its
        absolute addresses under the `fixed` pseudo-unit."""
        parts = []
        while a < b:
            u = self.table[(a - self.lo) >> 2] if self.lo <= a < self.hi else -1
            if u >= 0:
                base = self.starts[u]
                end = min(b, self.ends[u])
                parts.append((u, a - base, end - base))
            else:
                i = bisect.bisect_right(self.starts, a)
                end = min(b, self.starts[i]) if i < len(self.starts) else b
                parts.append((self.fixed, a, end))
            a = end
        return tuple(parts)


def ends_with_transfer(elf, end):
    """Whether a range ending at `end` ends the way execution can leave a
    sequential run: a transfer with its delay slot, or a likely branch/eret/
    syscall as the last instruction. None if the code is not in the ELF."""
    words = elf.words(end - 8, 8)
    if len(words) != 2:
        return None
    return any(transfer(pc, word) is not None for pc, word in words)


def import_trace(model, path, name=None, weight=1.0, elf=None):
    path = Path(path).resolve()
    with open(path, "rb") as f:
        header = read_header(f.read(HEADER_BYTES))
    sidecar = Path(str(path) + ".json")
    meta = json.loads(sidecar.read_text(encoding="utf-8")) if sidecar.is_file() else {}
    if meta.get("elf_sha256") and meta["elf_sha256"] != model["elf_sha256"]:
        raise ValueError(f"{path.name} was captured from a different ELF; never reuse a trace across builds")
    units = model["units"]
    if len(units) >= 1 << 16:
        raise ValueError("too many placement units for trace import")
    loc = Locator(units)
    fixed = loc.fixed
    elf = elf or Elf.read(model["elf"])
    name = re.sub(r"[^A-Za-z0-9_-]+", "_", name or meta.get("scenario") or path.stem).strip("_") or "trace"

    segments, frames, fills, resets = (array("I") for _ in ARRAYS)
    memo, end_ok, totals = {}, {}, {}
    unit_words = [0] * (fixed + 1)
    transitions = defaultdict(int)
    align32 = [u["align"] >= 32 for u in units] + [True]
    instructions = uncached = raw = fill_count = checked = consistent = 0
    lu = ls = le = -1
    prev_unit = -1
    pending_end = 0
    split, extend = loc.split, segments.extend
    for words in records(path):
        raw += len(words) // 3
        it = iter(words)
        for a, b, t in zip(it, it, it):
            kind = t >> 28
            if kind == RANGE:
                if b <= a or (b - a) & 3 or (a >> 29) != 4:
                    raise ValueError(f"{path.name}: corrupt range record {a:#x}-{b:#x}")
                count = t & 0x0FFFFFFF
                if pending_end and a not in EXCEPTION_VECTORS:
                    ok = end_ok.get(pending_end, 2)
                    if ok == 2:
                        ok = end_ok[pending_end] = ends_with_transfer(elf, pending_end)
                    if ok is not None:
                        checked += 1
                        consistent += ok
                pending_end = b
                instructions += count * ((b - a) >> 2)
                key = a << 32 | b
                parts = memo.get(key)
                if parts is None:
                    parts = memo[key] = split(a, b)
                for u, s, e in parts:
                    unit_words[u] += count * ((e - s) >> 2)
                    if u != prev_unit:
                        if prev_unit >= 0 and prev_unit != fixed and u != fixed:
                            transitions[prev_unit << 16 | u] += 1
                        prev_unit = u
                    # A range whose lines the previous one just touched cannot miss,
                    # whatever the layout (32-byte-aligned units keep their line grid).
                    if u == lu and ((ls <= s and e <= le) or
                                    (align32[u] and s >> 5 >= ls >> 5 and (e - 4) >> 5 <= (le - 4) >> 5)):
                        continue
                    extend((u, s, e))
                    lu, ls, le = u, s, e
            elif kind == FILL:
                fills.append(len(segments) // 3)
                fills.append(a)
                fill_count += 1
                lu, pending_end = -1, 0
            elif kind == FRAME:
                frames.append(len(segments) // 3)
                pending_end = 0
            elif kind == UNCACHED:
                uncached += a
                pending_end = 0
            elif kind == RESET:
                resets.append(len(segments) // 3)
                lu, prev_unit, pending_end = -1, -1, 0
            elif kind == TOTALS:
                totals[t & 0xF] = (a, b)
            else:
                raise ValueError(f"{path.name}: unknown record type {kind}")
    if 0 not in totals or 1 not in totals or 2 not in totals:
        raise ValueError(f"{path.name}: incomplete trace (no totals); finish captures with ares.cpuTraceStop()")
    truncated = bool(totals[2][0] & 1)
    if not truncated and ((totals[0][0] | totals[0][1] << 32) != instructions or (totals[1][0] | totals[1][1] << 32) != fill_count):
        raise ValueError(f"{path.name}: record totals do not match the file content")
    if checked >= 1000 and consistent < 0.9 * checked:
        raise ValueError(f"{path.name}: only {consistent}/{checked} range ends are control transfers in this ELF; "
                         "the trace was captured from a different build")

    spans = defaultdict(list)
    for parts in memo.values():
        for u, s, e in parts:
            if u != fixed:
                spans[u].append((s, e))
    coverage = {}
    for u, items in sorted(spans.items()):
        items.sort()
        merged = []
        for s, e in items:
            if merged and s <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], e)
            else:
                merged.append([s, e])
        coverage[str(u)] = merged

    initial = []
    for p in header["initial"]:
        if p == 0xFFFFFFFF or p >= 0x20000000:
            initial.append(None)
            continue
        parts = split(p | 0x80000000, (p | 0x80000000) + 32)
        u, s, _ = next((x for x in parts if x[0] != fixed), parts[0])
        initial.append([u, s])

    warnings = []
    if not meta.get("elf_sha256"):
        warnings.append(f"{path.name}: no {sidecar.name} with the ELF hash; provenance rests on the control-flow check "
                        f"({consistent}/{checked} range ends match)")
    if truncated:
        warnings.append(f"{path.name}: capture stopped at maxBytes; only its beginning is analyzed")
    if header["recompiler"]:
        warnings.append(f"{path.name}: captured with the recompiler, which skips some cache checks; "
                        "use ares.setRecompiler(false) for exact calibration")
    if not frames:
        warnings.append(f"{path.name}: no frame marks; per-frame figures cover the whole capture")
    return dict(version=1, name=name, weight=weight, source=str(path), source_sha256=file_sha256(path),
                elf_sha256=model["elf_sha256"], attested=bool(meta.get("elf_sha256")), scenario=meta.get("scenario"),
                recompiler=header["recompiler"], units=[u["id"] for u in units],
                fixed=fixed, initial=initial, warnings=warnings,
                stats=dict(raw_records=raw, segments=len(segments) // 3, unique_ranges=len(memo), instructions=instructions,
                           uncached=uncached, outside_units=unit_words[fixed], fills=fill_count, frames=len(frames),
                           truncated=truncated, control_flow_checked=checked, control_flow_consistent=consistent),
                unit_instructions=unit_words[:fixed],
                transitions=[[k >> 16, k & 0xFFFF, n] for k, n in sorted(transitions.items())],
                coverage=coverage, segments=segments, frames=frames, fills=fills, resets=resets)


def save(trace, out):
    """Write trace-<name>.json (metadata) and trace-<name>.bin (arrays)."""
    out = Path(out)
    stem = "trace-" + trace["name"]
    with open(out / (stem + ".bin"), "wb") as f:
        for key in ARRAYS:
            data = trace[key]
            if sys.byteorder == "big":
                data = array("I", data)
                data.byteswap()
            data.tofile(f)
    meta = {k: v for k, v in trace.items() if k not in ARRAYS}
    meta.update(data=stem + ".bin", arrays={k: len(trace[k]) for k in ARRAYS})
    (out / (stem + ".json")).write_text(json.dumps(meta), encoding="utf-8")
    return stem + ".json"


def load(path):
    path = Path(path)
    trace = json.loads(path.read_text(encoding="utf-8"))
    with open(path.parent / trace.pop("data"), "rb") as f:
        for key, length in trace.pop("arrays").items():
            data = array("I")
            data.fromfile(f, length)
            if sys.byteorder == "big":
                data.byteswap()
            trace[key] = data
    return trace


def frame_bounds(trace):
    """[start, end) segment intervals per frame. Code after the last frame mark
    forms a final partial frame."""
    total = len(trace["segments"]) // 3
    bounds, start = [], 0
    for mark in trace["frames"]:
        bounds.append((start, mark))
        start = mark
    if start < total or not bounds:
        bounds.append((start, total))
    return bounds
