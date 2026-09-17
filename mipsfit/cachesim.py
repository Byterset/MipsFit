"""Exact VR4300 instruction-cache replay of imported execution traces.

The icache is direct mapped: 512 lines of 32 bytes, indexed by (vaddr >> 5) & 511.
Replaying a trace against unit addresses gives the fills that layout would cause.
"""
from __future__ import annotations

import bisect
from collections import Counter, OrderedDict

from .trace import frame_bounds

LINES = 512
MISS_CYCLES = 48  # CPU cycles ares charges per icache line fill


def bases(trace, addresses):
    missing = next((uid for uid in trace["units"] if uid not in addresses), None)
    if missing:
        raise ValueError(f"trace unit missing from layout: {missing}")
    return [addresses[uid] for uid in trace["units"]] + [0]


def windows(trace, max_segments=0, span=3):
    """Frame windows (first, end, warmup frames) spread over the trace, holding
    about max_segments segments. 0 replays everything."""
    bounds = frame_bounds(trace)
    total = bounds[-1][1]
    if not max_segments or total <= max_segments or len(bounds) <= 2 * span:
        return None
    count = max(1, min(len(bounds) // span, max_segments * len(bounds) // (total * span)))
    step = len(bounds) / count
    return [(int(i * step), min(len(bounds), int(i * step) + span), 0 if int(i * step) == 0 else 1)
            for i in range(count)]


def _spans(resets, start, end):
    """Split [start, end) at machine resets: (start, end, clear cache first)."""
    lo, hi = bisect.bisect_left(resets, start), bisect.bisect_left(resets, end)
    points = resets[lo:hi]
    if not points or points[0] > start:
        yield start, points[0] if points else end, False
    for i, point in enumerate(points):
        yield point, points[i + 1] if i + 1 < len(points) else end, True


def _replay(seg, base, cache, start, end):
    it = iter(seg[start * 3:end * 3])
    misses = 0
    for u, s, e in zip(it, it, it):
        b = base[u]
        line = (b + s) >> 5
        k = line & 511
        if cache[k] != line:
            cache[k] = line
            misses += 1
        last = (b + e - 4) >> 5
        while line < last:
            line += 1
            k = line & 511
            if cache[k] != line:
                cache[k] = line
                misses += 1
    return misses


class _Detail:
    def __init__(self, units):
        self.evicted = {}
        self.pairs = Counter()
        self.slot_misses = [0] * LINES
        self.unit_misses = [0] * (units + 1)
        self.fills = self.first = self.conflict = self.capacity = 0


def _replay_detail(seg, base, cache, owner, start, end, st, touched):
    it = iter(seg[start * 3:end * 3])
    evicted, pairs, slot_misses, unit_misses = st.evicted, st.pairs, st.slot_misses, st.unit_misses
    fills, first, conflict, capacity = st.fills, st.first, st.conflict, st.capacity
    touch = touched.add
    misses = 0
    for u, s, e in zip(it, it, it):
        b = base[u]
        line = (b + s) >> 5
        last = (b + e - 4) >> 5
        while True:
            touch(line)
            k = line & 511
            old = cache[k]
            if old != line:
                misses += 1
                if old >= 0:
                    evicted[old] = fills
                    ou = owner[k]
                    pairs[u, (line << 5) - b, ou, (old << 5) - base[ou]] += 1
                fills += 1
                # ares' classification: refetched fewer than 512 fills after its
                # eviction is a conflict miss (layout-fixable), otherwise capacity
                previous = evicted.get(line)
                if previous is None:
                    first += 1
                elif fills - previous < LINES:
                    conflict += 1
                else:
                    capacity += 1
                slot_misses[k] += 1
                unit_misses[u] += 1
                cache[k] = line
                owner[k] = u
            if line >= last:
                break
            line += 1
    st.fills, st.first, st.conflict, st.capacity = fills, first, conflict, capacity
    return misses


def _initial(trace, base, cache, owner):
    for k in range(LINES):
        cache[k], owner[k] = -1, -1
    for entry in trace["initial"]:
        if entry:
            u, offset = entry
            line = (base[u] + offset) >> 5
            cache[line & 511], owner[line & 511] = line, u


def simulate(trace, addresses, frames=None, detail=False, top_pairs=40):
    """Replay the trace (or the frame windows from windows()) at `addresses`."""
    if detail and frames:
        raise ValueError("detailed replay covers the whole trace")
    base = bases(trace, addresses)
    seg, resets, bounds = trace["segments"], list(trace["resets"]), frame_bounds(trace)
    cache, owner = [-1] * LINES, [-1] * LINES
    st = _Detail(len(trace["units"])) if detail else None
    per_frame, working_set = [], []
    for first, end, warmup in frames or [(0, len(bounds), 0)]:
        if first == 0:
            _initial(trace, base, cache, owner)
        else:
            cache[:], owner[:] = [-1] * LINES, [-1] * LINES
        for f in range(first, end):
            n, touched = 0, set()
            for start, stop, clear in _spans(resets, *bounds[f]):
                if clear:
                    cache[:], owner[:] = [-1] * LINES, [-1] * LINES
                if detail:
                    n += _replay_detail(seg, base, cache, owner, start, stop, st, touched)
                else:
                    n += _replay(seg, base, cache, start, stop)
            if f - first >= warmup:
                per_frame.append(n)
                if detail:
                    working_set.append(len(touched))
    misses = sum(per_frame)
    result = dict(misses=misses, frames=len(per_frame), misses_per_frame=misses / len(per_frame) if per_frame else 0.0,
                  cycles=misses * MISS_CYCLES, per_frame=per_frame, sampled=bool(frames))
    if detail:
        units = trace["units"]

        def name(u):
            return units[u] if u < len(units) else None

        result.update(first_misses=st.first, conflict_misses=st.conflict, capacity_misses=st.capacity,
                      slot_misses=st.slot_misses, working_set=working_set,
                      unit_misses={units[u]: n for u, n in enumerate(st.unit_misses[:-1]) if n},
                      outside_misses=st.unit_misses[-1],
                      pairs=[dict(incoming=dict(unit=name(a), offset=ao), evicted=dict(unit=name(b), offset=bo), count=n)
                             for (a, ao, b, bo), n in st.pairs.most_common(top_pairs)])
    return result


def simulate_associative(trace, addresses, capacity=LINES):
    """Fully associative LRU cache of the same size: a layout-independent
    reference for how many misses no placement can avoid."""
    base = bases(trace, addresses)
    seg = trace["segments"]
    lru = OrderedDict()
    for entry in trace["initial"]:
        if entry:
            lru[(base[entry[0]] + entry[1]) >> 5] = None
    resets = set(trace["resets"])
    touch, evict = lru.move_to_end, lru.popitem
    misses, previous = 0, -1
    it = iter(seg)
    for index, (u, s, e) in enumerate(zip(it, it, it)):
        if index in resets:
            lru.clear()
            previous = -1
        b = base[u]
        line, last = (b + s) >> 5, (b + e - 4) >> 5
        while True:
            if line != previous:
                if line in lru:
                    touch(line)
                else:
                    misses += 1
                    lru[line] = None
                    if len(lru) > capacity:
                        evict(last=False)
                previous = line
            if line >= last:
                break
            line += 1
    frames = len(frame_bounds(trace))
    return dict(misses=misses, misses_per_frame=misses / frames, cycles=misses * MISS_CYCLES)


def calibrate(trace, result):
    """Compare a whole-trace replay at the captured layout with the emulator's fills."""
    marks = trace["frames"]
    emulator = [0] * max(len(result["per_frame"]), len(marks) + 1)
    for index in trace["fills"][0::2]:
        emulator[bisect.bisect_right(marks, index)] += 1
    simulated = result["per_frame"] + [0] * (len(emulator) - len(result["per_frame"]))
    differing = [i for i, (a, b) in enumerate(zip(emulator, simulated)) if a != b]
    return dict(emulator_fills=trace["stats"]["fills"], simulated_misses=result["misses"],
                exact=not differing, frames_differing=len(differing), first_difference=differing[0] if differing else None,
                executor="recompiler" if trace["recompiler"] else "interpreter")
