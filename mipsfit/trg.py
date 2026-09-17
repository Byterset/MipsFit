"""Temporal relationship graph over 32-byte code chunks.

Gloy & Smith ("Procedure Placement Using Temporal-Ordering Information",
TOPLAS 1999): the weight between two chunks is how often one of them runs
between two runs of the other. Chunks that interleave that way evict each other
whenever a layout maps them to the same cache line, so the weighted sum over
aliasing pairs estimates the conflict misses of a layout without replaying it.
"""
from __future__ import annotations

from collections import defaultdict
import heapq
import json
from pathlib import Path

try:  # C helper behind Counter.update; keeps the inner loop out of Python
    from collections import _count_elements
except ImportError:  # pragma: no cover
    def _count_elements(mapping, iterable):
        for item in iterable:
            mapping[item] = mapping.get(item, 0) + 1

from .trace import frame_bounds

LINES = 512
CHUNK_SPAN = 1 << 27  # chunk keys per unit: enough for absolute KSEG0 line numbers


class Graph:
    """chunks[i] = (unit index, byte offset from the unit's base). The `fixed`
    pseudo-unit holds code outside every placement unit, at absolute addresses."""

    def __init__(self, fixed, source):
        self.fixed = fixed
        self.source = source
        self.ids = {}
        self.unit, self.offset, self.touches, self.neighbors = [], [], [], []
        self.transitions = defaultdict(float)
        self.unit_touches = defaultdict(float)
        self.active = []

    def chunk(self, unit, offset):
        key = unit * CHUNK_SPAN + (offset >> 5)
        index = self.ids.get(key)
        if index is None:
            index = self.ids[key] = len(self.unit)
            self.unit.append(unit)
            self.offset.append(offset >> 5 << 5)
            self.touches.append(0.0)
            self.neighbors.append({})
        return index

    def connect(self, a, b, weight):
        if a == b or not weight:
            return
        na, nb = self.neighbors[a], self.neighbors[b]
        na[b] = na.get(b, 0.0) + weight
        nb[a] = nb.get(a, 0.0) + weight

    def finish(self):
        self.active = [c for c, n in enumerate(self.neighbors) if n]
        self.unit_touches = defaultdict(float)
        for c, weight in enumerate(self.touches):
            self.unit_touches[self.unit[c]] += weight
        self.unit_chunks = defaultdict(list)
        for c in range(len(self.unit)):
            self.unit_chunks[self.unit[c]].append(c)
        return self

    def to_json(self):
        return dict(version=1, fixed=self.fixed, source=self.source,
                    chunks=[[self.unit[c], self.offset[c], round(self.touches[c], 6),
                             [[b, round(w, 6)] for b, w in sorted(self.neighbors[c].items())]]
                            for c in range(len(self.unit))],
                    transitions=[[a, b, round(w, 6)] for (a, b), w in sorted(self.transitions.items())])

    @classmethod
    def from_json(cls, data):
        graph = cls(data["fixed"], data["source"])
        for unit, offset, touches, neighbors in data["chunks"]:
            graph.unit.append(unit)
            graph.offset.append(offset)
            graph.touches.append(touches)
            graph.neighbors.append({b: w for b, w in neighbors})
            graph.ids[unit * CHUNK_SPAN + (offset >> 5)] = len(graph.unit) - 1
        for a, b, w in data["transitions"]:
            graph.transitions[a, b] = w
        return graph.finish()


def chunk_sequence(graph, trace, frames=None):
    """Chunk ids touched in order, consecutive repeats removed."""
    bounds = frame_bounds(trace)
    seg = trace["segments"]
    chunk, sequence = graph.chunk, []
    append, last = sequence.append, -1
    counted_frames = 0
    for first, end, warmup in frames or [(0, len(bounds), 0)]:
        for f in range(first, end):
            if f - first >= warmup:
                counted_frames += 1
            start, stop = bounds[f]
            it = iter(seg[start * 3:stop * 3])
            for u, s, e in zip(it, it, it):
                for offset in range(s >> 5 << 5, ((e - 4) >> 5 << 5) + 1, 32):
                    c = chunk(u, offset)
                    if c != last:
                        append(c)
                        last = c
    return sequence, max(1, counted_frames)


def _hot(sequence, coverage=0.999, minimum=2):
    counts = defaultdict(int)
    _count_elements(counts, sequence)
    total = len(sequence)
    keep, seen = set(), 0
    for c, n in sorted(counts.items(), key=lambda item: (-item[1], item[0])):
        if n < minimum or seen >= coverage * total:
            break
        keep.add(c)
        seen += n
    return keep, counts


def _temporal(graph, sequence, scale, recency=LINES):
    """Count, for every chunk, which other chunks ran since its previous run."""
    pairs = defaultdict(dict)
    stack, window = [], set()
    index, insert, pop = stack.index, stack.insert, stack.pop
    for x in sequence:
        if x in window:
            i = index(x)
            if i:
                _count_elements(pairs[x], stack[:i])
                del stack[i]
                insert(0, x)
        else:
            insert(0, x)
            window.add(x)
            if len(stack) > recency:
                window.discard(pop())
    for x, others in pairs.items():
        for y, n in others.items():
            graph.connect(x, y, n * scale)


def from_traces(traces, model, frames=None, recency=LINES, coverage=0.999):
    """Build the graph from imported traces. `frames` maps a trace name to the
    frame windows to sample (cachesim.windows), or None for everything."""
    graph = Graph(len(model["units"]), "trace")
    for trace in traces:
        sequence, counted = chunk_sequence(graph, trace, (frames or {}).get(trace["name"]))
        keep, counts = _hot(sequence, coverage)
        scale = trace["weight"] / counted
        for c, n in counts.items():
            graph.touches[c] += n * scale
        hot, last = [], -1
        for c in sequence:
            if c in keep and c != last:
                hot.append(c)
                last = c
        _temporal(graph, hot, scale, recency)
        total_frames = max(1, len(frame_bounds(trace)))
        for a, b, n in trace["transitions"]:
            graph.transitions[a, b] += n * trace["weight"] / total_frames
    return graph.finish()


def from_relationships(model):
    """Static fallback: call/return edges (and imported eviction pairs) as a
    coarse stand-in for measured interleaving."""
    graph = Graph(len(model["units"]), "static")
    index = {u["id"]: i for i, u in enumerate(model["units"])}
    for edge in model["relationships"]:
        ua, ub = index.get(edge["a"]["unit"]), index.get(edge["b"]["unit"])
        if ua is None or ub is None:
            continue
        weight = edge["weight"]
        a, b = graph.chunk(ua, edge["a"]["offset"]), graph.chunk(ub, edge["b"]["offset"])
        graph.touches[a] += weight
        graph.touches[b] += weight
        graph.connect(a, b, weight)
        if ua != ub:
            graph.transitions[ua, ub] += weight
    return graph.finish()


def lines(graph, base):
    return [(base[u] + offset) >> 5 for u, offset in zip(graph.unit, graph.offset)]


def alias_cost(graph, base, top=0):
    """Weighted interleaving between chunks that share a cache line slot while
    holding different lines: the layout's estimated conflict misses."""
    line = lines(graph, base)
    slots = [[] for _ in range(LINES)]
    for c in graph.active:
        slots[line[c] & 511].append(c)
    neighbors = graph.neighbors
    cost = 0.0
    worst = []
    for members in slots:
        count = len(members)
        if count < 2:
            continue
        for i in range(count):
            a = members[i]
            la, na = line[a], neighbors[a]
            if not na:
                continue
            for j in range(i + 1, count):
                b = members[j]
                if line[b] != la:
                    weight = na.get(b)
                    if weight:
                        cost += weight
                        if top:
                            worst.append((weight, a, b))
    if not top:
        return cost, []
    return cost, [(w, a, b) for w, a, b in heapq.nlargest(top, worst)]


def describe(graph, units, pairs, base):
    """Turn (weight, chunk, chunk) tuples into report rows."""
    line = lines(graph, base)

    def side(c):
        u = graph.unit[c]
        return dict(unit=units[u]["id"] if u < len(units) else None, offset=graph.offset[c], line=line[c])

    return [dict(weight=round(w, 3), a=side(a), b=side(b), slot=line[a] & 511) for w, a, b in pairs]


def save(graph, out, name="graph.json"):
    Path(out, name).write_text(json.dumps(graph.to_json()), encoding="utf-8")
    return name


def load(path):
    return Graph.from_json(json.loads(Path(path).read_text(encoding="utf-8")))
