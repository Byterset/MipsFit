"""Code placement search.

Three stages, following the profile-guided layout literature and adapted to a
linker script (units keep their sizes and alignments, only their order changes):

1. Call-chain clustering (Ottoni & Maher, CGO 2017 "C3"): a hot unit joins its
   hottest caller's cluster while the cluster fits in the cache, and clusters are
   emitted densest first so the hot working set lands in as few 16 KiB windows
   as possible.
2. Slot-aware placement: clusters are laid down one at a time, choosing the
   position whose cache slots collide least with what is already placed
   (Hashemi/Kaeli/Calder-style cache-line colouring). Never-executed units serve
   as free spacers, so a cluster can be shifted without growing the ROM.
3. Late-acceptance hill climbing over the resulting order.

All three score layouts with the temporal-relationship-graph cost from trg.py;
candidates are then ranked by replaying the trace through the cache simulator.
"""
from __future__ import annotations

from bisect import bisect_left
import random
import time

from . import cachesim
from .layout import align, disruption, positions
from .trg import LINES, alias_cost, describe


class Layout:
    """Unit-index view of the placement region, with fast address arithmetic."""

    def __init__(self, model, graph):
        units = model["units"]
        self.model, self.graph, self.units = model, graph, units
        self.ids = [u["id"] for u in units]
        self.size = [u["size"] for u in units]
        self.align = [max(1, u["align"]) for u in units]
        self.original = [u["address"] for u in units]
        self.region = [i for i, u in enumerate(units) if u["region"]]
        self.movable = [i for i in self.region if units[i]["movable"]]
        self.pinned = [i for i in self.region if not units[i]["movable"]]
        self.start = min((self.original[i] for i in self.region), default=0)
        touches = graph.unit_touches
        self.hot = [i for i in self.movable if touches.get(i, 0.0) > 0]
        self.cold = [i for i in self.movable if touches.get(i, 0.0) <= 0]
        moving = set(self.region)
        self.fixed_chunks = [c for c in graph.active if graph.unit[c] not in moving]

    def bases(self, order, padding=None):
        base = list(self.original)
        cursor = self.start
        size, alignment = self.size, self.align
        for i in order:
            if padding:
                cursor += padding.get(i, 0)
            a = alignment[i]
            cursor = (cursor + a - 1) // a * a
            base[i] = cursor
            cursor += size[i]
        base.append(0)  # the `fixed` pseudo-unit keeps absolute addresses
        return base

    def cost(self, order, padding=None, top=0):
        return alias_cost(self.graph, self.bases(order, padding), top)


def clusters(lay, limit=16 * 1024, ratio=8.0):
    """C3: append a unit to its hottest caller's cluster, densest cluster first."""
    graph = lay.graph
    touches = graph.unit_touches
    hot = sorted(lay.hot, key=lambda i: (-touches.get(i, 0.0), i))
    hotset = set(hot)
    caller = {}
    for (a, b), weight in sorted(graph.transitions.items()):
        if a in hotset and b in hotset and a != b and weight > caller.get(b, (0.0, -1))[0]:
            caller[b] = (weight, a)
    group = {i: [i] for i in hot}
    owner = {i: i for i in hot}
    size = {i: max(1, align(lay.size[i], lay.align[i])) for i in hot}
    weight = {i: touches.get(i, 0.0) for i in hot}
    for unit in hot:
        found = caller.get(unit)
        if not found:
            continue
        target, source = owner[found[1]], owner[unit]
        if target == source or size[target] + size[source] > limit:
            continue
        # C3 also refuses merges that would dilute the caller cluster's density
        if weight[target] * size[source] > ratio * weight[source] * size[target]:
            continue
        group[target].extend(group.pop(source))
        size[target] += size.pop(source)
        weight[target] += weight.pop(source)
        for member in group[target]:
            owner[member] = target
    return sorted(group.values(), key=lambda members: (-weight[owner[members[0]]] / size[owner[members[0]]], min(members)))


def _group_cost(lay, group, cursor, occupancy, commit=False):
    graph = lay.graph
    offset, neighbors, chunks = graph.offset, graph.neighbors, graph.unit_chunks
    cost = 0.0
    local = {}
    for unit in group:
        cursor = align(cursor, lay.align[unit])
        base, cursor = cursor, cursor + lay.size[unit]
        for c in chunks.get(unit, ()):
            line = (base + offset[c]) >> 5
            slot = line & 511
            near = neighbors[c]
            if near:
                for other, d in occupancy[slot]:
                    if other != line:
                        weight = near.get(d)
                        if weight:
                            cost += weight
                for other, d in local.get(slot, ()):
                    if other != line:
                        weight = near.get(d)
                        if weight:
                            cost += weight
            if commit:
                occupancy[slot].append((line, c))
            else:
                local.setdefault(slot, []).append((line, c))
    return cost, cursor


def _shift_options(lay, pool, count, pad_budget, pad_step=32):
    """Ways to shift the next cluster: nothing, a cold unit as spacer, or padding."""
    options = [((), 0)]
    if pool and count:
        sizes = sorted((lay.size[i], i) for i in pool)
        picked = []
        for target in [32 << k for k in range(count)]:
            j = bisect_left(sizes, (target, -1))
            for candidate in (sizes[j] if j < len(sizes) else None, sizes[j - 1] if j else None):
                if candidate and candidate[1] not in picked:
                    picked.append(candidate[1])
                    break
        options += [((i,), 0) for i in picked]
    if pad_budget >= pad_step:
        options += [((), pad) for pad in (pad_step, pad_step * 2, pad_step * 4) if pad <= pad_budget]
    return options


def place(lay, groups, beam=4, spacers=8, pad_budget=0):
    """Lay clusters down one at a time, each at its cheapest reachable offset."""
    graph = lay.graph
    occupancy = [[] for _ in range(LINES)]
    base = list(lay.original) + [0]
    for c in lay.fixed_chunks:
        line = (base[graph.unit[c]] + graph.offset[c]) >> 5
        occupancy[line & 511].append((line, c))
    cursor = lay.start
    order, padding, used = [], {}, 0
    pool, remaining = list(lay.cold), list(groups)
    while remaining:
        options = _shift_options(lay, pool, spacers, pad_budget - used)
        best = None
        for index, group in enumerate(remaining[:beam]):
            for spacer, pad in options:
                start = cursor
                for unit in spacer:
                    start = align(start, lay.align[unit]) + lay.size[unit]
                cost, _ = _group_cost(lay, group, start + pad, occupancy)
                key = (cost, sum(lay.size[u] for u in spacer) + pad, index)
                if best is None or key < best[0]:
                    best = (key, index, spacer, pad)
            if best[0][0] == 0 and best[1] == 0 and not best[2] and not best[3]:
                break  # the densest cluster already fits without a conflict
        _, index, spacer, pad = best
        group = remaining.pop(index)
        for unit in spacer:
            pool.remove(unit)
            order.append(unit)
            cursor = align(cursor, lay.align[unit]) + lay.size[unit]
        if pad:
            padding[group[0]] = pad
            cursor += pad
            used += pad
        _, cursor = _group_cost(lay, group, cursor, occupancy, commit=True)
        order.extend(group)
    order.extend(pool)
    return order, padding


def refine(lay, order, padding, seconds, seed, pad_budget=0, history=64):
    """Late-acceptance hill climbing: accept anything no worse than the cost
    `history` steps ago, which escapes shallow local minima without a schedule."""
    rng = random.Random(seed)
    order, padding = list(order), dict(padding)
    current, _ = lay.cost(order, padding)
    best, best_state = current, (list(order), dict(padding))
    memory = [current] * history
    deadline = time.monotonic() + seconds
    hot = lay.hot or lay.movable
    step = 0
    while hot and time.monotonic() < deadline:
        step += 1
        trial, pad = list(order), dict(padding)
        unit = hot[rng.randrange(len(hot))]
        i = trial.index(unit)
        choice = rng.random()
        if choice < 0.3:
            j = trial.index(hot[rng.randrange(len(hot))])
            trial[i], trial[j] = trial[j], trial[i]
        elif choice < 0.6:
            block = trial[i:i + rng.randint(1, 4)]
            target = hot[rng.randrange(len(hot))]
            if target in block:
                continue
            del trial[i:i + len(block)]
            j = trial.index(target)
            trial[j:j] = block
        elif choice < 0.8 and lay.cold:
            spacer = lay.cold[rng.randrange(len(lay.cold))]
            trial.remove(spacer)
            trial.insert(trial.index(unit), spacer)
        elif pad_budget:
            used = sum(pad.values()) - pad.get(unit, 0)
            value = max(0, pad.get(unit, 0) + (32 if rng.random() < 0.5 else -32))
            if used + value > pad_budget:
                continue
            if value:
                pad[unit] = value
            else:
                pad.pop(unit, None)
        else:
            continue
        value, _ = lay.cost(trial, pad)
        if value <= current or value <= memory[step % history]:
            order, padding, current = trial, pad, value
            if value < best:
                best, best_state = value, (list(trial), dict(pad))
        memory[step % history] = current
    return best_state[0], best_state[1], best


def _cost_record(lay, model, graph, order, padding, traces, windows, top=12):
    ids = [lay.ids[i] for i in order]
    pad_ids = {lay.ids[i]: n for i, n in padding.items()}
    addresses = positions(model, ids, padding=pad_ids)
    base = [addresses[uid] for uid in lay.ids] + [0]
    alias, pairs = alias_cost(graph, base, top)
    record = dict(alias=round(alias, 3), padding_bytes=sum(pad_ids.values()),
                  disruption=disruption(model, ids), traces={})
    total = weighted = 0.0
    for trace in traces:
        result = cachesim.simulate(trace, addresses, frames=windows.get(trace["name"]))
        record["traces"][trace["name"]] = dict(misses=result["misses"], frames=result["frames"],
                                               misses_per_frame=round(result["misses_per_frame"], 2),
                                               sampled=result["sampled"])
        weighted += result["misses_per_frame"] * trace["weight"]
        total += trace["weight"]
    if total:
        record["misses_per_frame"] = round(weighted / total, 2)
    return ids, pad_ids, addresses, record, pairs


def rank_key(record):
    return (record.get("misses_per_frame", record["alias"]), record["alias"], record["disruption"])


def generate(model, graph, traces=(), count=3, search_seconds=30.0, seed=0, padding_budget=0,
             sim_segments=0, beam=4):
    """Search for layouts and return the baseline plus the best `count` alternatives."""
    lay = Layout(model, graph)
    windows = {t["name"]: cachesim.windows(t, sim_segments) for t in traces}
    proposals = [("original linker layout", [i for i in lay.region], {}, True)]
    if len(lay.movable) > 1:
        proposals.append(("verified sections before fallback", lay.movable + lay.pinned, {}, False))
        groups = clusters(lay)
        dense = [u for group in groups for u in group]
        proposals.append(("hot clusters, densest first", dense + lay.cold + lay.pinned, {}, False))
        order, padding = place(lay, groups, beam=beam, pad_budget=padding_budget)
        proposals.append(("slot-aware placement", order + lay.pinned, padding, False))
        rounds = max(1, min(3, count))
        for k in range(rounds):
            refined, pad, _ = refine(lay, order, padding, search_seconds / rounds, seed + k, padding_budget)
            proposals.append((f"refined placement (seed {seed + k})", refined + lay.pinned, pad, False))

    candidates, seen = [], set()
    for method, order, padding, baseline in proposals:
        if baseline:
            addresses = positions(model, [lay.ids[i] for i in order], baseline=True)
            base = [addresses[uid] for uid in lay.ids] + [0]
            alias, pairs = alias_cost(graph, base, 12)
            ids = [lay.ids[i] for i in order]
            record = dict(alias=round(alias, 3), padding_bytes=0, disruption=0, traces={})
            total = weighted = 0.0
            for trace in traces:
                result = cachesim.simulate(trace, addresses, frames=windows.get(trace["name"]))
                record["traces"][trace["name"]] = dict(misses=result["misses"], frames=result["frames"],
                                                       misses_per_frame=round(result["misses_per_frame"], 2),
                                                       sampled=result["sampled"])
                weighted += result["misses_per_frame"] * trace["weight"]
                total += trace["weight"]
            if total:
                record["misses_per_frame"] = round(weighted / total, 2)
            pad_ids = {}
        else:
            ids, pad_ids, addresses, record, pairs = _cost_record(lay, model, graph, order, padding, traces, windows)
        fingerprint = tuple(sorted(addresses.items()))
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        candidates.append(dict(method=method, baseline=baseline, order=ids, padding=pad_ids, addresses=addresses,
                               cost=record, conflicts=describe(graph, model["units"], pairs,
                                                               [addresses[uid] for uid in lay.ids] + [0])))
    control = candidates[0]
    # the baseline is the reference, not a proposal: it is always kept, and
    # `count` bounds the alternatives the report offers instead.
    alternatives = sorted((c for c in candidates if not c["baseline"]), key=lambda c: rank_key(c["cost"]))[:count]
    for i, candidate in enumerate(alternatives):
        candidate["id"] = f"layout-{i + 1:02d}"
    retained = sorted([control] + alternatives, key=lambda c: (rank_key(c["cost"]), not c["baseline"]))
    control["id"] = "baseline"
    for i, candidate in enumerate(retained):
        candidate["rank"] = i + 1
        candidate["predicted_delta"] = dict(
            alias=round(candidate["cost"]["alias"] - control["cost"]["alias"], 3),
            misses_per_frame=round(candidate["cost"].get("misses_per_frame", 0)
                                   - control["cost"].get("misses_per_frame", 0), 2) if traces else None)
    return retained
