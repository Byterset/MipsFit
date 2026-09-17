"""Cache problems that reordering alone cannot fix, ranked by estimated saving.

Each finding names the code involved, says what to change, and estimates the
benefit by re-planning the layout with that change applied and comparing the
placement cost. Savings are converted to misses per frame with the ratio between
the baseline's measured conflict misses and its estimated cost, so they are
indicative, not measured.
"""
from __future__ import annotations

import copy

from . import optimize
from .model import run_tool

CACHE_BYTES = 16 * 1024
LINES = 512


def _plan_cost(lay):
    order, padding = optimize.place(lay, optimize.clusters(lay))
    return lay.cost(order + lay.pinned, padding)[0]


def _patched(model, graph, sizes=None, offsets=None, movable=None, aligns=None):
    """A Layout with unit sizes/alignments, chunk offsets or movability changed."""
    if offsets:
        graph = copy.copy(graph)
        graph.offset = list(graph.offset)
        for chunk, value in offsets.items():
            graph.offset[chunk] = value
    lay = optimize.Layout(model, graph)
    if sizes:
        lay.size = list(lay.size)
        for unit, value in sizes.items():
            lay.size[unit] = value
    if aligns:
        lay.align = list(lay.align)
        for unit, value in aligns.items():
            lay.align[unit] = value
    if movable:
        lay.movable = sorted(set(lay.movable) | movable)
        lay.pinned = [i for i in lay.pinned if i not in movable]
        touches = lay.graph.unit_touches
        lay.hot = [i for i in lay.movable if touches.get(i, 0.0) > 0]
        lay.cold = [i for i in lay.movable if touches.get(i, 0.0) <= 0]
    return lay


def _source_lines(model, prefix, addresses):
    """function at file:line for each address, in one addr2line call."""
    addresses = [a for a in dict.fromkeys(addresses)]
    if not addresses or not prefix:
        return {}
    try:
        text = run_tool(prefix, "addr2line", ["-e", model["elf"], "-f", "-C"],
                        "".join(f"0x{a:x}\n" for a in addresses)).splitlines()
    except (ValueError, OSError):
        return {}
    result = {}
    for i, address in enumerate(addresses):
        if 2 * i + 1 < len(text):
            name, where = text[2 * i], text[2 * i + 1]
            if where != "??:0":
                result[address] = f"{name} at {where}"
    return result


def _coverage(traces, index):
    spans = []
    for trace in traces:
        spans.extend(trace["coverage"].get(str(index), []))
    spans.sort()
    merged = []
    for start, stop in spans:
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], stop)
        else:
            merged.append([start, stop])
    return merged


def collect(model, graph, traces, candidates, simulation, prefix=None, limit=6):
    units = model["units"]
    index = {u["id"]: i for i, u in enumerate(units)}
    baseline = next(c for c in candidates if c["baseline"])
    best = next((c for c in candidates if not c["baseline"]), baseline)
    detail = (simulation or {}).get("baseline") or {}
    conflict_per_frame = detail.get("conflict_misses", 0.0)
    lay = optimize.Layout(model, graph)
    plan = _plan_cost(lay)
    # cost -> misses/frame: the estimate and the replay measure the same thing
    scale = (conflict_per_frame / plan) if (plan and conflict_per_frame) else 0.0
    findings, whatifs = [], []

    working_set = (simulation or {}).get("working_set")
    if working_set:
        share = [(u.get("executed_bytes", 0) // 32, u["id"]) for u in units if u.get("executed_bytes")]
        share.sort(reverse=True)
        top = ", ".join(f"{uid.rsplit(':', 1)[-1]} ({n} lines)" for n, uid in share[:5])
        if working_set > LINES:
            findings.append(dict(
                kind="capacity", title=f"Per frame the game runs through {working_set:.0f} cache lines, "
                                       f"{working_set / LINES:.1f}x what the 16 KiB cache holds",
                where="whole frame", savings=None,
                detail=f"A fully associative cache of the same size would still miss "
                       f"{(simulation or {}).get('associative', 0):g} times per frame, so most of the remaining misses "
                       f"need less code per frame, not a different order.",
                suggestion="Shrink or split the biggest per-frame contributors, or run less code per frame.",
                sources=[f"Largest executed footprints: {top}"]))
        else:
            findings.append(dict(
                kind="capacity", title=f"The per-frame working set ({working_set:.0f} lines) fits in the cache",
                where="whole frame", savings=None,
                detail="Every remaining miss is a conflict: two pieces of code competing for one slot, which the layout can fix.",
                suggestion="No code change needed for capacity; let the placement search do the work.",
                sources=[f"Largest executed footprints: {top}"]))

    # --- hot functions carrying cold code -----------------------------------
    mixed = []
    for i, unit in enumerate(units):
        executed = unit.get("executed_bytes", 0)
        if not executed or not unit["region"]:
            continue
        spans = _coverage(traces, i)
        if not spans:
            continue
        span = spans[-1][1] - spans[0][0]
        cold_inside = span - executed
        if cold_inside >= 256 and executed >= 128:
            mixed.append((cold_inside * unit.get("executed_instructions", 0), cold_inside, span, executed, i, spans))
    mixed.sort(reverse=True)
    for _, cold_inside, span, executed, i, spans in mixed[:3]:
        unit = units[i]
        chunks = graph.unit_chunks.get(i, [])
        hot_chunks = [c for c in chunks if graph.touches[c] > 0]
        offsets = {c: n * 32 for n, c in enumerate(sorted(hot_chunks, key=lambda c: graph.offset[c]))}
        whatifs.append((dict(
            kind="hot-cold-split",
            title=f"{unit['id'].rsplit(':', 1)[-1]} spreads {executed} executed bytes over {span} bytes",
            where=unit["id"], detail=f"{cold_inside} bytes inside the executed span never ran in the traces, so they take "
                                     f"{cold_inside // 32} cache lines with them whenever the hot parts are fetched.",
            suggestion="Mark the rare paths [[unlikely]] / __attribute__((cold, noinline)), or build this file with "
                       "-freorder-blocks-and-partition so GCC moves them to .text.unlikely.*",
            addresses=[unit["address"] + spans[k][1] for k in range(min(3, len(spans) - 1))]),
            dict(sizes={i: max(32, len(hot_chunks) * 32)}, offsets=offsets)))

    # --- executed code the script cannot move -------------------------------
    stuck = [(u.get("misses", 0), u.get("executed_instructions", 0), i)
             for i, u in enumerate(units) if u.get("executed_instructions") and not u["movable"]]
    stuck.sort(reverse=True)
    if stuck and stuck[0][0]:
        misses, _, i = stuck[0]
        unit = units[i]
        reason = ("it is not in the reorderable .text.* region" if not unit["region"]
                  else "its input section name is ambiguous or its size could not be verified")
        whatifs.append((dict(
            kind="pinned", title=f"{misses:g} misses per frame land in code the linker script cannot move",
            where=unit["id"], detail=f"{unit['id']} runs but stays where it is: {reason}.",
            suggestion="Build that object with -ffunction-sections (and give assembly symbols .type/.size) so each "
                       "function becomes its own movable input section.",
            addresses=[unit["address"]]),
            dict(movable={i}) if unit["region"] else None))

    # --- large hot units ----------------------------------------------------
    large = sorted(((u.get("executed_instructions", 0), u["size"], i) for i, u in enumerate(units)
                    if u["size"] >= 4096 and u.get("executed_bytes")), reverse=True)
    for instructions, size, i in large[:2]:
        unit = units[i]
        executed = unit.get("executed_bytes", 0)
        findings.append(dict(
            kind="large-unit", title=f"{unit['id'].rsplit(':', 1)[-1]} is one {size}-byte block ({size // 32} cache lines)",
            where=unit["id"], savings=None,
            detail=f"{executed} of its bytes ran. A unit moves as a whole, so its cold half keeps competing for slots "
                   f"with everything else.",
            suggestion="Split it into smaller functions, or keep rarely used branches in separate noinline helpers.",
            sources=[]))

    # --- alignment waste in hot code ----------------------------------------
    waste = sum(optimize.align(u["size"], u["align"]) - u["size"]
                for u in units if u.get("executed_bytes") and u["align"] >= 32)
    if waste >= 1024:
        hot_small = {i for i, u in enumerate(units) if u.get("executed_bytes") and u["align"] >= 32 and u["size"] < 256}
        whatifs.append((dict(
            kind="alignment", title=f"{waste} bytes of -falign-functions=32 padding sit inside executed code",
            where="hot functions", detail=f"That is {waste // 32} cache lines of padding fetched along with the code "
                                          f"around it.",
            suggestion="For the hottest small functions, relax -falign-functions for that translation unit and measure.",
            addresses=[]),
            dict(aligns={i: 4 for i in hot_small})))

    # --- estimate savings by re-planning ------------------------------------
    for description, change in whatifs[:limit]:
        savings = None
        if change and scale:
            try:
                modified = _plan_cost(_patched(model, graph, **change))
                savings = round(max(0.0, plan - modified) * scale, 2)
            except (ValueError, KeyError):
                savings = None
        sources = _source_lines(model, prefix, description.pop("addresses", []))
        findings.append(dict(savings=savings, sources=[f"{hex(a)}: {text}" for a, text in sources.items()],
                             **description))

    # --- what is left after the best layout ---------------------------------
    remaining = ((simulation or {}).get("best") or {})
    for name, entry in list(remaining.items())[:1]:
        pairs = [p for p in entry.get("pairs", []) if p["incoming"]["unit"] and p["evicted"]["unit"]][:5]
        if not pairs:
            continue
        rows = [f"{p['incoming']['unit'].rsplit(':', 1)[-1]} vs {p['evicted']['unit'].rsplit(':', 1)[-1]}: {p['count']} misses"
                for p in pairs]
        findings.append(dict(
            kind="residual", title=f"Strongest conflicts left in {entry['candidate']}", where=name, savings=None,
            detail=f"{entry['conflict_misses']:g} conflict misses per frame remain after the best candidate.",
            suggestion="If these pairs matter, shrink one side or give the search more time (--search-seconds).",
            sources=rows))
    findings.sort(key=lambda f: (f.get("savings") is None, -(f.get("savings") or 0)))
    return findings
