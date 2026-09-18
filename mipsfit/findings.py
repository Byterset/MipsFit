"""Cache problems that reordering alone cannot fix, ranked by estimated saving.

Each finding names the code involved, says what to change, and estimates the
benefit by re-planning the layout with that change applied and comparing the
placement cost. Savings are converted to misses per frame with the ratio between
the baseline's measured conflict misses and its estimated cost, so they are
indicative, not measured.
"""
from __future__ import annotations

import copy
import subprocess

from . import optimize
from .model import run_tool
from .trg import LINES, alias_cost



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
    if not addresses or prefix is None:
        return {}
    try:
        text = run_tool(prefix, "addr2line", ["-e", model["elf"], "-f", "-C"],
                        "".join(f"0x{a:x}\n" for a in addresses)).splitlines()
    except (ValueError, OSError, subprocess.SubprocessError):
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
    names_by_unit = {}
    for function in model["functions"]:
        uid, name = function.get("unit"), function["name"]
        if uid and name and name != "??":
            names = names_by_unit.setdefault(uid, [])
            if name not in names:
                names.append(name)

    def unit_name(uid):
        names = names_by_unit.get(uid, [])
        if not names:
            return uid.rsplit(":", 1)[-1]
        return ", ".join(names[:3]) + (f" +{len(names) - 3} more" if len(names) > 3 else "")

    baseline = next(c for c in candidates if c["baseline"])
    detail = (simulation or {}).get("baseline") or {}
    conflict_per_frame = detail.get("conflict_misses", 0.0)
    lay = optimize.Layout(model, graph)
    plan = _plan_cost(lay)
    baseline_cost, _ = alias_cost(graph, [baseline["addresses"][u["id"]] for u in units] + [0])
    # Calibrate the baseline replay against the graph cost of that same layout.
    scale = conflict_per_frame / baseline_cost if baseline_cost else 0.0
    findings, whatifs = [], []

    working_set = (simulation or {}).get("working_set")
    if working_set:
        peak = simulation["working_set_max"]
        share = [(u["executed_bytes"], u["id"]) for u in units if u.get("executed_bytes")]
        share.sort(reverse=True)
        top = ", ".join(f"{unit_name(uid)} ({n} executed bytes)" for n, uid in share[:5])
        if peak > LINES:
            findings.append(dict(
                kind="capacity", title=f"Peak frame touches {peak} cache lines; the cache holds {LINES}",
                where="all captured scenarios", savings=None,
                detail=f"The weighted average is {working_set:.1f} lines per frame. This indicates a large footprint, "
                       "but reuse order determines capacity misses; frame size alone does not say how many misses layout can fix.",
                suggestion="Use the capacity-miss figures to judge whether reducing executed code would help.",
                sources=[f"Largest coverage across captures: {top}"]))
        else:
            findings.append(dict(
                kind="capacity", title=f"Peak frame touches {peak} lines, within the {LINES}-line cache size",
                where="all captured scenarios", savings=None,
                detail="Each observed frame fits by line count. First touches and reuse across frames can still miss, "
                       "and fixed sections can prevent layout from eliminating conflicts.",
                suggestion="Compare replayed layouts and the miss breakdown before deciding on code changes.",
                sources=[f"Largest coverage across captures: {top}"]))

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
            title=f"{unit_name(unit['id'])} spreads {executed} executed bytes over {span} bytes",
            where=unit["id"], detail=f"{cold_inside} unexecuted bytes separate hot blocks and constrain their placement. "
                                     "Only cache lines actually touched are fetched; the gaps do not all occupy the cache.",
            suggestion="Move rare paths into separate cold, noinline helpers so the hot code can be placed more compactly.",
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
            where=unit["id"], detail=f"{unit_name(unit['id'])} runs but stays where it is: {reason}.",
            suggestion="Build that object with -ffunction-sections (and give assembly symbols .type/.size) so each "
                       "function becomes its own movable input section.",
            addresses=[unit["address"]]),
            dict(movable={i}) if unit["region"] else None))

    # --- large hot units ----------------------------------------------------
    large = sorted(((u.get("executed_instructions", 0), u["size"], i) for i, u in enumerate(units)
                    if u["size"] >= 4096 and u.get("executed_bytes")), reverse=True)
    for _, size, i in large[:2]:
        unit = units[i]
        executed = unit.get("executed_bytes", 0)
        findings.append(dict(
            kind="large-unit", title=f"{unit_name(unit['id'])} is one {size}-byte block ({size // 32} cache lines)",
            where=unit["id"], savings=None,
            detail=f"{executed} of its bytes ran. The unit moves as a whole, which limits independent placement "
                   "of its hot blocks. Unexecuted cache lines do not compete for cache slots.",
            suggestion="Split it into smaller functions, or keep rarely used branches in separate noinline helpers.",
            sources=[]))

    # --- alignment waste in hot code ----------------------------------------
    hot_small = {i for i, u in enumerate(units)
                 if u.get("executed_bytes") and u["align"] >= 32 and u["size"] < 256}
    waste = 0
    for i in hot_small:
        if i and units[i - 1].get("output") == units[i].get("output") == ".text":
            end = units[i - 1]["address"] + units[i - 1]["size"]
            if optimize.align(end, units[i]["align"]) == units[i]["address"]:
                waste += units[i]["address"] - end
    if waste >= 1024:
        whatifs.append((dict(
            kind="alignment", title=f"{waste} bytes of alignment gaps precede small hot sections",
            where="hot sections", detail="These gaps spread code across addresses. They need not be fetched, "
                                          "but relaxing alignment can change cache-line packing and slot conflicts.",
            suggestion="For the hottest small functions, relax -falign-functions for that translation unit and measure.",
            addresses=[]),
            dict(aligns={i: 4 for i in hot_small})))

    # --- estimate savings by re-planning ------------------------------------
    for index, (description, change) in enumerate(whatifs):
        savings = None
        if index < limit and change and scale:
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
    for name, entry in remaining.items():
        pairs = [p for p in entry.get("pairs", []) if p["incoming"]["unit"] and p["evicted"]["unit"]][:5]
        if not pairs:
            continue
        rows = [f"{unit_name(p['incoming']['unit'])} vs {unit_name(p['evicted']['unit'])}: {p['count']:.2f} conflict misses/frame"
                for p in pairs]
        findings.append(dict(
            kind="residual", title=f"Strongest conflicts left in {entry['candidate']}", where=name, savings=None,
            detail=f"{entry['conflict_misses']:g} conflict misses per frame remain after the best candidate.",
            suggestion="If these pairs matter, shrink one side or give the search more time (--search-seconds).",
            sources=rows))
    findings.sort(key=lambda f: (f.get("savings") is None, -(f.get("savings") or 0)))
    return findings
