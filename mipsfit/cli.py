from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys

from . import cachesim, findings as findings_module, optimize, trace as trace_module, trg
from .elf import sha256
from .layout import actual_addresses, check_inputs, script_blocker, script_variant
from .model import make_model
from .report import write_report


def raise_unless_script_ready(model):
    if not model["script_ready"]:
        raise ValueError(script_blocker(model))


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def load_traces(model, directory):
    """Traces recorded in a model.json, by name."""
    return [trace_module.load(Path(directory) / entry["file"]) for entry in model.get("traces", [])]


def annotate_units(model, traces, unit_misses, frames):
    """Per-unit coverage, instructions and misses for the report.

    Instructions and misses are **per frame**, like every other rate the report
    shows, so a longer capture of the same workload reports the same numbers
    instead of larger ones. `frames` maps a trace name to the frames replayed;
    traces are combined with their weights.
    """
    coverage = {}
    instructions = [0.0] * len(model["units"])
    weight = sum(t["weight"] for t in traces) or 1.0
    for trace in traces:
        share = trace["weight"] / weight / max(1, frames.get(trace["name"], 1))
        for index, count in enumerate(trace["unit_instructions"]):
            instructions[index] += count * share
        for key, spans in trace["coverage"].items():
            merged = coverage.setdefault(int(key), [])
            merged.extend(spans)
    for index, unit in enumerate(model["units"]):
        spans = sorted(coverage.get(index, []))
        executed, end = 0, -1
        for start, stop in spans:
            start = max(start, end)
            if stop > start:
                executed += stop - start
                end = stop
        unit["executed_bytes"] = executed
        unit["executed_instructions"] = round(instructions[index], 2)
        unit["misses"] = round(unit_misses.get(unit["id"], 0.0), 3)


def analyze(args):
    model = make_model(args.elf, args.tool_prefix, args.map, args.build_dir, not args.no_source)
    if args.linker_script:
        # check before the search: the scripts are the point of the run, and
        # finding out after a minute of refinement helps nobody
        if not args.map:
            raise ValueError("--linker-script requires --map")
        raise_unless_script_ready(model)
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)

    traces, names = [], set()
    for spec in args.trace or []:
        path, weight = trace_module.parse_spec(spec)
        print(f"Importing {path} ...", flush=True)
        imported = trace_module.import_trace(model, path, weight=weight)
        while imported["name"] in names:
            imported["name"] += "-2"
        names.add(imported["name"])
        traces.append(imported)
        stats = imported["stats"]
        print(f"  {stats['frames']} frames, {stats['instructions']} instructions, {stats['fills']} icache fills, "
              f"{stats['segments']} segments")
    model["traces"] = []

    graph = trg.from_traces(traces, model, frames={t["name"]: cachesim.windows(t, args.graph_segments) for t in traces}) \
        if traces else trg.from_relationships(model)
    print(f"Cost model: {graph.source}, {len(graph.active)} interleaving chunks", flush=True)

    candidates = optimize.generate(model, graph, traces, count=args.candidates, search_seconds=args.search_seconds,
                                   seed=args.seed, padding_budget=args.padding_budget, sim_segments=args.sim_segments)

    simulation, unit_misses, replayed = {}, {}, {}
    baseline = next(c for c in candidates if c["baseline"])
    best = next((c for c in candidates if not c["baseline"]), None)
    for trace in traces:
        detail = cachesim.simulate(trace, baseline["addresses"], detail=True)
        calibration = cachesim.calibrate(trace, detail)
        associative = cachesim.simulate_associative(trace, baseline["addresses"])
        entry = dict(name=trace["name"], file=trace_module.save(trace, out), weight=trace["weight"],
                     stats=trace["stats"], warnings=trace["warnings"], calibration=calibration,
                     attested=trace["attested"], scenario=trace["scenario"])
        model["traces"].append(entry)
        if not simulation:
            simulation = dict(baseline=dict(misses_per_frame=round(detail["misses_per_frame"], 2),
                                            conflict_misses=round(detail["conflict_misses"] / max(1, detail["frames"]), 2),
                                            capacity_misses=round(detail["capacity_misses"] / max(1, detail["frames"]), 2),
                                            first_misses=round(detail["first_misses"] / max(1, detail["frames"]), 2)),
                              associative=round(associative["misses_per_frame"], 2),
                              working_set=round(sum(detail["working_set"]) / max(1, len(detail["working_set"])), 1),
                              trace=trace["name"])
            simulation["baseline_detail"] = dict(pairs=detail["pairs"], slot_misses=detail["slot_misses"])
        replayed[trace["name"]] = detail["frames"]
        share = trace["weight"] / (sum(t["weight"] for t in traces) or 1.0) / max(1, detail["frames"])
        for uid, count in detail["unit_misses"].items():
            unit_misses[uid] = unit_misses.get(uid, 0.0) + count * share
        if best:
            after = cachesim.simulate(trace, best["addresses"], detail=True)
            simulation.setdefault("best", {})[trace["name"]] = dict(
                candidate=best["id"], misses_per_frame=round(after["misses_per_frame"], 2),
                conflict_misses=round(after["conflict_misses"] / max(1, after["frames"]), 2),
                pairs=after["pairs"][:20])
        if not calibration["exact"]:
            print(f"  Note: replay of {trace['name']} differs from the emulator in "
                  f"{calibration['frames_differing']} frames (captured with the {calibration['executor']})")

    annotate_units(model, traces, unit_misses, replayed)
    found = findings_module.collect(model, graph, traces, candidates, simulation, args.tool_prefix,
                                    limit=args.findings) if not args.no_findings else []

    if args.linker_script:
        script = Path(args.linker_script).read_text(encoding="utf-8")
        generated = {c["id"]: script_variant(script, model, c) for c in candidates}
        model["linker_script"] = dict(path=str(Path(args.linker_script).resolve()), sha256=sha256(args.linker_script))
        for name, text in generated.items():
            (out / (name + ".ld")).write_text(text, encoding="utf-8")
    write_report(out, model, candidates, found, simulation)
    print(f"Analyzed {len(model['functions'])} functions, {sum(u['movable'] for u in model['units'])} movable units.")
    for candidate in candidates:
        cost = candidate["cost"]
        measured = f", {cost['misses_per_frame']:g} misses/frame" if "misses_per_frame" in cost else ""
        print(f"  {candidate['rank']}. {candidate['id']}: estimated conflicts {cost['alias']:g}{measured} - {candidate['method']}")
    print(f"Wrote {len(candidates)} candidates, {len(found)} findings and {out / 'report.html'}")
    for warning in model["warnings"][:8]:
        print("Note:", warning)


def relinked(model, analysis, elf, map_path):
    """Where the units actually ended up in a freshly linked ELF, and which
    candidate that placement matches."""
    check_inputs(model)
    if model["map"] and not map_path:
        raise ValueError("the analysis used a map; --map must be the map of the newly linked ELF")
    fresh = make_model(elf, map_path=map_path, build_dir=model["build_dir"], source_lookup=False)
    addresses = actual_addresses(model, fresh)
    result = dict(elf=str(elf), elf_sha256=fresh["elf_sha256"], addresses=addresses)
    for candidate in read_json(Path(analysis) / "candidates.json"):
        mismatches = sum(addresses[u] != a for u, a in candidate["addresses"].items())
        if not mismatches:
            result["matches"] = candidate["id"]
            result.pop("closest", None)
            break
        if mismatches < result.get("closest", (None, 1 << 30))[1]:
            result["closest"] = (candidate["id"], mismatches)
    return result


def simulate_cmd(args):
    analysis = Path(args.analysis).resolve()
    model = read_json(analysis / "model.json")
    traces = load_traces(model, analysis)
    if not traces:
        raise ValueError("this analysis has no traces; rerun analyze with --trace")
    if args.elf:
        actual = relinked(model, analysis, args.elf, args.map)
        original = {u["id"]: u["address"] for u in model["units"]}
        rows = [("baseline (analyzed)", original), ("linked " + Path(args.elf).name, actual["addresses"])]
        if args.out:
            write_json(args.out, actual)
    else:
        actual = None
        rows = [(c["id"], c["addresses"]) for c in read_json(analysis / "candidates.json")]
    print(f"{'layout':28} " + " ".join(f"{t['name'][:16]:>16}" for t in traces))
    for name, addresses in rows:
        values = [f"{cachesim.simulate(trace, addresses)['misses_per_frame']:16.1f}" for trace in traces]
        print(f"{name:28} " + " ".join(values))
    print("misses per frame, replayed through the emulated 16 KiB direct-mapped icache")
    if actual:
        if "matches" in actual:
            print(f"Placement verified: the linked ELF puts every unit where {actual['matches']} predicted.")
        else:
            name, count = actual["closest"]
            print(f"Placement matches no candidate exactly; closest is {name} with {count} units at unexpected "
                  f"addresses. Check that the link really used the generated script.")


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="mipsfit",
        description="Optimize Nintendo 64 code layout for the VR4300 instruction cache",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("analyze", help="analyze a linked ELF and search for better code layouts")
    p.add_argument("elf", help="unstripped, linked N64 MIPS ELF to analyze")
    p.add_argument("--map", metavar="FILE",
                   help="GNU ld map; enables verified input-section layouts and is required with --linker-script")
    p.add_argument("--build-dir", metavar="DIR",
                   help="linker's working directory for map-relative inputs (default: ELF grandparent; ignored without --map)")
    p.add_argument("--tool-prefix", default="mips64-elf-", metavar="PREFIX",
                   help="prefix or path for addr2line (default: mips64-elf-)")
    p.add_argument("--linker-script", metavar="FILE",
                   help="original GNU ld script used to generate candidate .ld files; requires --map and is never modified")
    p.add_argument("--trace", action="append", metavar="FILE[=WEIGHT]",
                   help="Ares CPU trace; repeatable, with an optional positive weight (default: 1; omitted: use the static call graph)")
    p.add_argument("--no-source", action="store_true",
                   help="skip the initial addr2line lookup; combine with --no-findings to avoid all addr2line lookups")
    p.add_argument("--candidates", type=int, default=3,
                   help="maximum alternative layouts to retain in addition to the baseline (default: 3)")
    p.add_argument("--search-seconds", type=float, default=30.0, metavar="SECONDS",
                   help="total hill-climbing refinement budget; 0 disables refinement (default: 30)")
    p.add_argument("--seed", type=int, default=0,
                   help="base random seed for reproducible refinement (default: 0)")
    p.add_argument("--padding-budget", type=int, default=0, metavar="BYTES",
                   help="maximum explicit cache-line padding across a layout; 0 disables padding (default: 0)")
    p.add_argument("--sim-frames", dest="sim_segments", type=int, default=0,
                   metavar="SEGMENTS",
                   help="approximate trace-segment budget for candidate ranking; 0 replays the full trace (default: 0)")
    p.add_argument("--graph-segments", type=int, default=4_000_000,
                   metavar="SEGMENTS",
                   help="approximate trace-segment budget for temporal-graph construction; 0 uses the full trace (default: 4000000)")
    p.add_argument("--findings", type=int, default=6, metavar="N",
                   help="maximum what-if findings whose savings are estimated, not total report findings (default: 6)")
    p.add_argument("--no-findings", action="store_true",
                   help="skip actionable findings, source attribution, and what-if replanning")
    p.add_argument("--out", required=True, metavar="DIR",
                   help="output directory for the report, analysis data, and optional linker scripts")
    p.set_defaults(func=analyze)
    p = sub.add_parser("simulate", help="replay analyzed traces for saved or freshly linked layouts")
    p.add_argument("analysis", help="trace-backed analysis directory produced by mipsfit analyze")
    p.add_argument("--elf", metavar="FILE",
                   help="freshly linked ELF to replay and verify (omitted: compare all saved candidates)")
    p.add_argument("--map", metavar="FILE",
                   help="GNU ld map for --elf; required if the analysis used --map and ignored without --elf")
    p.add_argument("--out", metavar="FILE",
                   help="write relink verification details as JSON; only used with --elf")
    p.set_defaults(func=simulate_cmd)
    args = parser.parse_args(argv)
    try:
        if hasattr(args, "candidates") and args.candidates < 1:
            raise ValueError("--candidates must be positive")
        if hasattr(args, "search_seconds") and args.search_seconds < 0:
            raise ValueError("--search-seconds must be nonnegative")
        if hasattr(args, "padding_budget") and args.padding_budget < 0:
            raise ValueError("--padding-budget must be nonnegative")
        args.func(args)
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as exc:
        print(f"mipsfit: {exc}", file=sys.stderr)
        return 1
    return 0
