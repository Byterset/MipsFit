import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

from mipsfit import cachesim, findings, optimize, trace as trace_module, trg
from mipsfit.cli import main, relinked
from mipsfit.elf import Elf, input_elfs
from mipsfit.layout import actual_addresses, positions, script_variant
from mipsfit.mips import control_flow, transfer
from mipsfit.model import make_model, parse_map

HOT_A, COLD, HOT_B = 0x80001000, 0x80001020, 0x80005000


class NoElf:
    """Stands in for the ELF during trace import: no code to cross-check."""

    def words(self, address, size):
        return []


def unit(name, address, size=32, movable=True, align=32, region=True):
    return dict(id=name, address=address, size=size, align=align, movable=movable, region=region,
                functions=[], section=".text." + name, output=".text", owner=None, verified=True)


def tiny_model():
    """Two 32-byte units exactly 16 KiB apart: they share one cache slot."""
    return dict(units=[unit("a", HOT_A), unit("gap", COLD, 16352, align=4), unit("b", HOT_B)],
                relationships=[dict(a=dict(unit="a", offset=0, length=32), b=dict(unit="b", offset=0, length=32),
                                    weight=8, reason="loop-call")],
                elf="fixture.elf", elf_sha256="a" * 64, warnings=[], script_ready=True, functions=[], traces=[])


def write_trace(path, records, initial=None, recompiler=False):
    """Build a P64XTRC1 file; records are (a, b, type_and_count) triples."""
    instructions = sum(((b - a) >> 2) * (t & 0x0FFFFFFF) for a, b, t in records if t >> 28 == trace_module.RANGE)
    fills = sum(1 for _, _, t in records if t >> 28 == trace_module.FILL)
    frames = sum(1 for _, _, t in records if t >> 28 == trace_module.FRAME)
    body = list(records) + [(instructions & 0xFFFFFFFF, instructions >> 32, trace_module.TOTALS << 28),
                            (fills, 0, trace_module.TOTALS << 28 | 1),
                            (0, frames, trace_module.TOTALS << 28 | 2)]
    lines = list(initial or [0xFFFFFFFF] * 512)
    with open(path, "wb") as f:
        f.write(trace_module.MAGIC)
        f.write(struct.pack("<4I", 1, trace_module.HEADER_BYTES, 512, 1 if recompiler else 0))
        f.write(struct.pack("<Q", 0))
        f.write(struct.pack("<512I", *lines))
        for record in body:
            f.write(struct.pack("<3I", *record))
    return path


def alternating_trace(path, rounds=50, frames=5):
    """rounds alternations between the two hot units, split into frames."""
    records = []
    for i in range(rounds):
        records.append((HOT_A, HOT_A + 32, trace_module.RANGE << 28 | 1))
        records.append((HOT_B, HOT_B + 32, trace_module.RANGE << 28 | 1))
        if (i + 1) % (rounds // frames) == 0:
            records.append((i, 0, trace_module.FRAME << 28))
    return write_trace(path, records)


class TraceTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="mipsfit-trace-"))
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.model = tiny_model()

    def imported(self, path):
        return trace_module.import_trace(self.model, path, elf=NoElf())

    def test_ranges_split_at_unit_boundaries(self):
        path = write_trace(self.dir / "cross.xtrace", [(HOT_A, HOT_A + 64, trace_module.RANGE << 28 | 1)])
        trace = self.imported(path)
        segments = list(trace["segments"])
        self.assertEqual(segments[:3], [0, 0, 32])       # unit a, whole unit
        self.assertEqual(segments[3:], [1, 0, 32])       # continues into the next unit
        self.assertEqual(trace["stats"]["instructions"], 16)

    def test_contained_repeat_is_dropped_but_counted(self):
        records = [(HOT_A, HOT_A + 32, trace_module.RANGE << 28 | 1),
                   (HOT_A + 8, HOT_A + 16, trace_module.RANGE << 28 | 3)]
        trace = self.imported(write_trace(self.dir / "repeat.xtrace", records))
        self.assertEqual(len(trace["segments"]) // 3, 1)
        self.assertEqual(trace["unit_instructions"][0], 8 + 3 * 2)

    def test_code_outside_units_keeps_absolute_addresses(self):
        trace = self.imported(write_trace(self.dir / "outside.xtrace",
                                          [(0x80000180, 0x80000188, trace_module.RANGE << 28 | 1)]))
        self.assertEqual(list(trace["segments"]), [3, 0x80000180, 0x80000188])
        self.assertEqual(trace["stats"]["outside_units"], 2)

    def test_incomplete_and_foreign_traces_are_rejected(self):
        path = self.dir / "partial.xtrace"
        write_trace(path, [(HOT_A, HOT_A + 32, trace_module.RANGE << 28 | 1)])
        data = path.read_bytes()
        path.write_bytes(data[:-36])  # drop the totals records
        with self.assertRaisesRegex(ValueError, "incomplete"):
            self.imported(path)
        other = write_trace(self.dir / "other.xtrace", [(HOT_A, HOT_A + 32, trace_module.RANGE << 28 | 1)])
        Path(str(other) + ".json").write_text(json.dumps(dict(elf_sha256="b" * 64)), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "different ELF"):
            self.imported(other)

    def test_save_and_load_round_trip(self):
        trace = self.imported(alternating_trace(self.dir / "alt.xtrace"))
        name = trace_module.save(trace, self.dir)
        again = trace_module.load(self.dir / name)
        self.assertEqual(list(again["segments"]), list(trace["segments"]))
        self.assertEqual(again["stats"], trace["stats"])


class CacheTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="mipsfit-cache-"))
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.model = tiny_model()
        self.trace = trace_module.import_trace(self.model, alternating_trace(self.dir / "alt.xtrace"), elf=NoElf())

    def test_aliasing_units_miss_every_time(self):
        baseline = positions(self.model, [u["id"] for u in self.model["units"]], baseline=True)
        result = cachesim.simulate(self.trace, baseline)
        self.assertEqual(result["misses"], 100)  # every one of the 50 alternations evicts both lines
        self.assertEqual(result["frames"], 5)
        self.assertEqual(result["cycles"], 100 * cachesim.MISS_CYCLES)

    def test_moving_one_unit_removes_the_conflict(self):
        moved = positions(self.model, ["a", "b", "gap"])
        self.assertEqual(cachesim.simulate(self.trace, moved)["misses"], 2)

    def test_associative_reference_is_the_floor(self):
        baseline = positions(self.model, [u["id"] for u in self.model["units"]], baseline=True)
        self.assertEqual(cachesim.simulate_associative(self.trace, baseline)["misses"], 2)

    def test_initial_cache_state_is_replayed(self):
        initial = [0xFFFFFFFF] * 512
        initial[(HOT_A >> 5) & 511] = HOT_A & 0x1FFFFFFF
        path = write_trace(self.dir / "warm.xtrace", [(HOT_A, HOT_A + 32, trace_module.RANGE << 28 | 1)], initial)
        warm = trace_module.import_trace(self.model, path, elf=NoElf())
        baseline = positions(self.model, [u["id"] for u in self.model["units"]], baseline=True)
        self.assertEqual(cachesim.simulate(warm, baseline)["misses"], 0)

    def test_calibration_matches_emulator_fills(self):
        records = [(HOT_A, HOT_A + 32, trace_module.RANGE << 28 | 1)]
        path = write_trace(self.dir / "fill.xtrace", [(HOT_A & 0x1FFFFFFF, 0, trace_module.FILL << 28)] + records)
        trace = trace_module.import_trace(self.model, path, elf=NoElf())
        baseline = positions(self.model, [u["id"] for u in self.model["units"]], baseline=True)
        report = cachesim.calibrate(trace, cachesim.simulate(trace, baseline))
        self.assertTrue(report["exact"])
        self.assertEqual(report["emulator_fills"], 1)


class GraphTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="mipsfit-graph-"))
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.model = tiny_model()

    def test_interleaving_becomes_edge_weight(self):
        trace = trace_module.import_trace(self.model, alternating_trace(self.dir / "alt.xtrace", rounds=4, frames=1),
                                          elf=NoElf())
        graph = trg.from_traces([trace], self.model)
        a, b = graph.ids[0 * trg.CHUNK_SPAN + (0 >> 5)], graph.ids[2 * trg.CHUNK_SPAN]
        self.assertEqual(graph.neighbors[a][b], graph.neighbors[b][a])
        self.assertGreater(graph.neighbors[a][b], 0)

    def test_alias_cost_only_counts_shared_slots(self):
        graph = trg.from_relationships(self.model)
        ids = [u["id"] for u in self.model["units"]]
        baseline = positions(self.model, ids, baseline=True)
        moved = positions(self.model, ["a", "b", "gap"])
        self.assertGreater(trg.alias_cost(graph, [baseline[i] for i in ids] + [0])[0], 0)
        self.assertEqual(trg.alias_cost(graph, [moved[i] for i in ids] + [0])[0], 0)

    def test_graph_survives_a_round_trip(self):
        graph = trg.from_relationships(self.model)
        trg.save(graph, self.dir)
        again = trg.load(self.dir / "graph.json")
        self.assertEqual(again.neighbors, graph.neighbors)
        self.assertEqual(dict(again.transitions), dict(graph.transitions))


class OptimizeTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="mipsfit-opt-"))
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.model = tiny_model()
        self.trace = trace_module.import_trace(self.model, alternating_trace(self.dir / "alt.xtrace"), elf=NoElf())

    def generate(self, **kwargs):
        graph = trg.from_traces([self.trace], self.model)
        return optimize.generate(self.model, graph, [self.trace], search_seconds=0.2, **kwargs)

    def test_search_resolves_the_conflict_and_keeps_the_control(self):
        candidates = self.generate()
        best = candidates[0]
        self.assertTrue(any(c["baseline"] for c in candidates))
        self.assertLess(best["cost"]["misses_per_frame"], 4)
        self.assertEqual(best["cost"]["traces"][self.trace["name"]]["misses"], 2)
        for candidate in candidates:
            self.assertEqual(set(candidate["order"]), {"a", "gap", "b"})

    def test_results_are_deterministic(self):
        first, second = self.generate(), self.generate()
        self.assertEqual([c["order"] for c in first], [c["order"] for c in second])

    def test_pinned_units_are_never_selected(self):
        self.model["units"][2]["movable"] = False
        candidates = self.generate()
        for candidate in candidates:
            self.assertEqual(candidate["order"][-1], "b")

    def test_padding_is_only_used_when_allowed(self):
        self.assertEqual(sum(c["cost"]["padding_bytes"] for c in self.generate()), 0)


class ScriptTests(unittest.TestCase):
    SCRIPT = "ENTRY(_start)\n.text : {\n  *(.boot)\n  *(.text.*)\n  KEEP(*(keep.text.*))\n}\n.ctors : { KEEP(*(.ctors)) }\n"

    def test_script_preserves_everything_outside_the_wildcard(self):
        model = tiny_model()
        candidate = dict(baseline=False, order=["a", "b", "gap"], padding={})
        rewritten = script_variant(self.SCRIPT, model, candidate)
        self.assertTrue(rewritten.startswith(self.SCRIPT.split("  *(.text.*)")[0]))
        self.assertTrue(rewritten.endswith(self.SCRIPT.split("  *(.text.*)")[1]))
        self.assertEqual(rewritten.count("*(.text.*)"), 1)
        self.assertIn("*(.text.a)\n  *(.text.b)", rewritten)
        self.assertEqual(script_variant(self.SCRIPT, model, dict(baseline=True)), self.SCRIPT)

    def test_padding_is_emitted_before_the_section(self):
        model = tiny_model()
        candidate = dict(baseline=False, order=["a", "b", "gap"], padding={"b": 64})
        rewritten = script_variant(self.SCRIPT, model, candidate)
        self.assertIn(". = . + 64;", rewritten)
        self.assertLess(rewritten.index(". = . + 64;"), rewritten.index("*(.text.b)"))
        with self.assertRaisesRegex(ValueError, "unsupported linker script"):
            script_variant(self.SCRIPT.replace(".text :", ".rodata :"), model, candidate)


class MipsTests(unittest.TestCase):
    def test_call_delay_slot_and_return(self):
        start = 0x80001000
        jal = (3 << 26) | ((0x80005000 >> 2) & 0x3ffffff)
        flow = control_flow([(start, jal), (start + 4, 0), (start + 8, 0x03e00008), (start + 12, 0)])
        self.assertEqual(flow["blocks"][0]["end"], start + 8)
        self.assertEqual(flow["blocks"][0]["successors"], [start + 8])
        self.assertEqual(flow["transfers"][0]["target"], 0x80005000)
        self.assertEqual(flow["transfers"][1]["kind"], "return")

    def test_likely_branch_and_natural_loop(self):
        start = 0x80001000
        # bnel a0,zero,-3: back to the start; delay slot annulled on exit.
        words = [(start, 0), (start + 4, 0), (start + 8, (21 << 26) | (4 << 21) | 0xfffd),
                 (start + 12, 0), (start + 16, 0x03e00008), (start + 20, 0)]
        flow = control_flow(words)
        self.assertEqual(flow["loops"][0]["header"], start)
        self.assertTrue(flow["blocks"][0]["delay_slot_annulled_on_not_taken"])

    def test_indirect_and_conditional_link(self):
        self.assertEqual(transfer(0x80001000, (25 << 21) | (31 << 11) | 9)["kind"], "indirect_call")
        self.assertEqual(transfer(0x80001000, (25 << 21) | 9)["kind"], "indirect_jump")
        tr = transfer(0x80001000, (1 << 26) | (4 << 21) | (19 << 16) | 12)
        self.assertEqual(tr["kind"], "call")
        self.assertTrue(tr["conditional"])
        self.assertTrue(tr["likely"])


class MapTests(unittest.TestCase):
    def test_discarded_sections_and_wrapped_names(self):
        rows, _ = parse_map("""Discarded input sections
 .text.dead 0x00000000 0x20 dead.o
Linker script and memory map
LOAD live.o
.text 0x80000400 0x60
 .text.foo
                0x80000400 0x40 live.o
                0x80000400 foo
 *fill* 0x80000440 0x20
Cross Reference Table
""")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["section"], ".text.foo")


PREFIX = os.environ.get("MIPS_TOOL_PREFIX", "mips64-elf-")
HAS_TOOLS = shutil.which(PREFIX + "as") is not None


@unittest.skipUnless(HAS_TOOLS, "set MIPS_TOOL_PREFIX to run real assembler/linker integration tests")
class LinkIntegrationTests(unittest.TestCase):
    def test_real_relink_aliases_multifunction_gc_and_verification(self):
        with tempfile.TemporaryDirectory(prefix="mipsfit-") as directory:
            root = Path(directory)
            source = root / "fixture.S"
            source.write_text(''' .set noreorder
 .section .boot,"ax",@progbits
 .globl _start
 .type _start,@function
_start: jal a
 nop
 j _start
 nop
 .size _start,.-_start
 .section .text.a,"ax",@progbits
 .balign 32
 .globl a
 .globl a_alias
 .type a,@function
 .type a_alias,@function
a:
a_alias:
 jal b
 nop
 jr $ra
 nop
 .size a,.-a
 .size a_alias,.-a_alias
 .section .text.gap,"ax",@progbits
 .balign 32
 .globl gap
 .type gap,@function
gap: .space 16384
 .size gap,.-gap
 .section .text.shared,"ax",@progbits
 .balign 32
 .globl b
 .type b,@function
b: jal c
 nop
 jal gap
 nop
 jr $ra
 nop
 .size b,.-b
 .globl c
 .type c,@function
c: jr $ra
 nop
 .size c,.-c
 .section .text.dead,"ax",@progbits
 .globl dead
 .type dead,@function
dead: jr $ra
 nop
 .size dead,.-dead
''', encoding="utf-8")
            script = root / "base.ld"
            script.write_text('''OUTPUT_ARCH(mips)
ENTRY(_start)
SECTIONS {
 .text 0x80000400 : {
  __text_start = .;
  *(.boot)
  *(.text)
  *(.text.*)
  __text_end = .;
 }
 .data : { *(.data*) }
 .bss : { *(.bss*) }
}
''', encoding="utf-8")

            def run(name, *args):
                subprocess.run([PREFIX + name, *map(str, args)], cwd=root, check=True, capture_output=True)

            run("as", "-march=vr4300", "-mabi=o64", "-o", "fixture.o", source)
            # .a produced by ld -r must not be mistaken for an archive.
            run("ld", "-r", "-o", "engine.a", "fixture.o")
            self.assertEqual(len(list(input_elfs(root / "engine.a"))), 1)
            run("ld", "--gc-sections", "-T", script, "-Map=base.map", "-o", "base.elf", "engine.a")
            model = make_model(root / "base.elf", PREFIX, root / "base.map", root)
            self.assertTrue(model["script_ready"])
            self.assertFalse(any("dead" in f["names"] for f in model["functions"]))
            alias = next(f for f in model["functions"] if "a" in f["names"])
            self.assertIn("a_alias", alias["names"])
            shared = next(u for u in model["units"] if u["section"] == ".text.shared")
            self.assertEqual(len(shared["functions"]), 2)
            graph = trg.from_relationships(model)
            cs = optimize.generate(model, graph, search_seconds=0.2)
            chosen = next(c for c in cs if not c["baseline"])
            generated = root / "candidate.ld"
            generated.write_text(script_variant(script.read_text(), model, chosen), encoding="utf-8")
            run("ld", "--gc-sections", "-T", generated, "-Map=candidate.map", "-o", "candidate.elf", "engine.a")
            new = make_model(root / "candidate.elf", PREFIX, root / "candidate.map", root)
            addresses = actual_addresses(model, new)
            self.assertFalse(any("dead" in f["names"] for f in new["functions"]))
            for u in model["units"]:
                self.assertEqual(addresses[u["id"]], chosen["addresses"][u["id"]])

            # A trace recorded against this ELF replays at the relinked addresses.
            entry = next(u for u in model["units"] if u["section"] == ".text.a")
            records = [(entry["address"], entry["address"] + 8, trace_module.RANGE << 28 | 1),
                       (0, 0, trace_module.FRAME << 28)]
            captured = write_trace(root / "capture.xtrace", records)
            Path(str(captured) + ".json").write_text(json.dumps(dict(elf_sha256=model["elf_sha256"],
                                                                     scenario="fixture")), encoding="utf-8")
            trace = trace_module.import_trace(model, captured)
            self.assertEqual(trace["stats"]["instructions"], 2)
            self.assertTrue(trace["attested"])
            self.assertEqual(cachesim.simulate(trace, chosen["addresses"])["misses"], 1)

            # the whole trace-driven pipeline through the CLI
            traced = root / "traced"
            self.assertEqual(main(["analyze", str(root / "base.elf"), "--map", str(root / "base.map"),
                                   "--build-dir", str(root), "--tool-prefix", PREFIX, "--trace", str(captured),
                                   "--search-seconds", "0.2", "--linker-script", str(script), "--out", str(traced)]), 0)
            traced_model = json.loads((traced / "model.json").read_text())
            self.assertEqual(traced_model["traces"][0]["stats"]["instructions"], 2)
            self.assertIn("calibration", traced_model["traces"][0])
            for candidate in json.loads((traced / "candidates.json").read_text()):
                self.assertIn("misses_per_frame", candidate["cost"])
            self.assertTrue((traced / "report.html").is_file())
            self.assertTrue((traced / ("trace-" + trace["name"] + ".bin")).is_file())

            # simulate against an ELF that was actually relinked: it must be
            # recognised as the candidate whose script produced it.
            best = json.loads((traced / "candidates.json").read_text())[0]
            run("ld", "--gc-sections", "-T", traced / (best["id"] + ".ld"), "-Map=relinked.map",
                "-o", "relinked.elf", "engine.a")
            self.assertEqual(main(["simulate", str(traced), "--elf", str(root / "relinked.elf"),
                                   "--map", str(root / "relinked.map"),
                                   "--out", str(root / "relinked.json")]), 0)
            self.assertEqual(json.loads((root / "relinked.json").read_text()).get("matches"), best["id"])

            # candidate.elf above used a different order, so it matches no candidate here
            other = relinked(json.loads((traced / "model.json").read_text()), traced,
                             root / "candidate.elf", root / "candidate.map")
            self.assertIsNone(other.get("matches"))
            self.assertEqual(other["closest"][0], best["id"])

    def test_zero_size_symbols_and_duplicate_archive_sections(self):
        with tempfile.TemporaryDirectory(prefix="mipsfit-") as directory:
            root = Path(directory)
            source = root / "fixture.S"
            source.write_text(''' .set noreorder
 .text
 .globl _start
 .type _start,@function
_start: jal zero_size
 nop
 jr $ra
 nop
 .size _start,.-_start
 .section .text.zero_size,"ax",@progbits
 .globl zero_size
 .type zero_size,@function
zero_size: jr $ra
 nop
''', encoding="utf-8")
            script = root / "base.ld"
            script.write_text('''OUTPUT_ARCH(mips)
ENTRY(_start)
SECTIONS { .text 0x80000400 : {
 *(.text)
 *(.text.*)
} }
''', encoding="utf-8")

            def run(name, *args):
                subprocess.run([PREFIX + name, *map(str, args)], cwd=root, check=True, capture_output=True)

            run("as", "-march=vr4300", "-mabi=o64", "-o", "one.o", source)
            duplicate = root / "duplicate.S"
            duplicate.write_text(' .section .text.zero_size,"ax",@progbits\n .word 0\n', encoding="utf-8")
            run("as", "-march=vr4300", "-mabi=o64", "-o", "two.o", duplicate)
            run("ar", "rcs", "unused.a", "two.o")
            self.assertEqual(len(list(input_elfs(root / "unused.a"))), 1)
            run("ld", "-T", script, "-Map=base.map", "-o", "base.elf", "one.o", "unused.a")
            model = make_model(root / "base.elf", PREFIX, root / "base.map", root)
            zero = next(f for f in model["functions"] if "zero_size" in f["names"])
            self.assertTrue(zero["inferred_size"])
            section = next(u for u in model["units"] if u["section"] == ".text.zero_size")
            self.assertFalse(section["movable"])


if __name__ == "__main__":
    unittest.main()
