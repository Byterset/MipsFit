# MipsFit

MipsFit is a code-layout optimizer for Nintendo 64 homebrew. 
It reorders independently linkable code sections to reduce conflict misses in the
VR4300's 16 KiB, direct-mapped instruction cache.
[VR4300 CPU Manual](https://github.com/Dillonb/n64-resources/blob/master/VR4300%20CPU%20Manual.pdf) Chapter 11.

The Code is based around this [Paper](https://dl.acm.org/doi/epdf/10.1145/330249.330254) by Gloy & Smith, which describes an algorithm for code placement that uses temporal ordering information from a program trace as an information basis.

Knowing how different parts of code ran temporally gives us information how they should be placed (e.g. two pieces of code that run frequently in succession should *not* be placed in the same cache slots as that will cause a conflict and perpetually evict).

It reads an unstripped MIPS ELF and, when available, a GNU ld map and one or
more execution traces obtained from the [ares64 Fork](https://github.com/HailToDodongo/ares-64). 
It searches for better section placements, writes ready-to-use linker scripts, 
and produces a self-contained HTML report showing the estimated improvements and the cache problems that layout changes alone cannot fix.

MipsFit does not modify the input ELF, ROM, object files, or original linker
script. All generated files go to the chosen output directory.

## Requirements

- Python 3.10 or newer
- GNU MIPS binutils `addr2line` for source lookup; the usual libdragon toolchain
  prefix is `mips64-elf-`. Source lookup can be disabled.
- For trace-guided analysis, an Ares-64 build with `ARES_ENABLE_DEBUG_TOOLS` and the CPU execution-trace bindings

MipsFit has no third-party Python runtime dependencies.

## Install

From a checkout:

```sh
python -m pip install -e .
mipsfit --help
```

You can also run it without installing:

```sh
python -m mipsfit --help
```

On Windows, pass the full tool prefix when the MIPS binutils are not on
`PATH`, for example `--tool-prefix C:/libdragon/bin/mips64-elf-`.

## Workflow

```text
capture representative execution in Ares-64
        -> mipsfit analyze
        -> inspect report.html
        -> relink with a generated candidate
        -> mipsfit simulate to verify the linked placement
```

Trace-guided analysis gives the strongest results. Without a trace, MipsFit
falls back to a static call graph and labels the weaker evidence accordingly.

### 1. Capture a trace


Build Ares-64 with debug tools enabled. The trace harness is
`mipsfit/ares/trace-scenario.js` in this repository:

### Linux
```sh
ares-test mipsfit/ares/trace-scenario.js \
    build/game.z64 build/game.elf build/gameplay.xtrace 120 "Starting Game"
```

### Windows
```sh
ares-test.exe "mipsfit\ares\trace-scenario.js" \ 
    "build\game.z64" "build\gj25_cathode_quest.elf" \ "build\gameplay.xtrace" 120 "Starting Game"
```

Arguments are `<rom> <elf> <out.xtrace> [frames] [start marker]`. The harness
boots the ROM, waits for the marker when supplied (otherwise 120 VI ticks),
then captures the requested number of frames. It writes the trace and a JSON
sidecar containing the ELF SHA-256. MipsFit rejects a trace captured from a
different ELF.

The harness sets Ares-64 to use the interpreter because the recompiler skips some cache checks. For controller input or a more representative workload, copy
`trace-scenario.js` and use the `capture()` and `replay()` helpers from
`mipsfit/ares/capture.js`.

### 2. Analyze

```sh
mipsfit analyze build/game.elf \
    --map build/game.map \
    --build-dir . \
    --tool-prefix mips64-elf- \
    --linker-script /path/to/n64.ld \
    --trace build/gameplay.xtrace \
    --search-seconds 60 \
    --out build/mipsfit
```

Only `elf` and `--out` are always required. `--map` is additionally required
when generating linker scripts.

| Argument | Required | Purpose and omitted behavior |
|---|---:|---|
| `elf` | Yes | Unstripped, linked N64 MIPS ELF to analyze. |
| `--out DIR` | Yes | Output directory for the report, analysis data, traces, and optional linker scripts. |
| `--map FILE` | With `--linker-script` | GNU ld map used to identify and verify movable input sections. Without it, MipsFit estimates layouts from ELF function ranges and cannot generate linker scripts. |
| `--build-dir DIR` | No | Linker's working directory, used to resolve map-relative object paths. Defaults to the ELF's grandparent directory and is ignored without `--map`. |
| `--tool-prefix PREFIX` | No | Prefix or path for `addr2line`. Defaults to `mips64-elf-`. Should be in libdragon install location. |
| `--linker-script FILE` | No | Original GNU ld script from which candidate `.ld` files are generated. Requires `--map`; when omitted, analysis still runs but writes no linker scripts. |
| `--trace FILE[=WEIGHT]` | No | Ares CPU trace; repeat the option to combine scenarios. Weight defaults to `1`. Without traces, MipsFit uses a less precise static call graph and the resulting analysis cannot be replayed by `simulate`. |
| `--no-source` | No | Skips all `addr2line` source lookups, including those for findings. |
| `--candidates N` | No | Maximum alternatives retained in addition to the baseline. Defaults to `3`; fewer may remain after duplicate layouts are removed. |
| `--search-seconds SECONDS` | No | Total hill-climbing budget. Defaults to `30`; `0` disables refinement but retains the other placement stages. |
| `--seed N` | No | Base random seed for refinement. Defaults to `0`; time-limited results may still vary. |
| `--padding-budget BYTES` | No | Maximum explicit padding across a layout. Defaults to `0`, so placement uses reordering and cold-section spacers only. |
| `--sim-segments SEGMENTS` | No | Approximate trace-segment budget per trace used to rank candidates, sampled in frame windows. Defaults to `0`, meaning full-trace replay. This is not a frame count. |
| `--graph-segments SEGMENTS` | No | Approximate trace-segment budget for temporal-graph construction. Defaults to `4,000,000`; `0` processes the full trace. |
| `--findings N` | No | Maximum what-if findings whose savings are estimated, not a cap on all report findings. Defaults to `6`. |
| `--no-findings` | No | Skips actionable findings, their source attribution, and what-if replanning. |

The output directory contains:

- `report.html`, with candidate rankings, findings, remaining conflicts,
  function sizes, placement-unit activity figures, and a 512-slot cache map
- `layout-01.ld` through `layout-03.ld`, plus `baseline.ld`, when a supported
  map and linker script are supplied
- `model.json`, `candidates.json`, and trace replay data used by `simulate`

The report compares the direct-mapped replay with a fully associative LRU cache
of the same size. This is a reference, not a lower bound or a prediction of
achievable savings: replacement behavior and line packing can differ. Baseline
summary figures are weighted averages across all supplied traces.

### 3. Relink with a candidate

Replace the build's normal linker script with a generated candidate for one
link only. For a libdragon `Makefile.custom`, an opt-in rule can look like:

```make
ifneq ($(strip $(MIPSFIT_LAYOUT_SCRIPT)),)
N64_LDFLAGS := $(filter-out -Tn64.ld,$(N64_LDFLAGS)) -T$(MIPSFIT_LAYOUT_SCRIPT)
$(BUILD_DIR)/$(ROM_NAME).elf: $(MIPSFIT_LAYOUT_SCRIPT)
endif
```

Then force a relink using an absolute path to the candidate:

```sh
rm build/game.elf
make MIPSFIT_LAYOUT_SCRIPT=/absolute/path/to/build/mipsfit/layout-01.ld
```

The generated script retains the original boot/vector setup, output sections,
constructor lists, linker symbols, `KEEP` directives, and garbage collection.
Only verified, globally unique `.text.*` input sections are explicitly ordered.
Ambiguous or unsupported sections remain under the original fallback wildcard.

### 4. Verify the linked placement

```sh
mipsfit simulate build/mipsfit \
    --elf build/game.elf \
    --map build/game.map
```

`simulate` loads the imported traces recorded in the analysis directory's
`model.json`; the original trace paths are not needed again.

| Argument | Required | Purpose and omitted behavior |
|---|---:|---|
| `analysis` | Yes | Trace-backed output directory produced by `mipsfit analyze`. It must contain `model.json`, `candidates.json`, and the imported trace data. |
| `--elf FILE` | No | Freshly linked ELF to replay and verify. MipsFit checks unchanged inputs and fixed symbols, uses the ELF's actual addresses, and reports the matching candidate. Without it, all saved candidates are replayed and compared instead. |
| `--map FILE` | If the analysis used `--map` and `--elf` is supplied | GNU ld map belonging to the freshly linked ELF. It is optional for ELF-only analyses and ignored without `--elf`. |
| `--out FILE` | No | Writes the relink verification result and actual addresses as JSON. Without it, results are printed only; it is ignored without `--elf`. |

## What MipsFit can move

For linker-script generation, MipsFit currently expects:

- an unstripped, ordinary MIPS executable ELF
- a GNU ld map whose input objects remain readable
- code built into unique `.text.*` input sections, normally with
  `-ffunction-sections`
- one standalone `*(.text.*)` wildcard inside the ordinary `.text` output
  block of the original linker script

Sections containing several functions move as a unit. `.boot`, interrupt
vectors, plain `.text`, ambiguous sections, and unverified inputs remain fixed.
Thin archives, compressed ELF, MIPS16/microMIPS, and arbitrary custom linker
script grammars are not supported.

These constraints fit the common libdragon build layout, but the analyzer and
cache simulator are not tied to a particular game repository. Other N64
homebrew builds work when they provide the same ELF/map/section information.

## How placement is chosen

MipsFit models the VR4300 cache as 512 direct-mapped lines of 32 bytes. Its
search combines:

1. Call-chain clustering to keep related hot sections together.
2. Slot-aware placement to keep temporally interleaved code out of the same
   cache slots. Cold sections can serve as zero-cost spacers.
3. Late-acceptance hill climbing to refine the section order and optional
   padding.

Trace-backed candidates are ranked by replay through the cache model, using
sampled windows when `--sim-segments` is nonzero. The report classifies baseline
misses using a same-size fully associative LRU reference: first touch since
capture/reset, conflict when the reference hits, and capacity when it misses.
Initial LRU recency is unavailable in the trace, so early classification is
approximate. Findings suggest source or build changes where reordering is
insufficient.

## Development

Run the Python suite from the repository root:

```sh
python -m unittest discover -s tests -v
```

Set `MIPS_TOOL_PREFIX` to enable the assembler/linker integration tests:

```sh
MIPS_TOOL_PREFIX=mips64-elf- python -m unittest discover -s tests -v
```

## License

MipsFit is available under the MIT License. See [LICENSE](LICENSE).
