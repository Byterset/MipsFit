"""Function/section model, source lookup, and offset-level static relationships."""
from __future__ import annotations

import bisect
from collections import Counter, defaultdict
from pathlib import Path
import re
import subprocess

from .elf import Elf, input_elfs, sha256
from .mips import control_flow


def run_tool(prefix, name, args, stdin=None):
    result = subprocess.run([prefix + name, *map(str, args)], input=stdin, text=True,
                            encoding="utf-8", errors="replace", capture_output=True, timeout=120)
    if result.returncode:
        raise ValueError(f"{name}: {result.stderr.strip()}")
    return result.stdout


def parse_map(text):
    if "Linker script and memory map" not in text:
        raise ValueError("expected GNU ld map with 'Linker script and memory map'")
    text = text.split("Linker script and memory map", 1)[1]
    rows, loads, pending, output = [], [], None, None
    name_only = re.compile(r"^ (\.[^\s]+|keep\.text[^\s]*)\s*$")
    row = re.compile(r"^ (\.[^\s]+|keep\.text[^\s]*)\s+(0x[\da-fA-F]+)\s+(0x[\da-fA-F]+)\s+(.+?)\s*$")
    continuation = re.compile(r"^\s+(0x[\da-fA-F]+)\s+(0x[\da-fA-F]+)\s+(.+?)\s*$")
    for line in text.splitlines():
        if line.startswith("Cross Reference Table"):
            break
        if line.startswith("LOAD "):
            loads.append(line[5:].strip())
        top = re.match(r"^(\.[^\s]+)\s+0x[\da-fA-F]+\s+0x[\da-fA-F]+", line)
        if top:
            output = top[1]
        match = row.match(line)
        if match:
            name, address, size, owner = match.groups()
        elif pending and (match := continuation.match(line)):
            name = pending
            address, size, owner = match.groups()
        else:
            match = name_only.match(line)
            pending = match[1] if match else None
            continue
        pending = None
        if int(size, 16) and not owner.startswith(("load address", "0x")):
            rows.append(dict(section=name, address=int(address, 16), size=int(size, 16), owner=owner, output=output))
    return rows, list(dict.fromkeys(loads))


def resolve_input(owner, build_dir):
    member = ""
    match = re.match(r"^(.*)\(([^()]*)\)$", owner)
    if match:
        owner, member = match.groups()
    path = Path(owner.replace("\\", "/"))
    if not path.is_absolute():
        path = Path(build_dir) / path
    return path.resolve(), member


def function_ranges(elf):
    by_address = defaultdict(list)
    executable = {s["index"]: s for s in elf.executable()}
    for symbol in elf.symbols:
        if symbol["type"] == 2 and symbol["section"] in executable and symbol["name"]:
            if symbol["other"] & 0xf0:
                raise ValueError("MIPS16/microMIPS or unsupported symbol attributes; only ordinary MIPS code is supported")
            by_address[symbol["address"]].append(symbol)
    functions = []
    addresses = sorted(by_address)
    for i, address in enumerate(addresses):
        symbols = by_address[address]
        section = executable[symbols[0]["section"]]
        size = max(s["size"] for s in symbols)
        inferred = size == 0
        if inferred:
            limit = section["address"] + section["size"]
            if i + 1 < len(addresses):
                limit = min(limit, addresses[i + 1])
            size = limit - address
        if size <= 0 or address + size > section["address"] + section["size"]:
            continue
        names = sorted(set(s["name"] for s in symbols))
        f = dict(address=address, size=size, names=names, name=names[0], source="??:0", inferred_size=inferred,
                 executable_section=section["name"])
        if functions and address < functions[-1]["address"] + functions[-1]["size"]:
            # Overlapping symbols are a single analysis range; never split their storage.
            prev = functions[-1]
            prev["size"] = max(prev["size"], address + size - prev["address"])
            prev["names"] += names
            prev["overlapping_symbols"] = True
        else:
            functions.append(f)
    return functions


def make_model(elf_path, prefix="mips64-elf-", map_path=None, build_dir=None, source_lookup=True):
    elf_path = Path(elf_path).resolve()
    elf = Elf.read(elf_path)
    if elf.type != 2 or not elf.symbols:
        raise ValueError("analysis requires an unstripped, linked executable ELF")
    if elf.flags & 0x06000000:
        raise ValueError("MIPS16/microMIPS ELF is unsupported")
    functions = function_ranges(elf)
    if not functions:
        raise ValueError("no CPU function symbols found")
    warnings = []
    if source_lookup:
        text = run_tool(prefix, "addr2line", ["-e", elf_path, "-f", "-C"],
                        "".join(f"0x{f['address']:x}\n" for f in functions)).splitlines()
        if len(text) != 2 * len(functions):
            raise ValueError("unexpected addr2line output")
        for i, f in enumerate(functions):
            f["name"], f["source"] = text[2 * i:2 * i + 2]
    units, inputs, script_ready = [], [], False
    if map_path:
        rows, loads = parse_map(Path(map_path).read_text(encoding="utf-8", errors="replace"))
        build_dir = Path(build_dir or elf_path.parent.parent).resolve()
        inventory, section_counts, files = {}, Counter(), {}
        owners = set(loads) | {r["owner"] for r in rows if r["output"] == ".text"}
        for owner in sorted(owners):
            path, _ = resolve_input(owner, build_dir)
            if path in files:
                continue
            try:
                members = list(input_elfs(path))
                files[path] = members
                inputs.append(dict(path=str(path), sha256=sha256(path)))
                for member, obj in members:
                    for section in obj.executable():
                        section_counts[section["name"]] += 1
                        inventory.setdefault((str(path), member, section["name"]), []).append((section, obj))
            except (OSError, ValueError) as exc:
                files[path] = []
                warnings.append(f"Cannot verify linker input {path}: {exc}")
        all_inputs_read = not warnings
        executable = elf.executable()
        seen_ids = Counter()
        for row in rows:
            if not any(s["address"] <= row["address"] and row["address"] + row["size"] <= s["address"] + s["size"] for s in executable):
                continue
            path, member = resolve_input(row["owner"], build_dir)
            uid = path.as_posix() + (f"({member})" if member else "") + ":" + row["section"]
            seen_ids[uid] += 1
            if seen_ids[uid] > 1:
                uid += f"#{seen_ids[uid]}"
            found = inventory.get((str(path), member, row["section"]), [])
            verified = len(found) == 1 and found[0][0]["size"] == row["size"]
            alignment = found[0][0]["align"] if verified else 32
            in_region = row["output"] == ".text" and row["section"].startswith(".text.")
            safe_name = bool(re.fullmatch(r"[.a-zA-Z0-9_$]+", row["section"]))
            movable = all_inputs_read and verified and in_region and safe_name and section_counts[row["section"]] == 1
            units.append(dict(row, id=uid, align=max(alignment, 1), movable=movable, region=in_region,
                              functions=[], verified=verified))
        units.sort(key=lambda u: u["address"])
        for a, b in zip(units, units[1:]):
            if a["address"] + a["size"] > b["address"]:
                raise ValueError("overlapping map input sections; unsupported map")
        script_ready = all_inputs_read and any(u["movable"] for u in units)
        # Validate map/symbol correspondence against the original input symbols.
        final_symbols = defaultdict(set)
        for s in elf.symbols:
            if s["type"] == 2:
                final_symbols[s["name"]].add(s["address"])
        for u in units:
            path, member = resolve_input(u["owner"], build_dir)
            found = inventory.get((str(path), member, u["section"]), [])
            if len(found) != 1:
                continue
            section, obj = found[0]
            for s in obj.symbols:
                if s["type"] == 2 and s["section"] == section["index"] and s["name"] in final_symbols:
                    if u["address"] + s["address"] not in final_symbols[s["name"]]:
                        raise ValueError(f"map/input/ELF mismatch at {s['name']}")
    else:
        for f in functions:
            region = f["executable_section"] == ".text" and "_start" not in f["names"]
            units.append(dict(id=f["names"][0] + f"@{f['address']:08x}", address=f["address"], size=f["size"],
                              align=32 if f["address"] % 32 == 0 else 4, movable=not f["inferred_size"],
                              region=region, functions=[], section=None, owner=None, verified=False))
        warnings.append("ELF-only orders use function ranges and estimated padding; supply a map and input objects for linker scripts.")
    starts = [u["address"] for u in units]

    def locate(address):
        i = bisect.bisect_right(starts, address) - 1
        if i >= 0 and address < units[i]["address"] + units[i]["size"]:
            return units[i]
        return None

    relationships, unresolved = [], []
    fstarts = [f["address"] for f in functions]

    def find_function(address):
        i = bisect.bisect_right(fstarts, address) - 1
        return functions[i] if i >= 0 and address < functions[i]["address"] + functions[i]["size"] else None

    def endpoint(address, length=4):
        unit = locate(address)
        if not unit:
            return None
        return dict(unit=unit["id"], offset=address - unit["address"], length=min(length, unit["address"] + unit["size"] - address))

    def connect(a, b, weight, reason, call_address):
        if a and b and a != b:
            relationships.append(dict(a=a, b=b, weight=weight, reason=reason, call_address=call_address))

    for fi, f in enumerate(functions):
        unit = locate(f["address"])
        if unit and f["address"] + f["size"] <= unit["address"] + unit["size"]:
            unit["functions"].append(fi)
            f["unit"], f["offset"] = unit["id"], f["address"] - unit["address"]
        else:
            f["unit"], f["offset"] = None, 0
            warnings.append(f"Function not covered by one map section: {f['name']}")
        flow = control_flow(elf.words(f["address"], f["size"]))
        f.update(flow)
        f["cache_lines"] = ((f["address"] & 31) + f["size"] + 31) // 32
        f["cache_slots"] = sorted({((f["address"] // 32) + i) & 511 for i in range(f["cache_lines"])})
        for tr in flow["transfers"]:
            pc, target = tr["address"], tr["target"]
            if tr["kind"] in ("indirect_call", "indirect_jump"):
                unresolved.append(dict(function=f["name"], address=pc, kind=tr["kind"]))
            is_call = tr["kind"] == "call"
            is_tail = tr["kind"] in ("jump", "branch") and target is not None and not f["address"] <= target < f["address"] + f["size"]
            if not (is_call or is_tail):
                continue
            target_function = find_function(target)
            if not target_function:
                unresolved.append(dict(function=f["name"], address=pc, kind="unresolved_direct", target=target))
                continue
            block = next((b for b in flow["blocks"] if b["start"] <= pc < b["end"]), None)
            in_loop = bool(block and any(block["start"] in loop["blocks"] for loop in flow["loops"]))
            weight = 8 if in_loop else 1
            # The first 32 bytes are a bounded entry footprint, not the whole callee.
            entry_length = min(32, target_function["address"] + target_function["size"] - target)
            entry = endpoint(target, entry_length)
            caller_start = max(block["start"] if block else f["address"], pc - 24)
            connect(endpoint(caller_start, pc + 8 - caller_start), entry, weight,
                    "loop-call" if in_loop else ("tail-call" if is_tail else "call"), pc)
            if is_call and pc + 8 < f["address"] + f["size"]:
                connect(endpoint(pc + 8, min(32, f["address"] + f["size"] - pc - 8)), entry,
                        weight, "return-continuation", pc)
    if map_path:
        for unit in units:
            if any(functions[i]["inferred_size"] or functions[i]["warnings"] for i in unit["functions"]):
                unit["movable"] = False
    special = {s["name"]: s["address"] for s in elf.symbols if s["name"] in ("_start", "__text_start", "__intvectors_end", "__text_end", "__bss_end", "__rom_end")}
    executable_bytes = sum(s["size"] for s in elf.executable())
    symbol_bytes = sum(f["size"] for f in functions)
    metrics = dict(executable_bytes=executable_bytes, symbol_range_bytes=symbol_bytes,
                   unattributed_bytes=max(0, executable_bytes - symbol_bytes),
                   input_section_bytes=sum(u["size"] for u in units) if map_path else None,
                   bytes_outside_input_sections=max(0, executable_bytes - sum(u["size"] for u in units)) if map_path else None)
    return dict(version=1, elf=str(elf_path), elf_sha256=sha256(elf_path), tool_prefix=prefix,
                map=str(Path(map_path).resolve()) if map_path else None, build_dir=str(build_dir) if build_dir else None,
                entry=elf.entry, special_symbols=special, executable_sections=elf.executable(),
                functions=functions, units=units, relationships=relationships, unresolved_calls=unresolved,
                inputs=inputs, script_ready=script_ready, warnings=warnings, metrics=metrics)
