"""Address arithmetic, opt-in GNU ld script generation and relink verification."""
from __future__ import annotations

from collections import defaultdict
from pathlib import Path
import re


def align(value, alignment):
    return (value + alignment - 1) // alignment * alignment


def positions(model, order, baseline=False, padding=None):
    """Addresses each unit would get from `order`. `padding` adds bytes in front
    of a unit (emitted as `. = . + n;` before its selector)."""
    units = {u["id"]: u for u in model["units"]}
    addresses = {u["id"]: u["address"] for u in model["units"]}
    region = [u for u in model["units"] if u["region"]]
    if baseline or not region:
        return addresses
    if set(order) != {u["id"] for u in region} or len(order) != len(region):
        raise ValueError("layout is not a permutation of the placement region")
    cursor = min(u["address"] for u in region)
    for uid in order:
        u = units[uid]
        if padding:
            cursor += padding.get(uid, 0)
        cursor = align(cursor, u["align"])
        addresses[uid] = cursor
        cursor += u["size"]
    # Suffix addresses are estimates until relinking, with their own input alignment.
    old_end = max(u["address"] + u["size"] for u in region)
    for u in model["units"]:
        if u["address"] >= old_end and not u["region"] and u.get("output") == ".text":
            cursor = align(cursor, u["align"])
            addresses[u["id"]] = cursor
            cursor += u["size"]
    return addresses


def disruption(model, order):
    """Sum of absolute index changes against the original region order."""
    original = [u["id"] for u in model["units"] if u["region"]]
    index = {uid: i for i, uid in enumerate(original)}
    return sum(abs(index[uid] - i) for i, uid in enumerate(order))


def script_blocker(model):
    """Why linker scripts cannot be generated, in terms of what to change."""
    unreadable = [w for w in model["warnings"] if w.startswith("Cannot verify linker input ")]
    if unreadable:
        paths = [w[len("Cannot verify linker input "):].rsplit(": ", 1)[0] for w in unreadable]
        shown = "\n  ".join(paths[:3])
        if len(paths) > 3:
            shown += f"\n  ... and {len(paths) - 3} more"
        return (f"cannot read {len(unreadable)} of the linker's input objects, so their sections cannot be "
                f"verified:\n  {shown}\n"
                "The map names inputs relative to the directory the linker ran from; pass that directory as "
                "--build-dir (usually the project root, not its build/ subdirectory).")
    if not any(u["movable"] for u in model["units"]):
        return ("no input section can be moved: none is a uniquely named .text.* section in the reorderable region. "
                "Build with -ffunction-sections and give assembly symbols .type/.size.")
    return "linker script generation requires a verified map and readable input objects"


def script_variant(script, model, candidate):
    if not model["script_ready"]:
        raise ValueError(script_blocker(model))
    # Deliberately support the existing libdragon placement idiom, not arbitrary ld grammar.
    pattern = r"(?m)^([ \t]*)\*\(\.text\.\*\)[ \t]*$"
    matches = list(re.finditer(pattern, script))
    if len(matches) != 1:
        raise ValueError("expected exactly one standalone *(.text.*) wildcard in linker script")
    text_blocks = list(re.finditer(r"(?m)^[ \t]*\.text(?:[ \t]+0x[\da-fA-F]+)?[ \t]*:[ \t]*\{([^}]*)\}", script))
    if len(text_blocks) != 1 or not text_blocks[0].start(1) <= matches[0].start() < text_blocks[0].end(1):
        raise ValueError("unsupported linker script: wildcard must be inside the ordinary .text output block")
    before = script[text_blocks[0].start(1):matches[0].start()]
    if re.search(r"\(\s*\.text\.", before):
        raise ValueError("unsupported earlier .text.* selectors would override the generated order")
    if candidate["baseline"]:
        return script
    units = {u["id"]: u for u in model["units"]}
    padding = candidate.get("padding") or {}
    selected = [uid for uid in candidate["order"] if units[uid]["movable"]]
    names = [units[uid]["section"] for uid in selected]
    if len(names) != len(set(names)):
        raise ValueError("ambiguous section selectors")
    if any(uid not in units or not units[uid]["movable"] for uid in padding):
        raise ValueError("padding can only precede a selected input section")
    match = matches[0]
    indent = match[1]
    body = [indent + "/* MipsFit: verified unique input sections; GC remains enabled */"]
    for uid in selected:
        pad = padding.get(uid, 0)
        if pad:
            if pad < 0 or pad % 4:
                raise ValueError("padding must be a non-negative multiple of 4")
            body.append(f"{indent}. = . + {pad};  /* MipsFit: cache-line offset */")
        body.append(indent + "*(" + units[uid]["section"] + ")")
    body.append(indent + "*(.text.*)")
    return script[:match.start()] + "\n".join(body) + script[match.end():]


def check_inputs(model):
    from .elf import sha256
    for item in model["inputs"]:
        if sha256(item["path"]) != item["sha256"]:
            raise ValueError(f"input changed since analysis: {item['path']}; reanalyze before linking")


def actual_addresses(model, new_model):
    """Match stable input-section identities, or symbols for ELF-only comparisons."""
    fresh = {u["id"]: u for u in new_model["units"]}
    addresses = {}
    if model["map"]:
        for old in model["units"]:
            new = fresh.get(old["id"])
            if not new or new["size"] != old["size"] or new["align"] != old["align"]:
                raise ValueError(f"placement unit missing or changed: {old['id']}")
            addresses[old["id"]] = new["address"]
        if set(fresh) != set(addresses):
            raise ValueError("executable input-section set changed")
    else:
        symbols = defaultdict(list)
        for f in new_model["functions"]:
            for name in f["names"]:
                symbols[name].append(f)
        for u in model["units"]:
            f = model["functions"][u["functions"][0]]
            matches = [match for name in f["names"] for match in symbols[name]]
            if not matches or len({m["address"] for m in matches}) != 1 or any(m["size"] != f["size"] for m in matches):
                raise ValueError(f"function missing or changed: {f['name']}")
            addresses[u["id"]] = matches[0]["address"]
    if model["entry"] != new_model["entry"]:
        raise ValueError("ELF entry point changed")
    for name in ("_start", "__text_start", "__intvectors_end"):
        if model["special_symbols"].get(name) != new_model["special_symbols"].get(name):
            raise ValueError(f"required linker symbol moved: {name}")
    for u in model["units"]:
        if u.get("section") in (".boot", ".intvectors") and addresses[u["id"]] != u["address"]:
            raise ValueError(f"required section moved: {u['section']}")
    return addresses
