"""MIPS III control flow. Delay slots belong to the transfer's basic block."""
from __future__ import annotations


def transfer(pc, word):
    op, rs, rt, fn = word >> 26, (word >> 21) & 31, (word >> 16) & 31, word & 63
    signed = (word & 0xffff) - (0x10000 if word & 0x8000 else 0)
    target = (pc + 4 + signed * 4) & 0xffffffff
    if op in (2, 3):
        return dict(kind="call" if op == 3 else "jump", target=((pc + 4) & 0xf0000000) | ((word & 0x3ffffff) << 2), conditional=False, likely=False, delay=True)
    if op == 0 and fn in (8, 9):
        # jalr $zero,$reg does not establish a return address.
        kind = "indirect_call" if fn == 9 and (word >> 11) & 31 else ("return" if rs == 31 else "indirect_jump")
        return dict(kind=kind, target=None, conditional=False, likely=False, delay=True)
    regimm = op == 1 and rt in (0, 1, 2, 3, 16, 17, 18, 19)
    copbranch = op in (16, 17, 18) and rs == 8
    if op in (4, 5, 6, 7, 20, 21, 22, 23) or regimm or copbranch:
        link = regimm and rt >= 16
        unconditional = (op == 4 and rs == rt) or (regimm and rt in (1, 17) and rs == 0)
        likely = op in (20, 21, 22, 23) or (regimm and rt in (2, 3, 18, 19)) or (copbranch and bool(rt & 2))
        return dict(kind="call" if link else "branch", target=target,
                    conditional=not unconditional, likely=likely, delay=True)
    if word == 0x42000018 or (op == 0 and fn in (12, 13)):
        return dict(kind="exit", target=None, conditional=False, likely=False, delay=False)
    return None


def control_flow(words):
    if not words:
        return dict(blocks=[], loops=[], transfers=[], warnings=[])
    start, end = words[0][0], words[-1][0] + 4
    decoded = {pc: transfer(pc, word) for pc, word in words}
    leaders, transfers, warnings = {start}, [], []
    for pc, tr in decoded.items():
        if not tr:
            continue
        tr = dict(tr, address=pc)
        transfers.append(tr)
        following = pc + (8 if tr["delay"] else 4)
        if following < end:
            leaders.add(following)
        if tr["target"] is not None and start <= tr["target"] < end:
            leaders.add(tr["target"])
        if tr["delay"] and decoded.get(pc + 4):
            warnings.append(f"control transfer in delay slot at 0x{pc + 4:08x}")
    for tr in transfers:
        if tr["delay"] and tr["address"] + 4 in leaders:
            warnings.append(f"branch targets delay slot at 0x{tr['address'] + 4:08x}")
    boundaries = sorted(leaders) + [end]
    blocks = []
    for a, b in zip(boundaries, boundaries[1:]):
        inside = [t for t in transfers if a <= t["address"] < b]
        tr = inside[-1] if inside else None
        succ = []
        if tr:
            target = tr["target"]
            if tr["kind"] in ("jump", "branch") and target in leaders:
                succ.append(target)
            if tr["kind"] in ("call", "indirect_call") or tr["conditional"]:
                if b < end:
                    succ.append(b)
        elif b < end:
            succ.append(b)
        blocks.append(dict(start=a, end=b, successors=sorted(set(succ)),
                           delay_slot_annulled_on_not_taken=bool(tr and tr["likely"])))
    # Dominator-based natural loops: a backwards branch alone is not proof of a loop.
    graph = {b["start"]: b["successors"] for b in blocks}
    reachable, pending = set(), [start]
    while pending:
        node = pending.pop()
        if node not in reachable:
            reachable.add(node)
            pending.extend(graph.get(node, []))
    pred = {n: set() for n in reachable}
    for a in reachable:
        for b in graph[a]:
            pred[b].add(a)
    dom = {n: ({start} if n == start else set(reachable)) for n in reachable}
    changed = True
    while changed:
        changed = False
        for n in sorted(reachable - {start}):
            value = {n} | set.intersection(*(dom[p] for p in pred[n]))
            if value != dom[n]:
                dom[n], changed = value, True
    loops = {}
    for a in sorted(reachable):
        for b in graph[a]:
            if b not in dom[a]:
                continue
            body, todo = {b, a}, ([] if a == b else [a])
            while todo:
                n = todo.pop()
                for p in pred[n]:
                    if p not in body:
                        body.add(p)
                        todo.append(p)
            loops.setdefault(b, set()).update(body)
    return dict(blocks=blocks, loops=[dict(header=h, blocks=sorted(body)) for h, body in sorted(loops.items())],
                transfers=transfers, warnings=warnings)
