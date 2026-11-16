"""脱敏影响视图：授权列可见，范围外节点只作匿名连接。

共享结果里只有三层信息：
1. 授权列（按名或按身份给展示名）；
2. 从授权列出发的受影响节点，一律换成匿名编号；
3. 节点之间的依赖连接，两端都匿名。

表名、列名、SQL 原文、断链明细、运行清单摘要都不出现。
闭包来自已存的 impact 结果，这里只做裁剪与匿名，不重算血缘。
"""

from __future__ import annotations

from app.modules.m8_sharing import scope as scope_mod


def _impact_nodes(run: dict, labels: dict[str, str]) -> tuple[dict[str, dict],
                                                              dict[str, list[str]]]:
    """从已存影响面里挑出受影响节点，并记下命中的授权列。"""
    impact = (run.get("impact") or {}).get("impact") or {}
    all_rows = {row["name"]: row for row in impact.get("rows") or []}
    hits: dict[str, list[str]] = {}
    for name, row in all_rows.items():
        because = sorted({labels[label] for label in row.get("fields") or []
                          if label in labels})
        if because:
            hits[name] = because
    return all_rows, hits


def _column_rows(run: dict, resolved: dict, hits: dict[str, list[str]]) -> list[dict]:
    """每个授权列一行：是否在本次判定中有破坏、原因码、影响节点数。"""
    fields = resolved["fields"]
    display = resolved["display_by_field"]
    diff_by_field = {row["field_id"]: row for row in run.get("diff") or []}
    counts: dict[str, int] = {}
    for because in hits.values():
        for column in because:
            counts[column] = counts.get(column, 0) + 1

    rows: list[dict] = []
    for field_id, column in display.items():
        if field_id not in fields:
            continue
        diff = diff_by_field.get(field_id) or {}
        rows.append({
            "column": column,
            "change": diff.get("change"),
            "verdict": diff.get("verdict"),
            "type_detail": diff.get("type_detail") if diff.get("verdict") == "BREAKING" else None,
            "required_change": diff.get("required_change"),
            "reason": diff.get("primary") if diff.get("verdict") == "BREAKING" else None,
            "direct_nodes": counts.get(column, 0),
        })
    rows.sort(key=lambda item: item["column"])
    return rows


def build(run: dict, resolved: dict, anon: scope_mod.Anonymizer) -> dict:
    labels: dict[str, str] = resolved["labels"]
    scope_columns = resolved["columns"]
    all_rows, seeds = _impact_nodes(run, labels)

    id_by_name: dict[str, str] = {}

    def node_id(name: str) -> str:
        if name not in id_by_name:
            id_by_name[name] = anon(name)
        return id_by_name[name]

    # 直接受授权列影响的节点，再从这些起点沿 via 向下扩展：
    # 下游节点自身没有授权列，但上游被授权列影响，仍属于同一条影响路径。
    children: dict[str, list[str]] = {}
    for name, row in all_rows.items():
        raw = row.get("via") or ""
        if raw in ("field", "broken", ""):
            continue
        children.setdefault(raw, []).append(name)

    kept: dict[str, dict] = {}
    queue: list[tuple[str, int, str | None]] = [(name, 0, None) for name in sorted(seeds)]
    while queue:
        name, parent_depth, parent = queue.pop(0)
        if name in kept or name not in all_rows:
            continue
        depth = parent_depth + 1 if parent is not None else 1
        kept[name] = {
            "node": node_id(name),
            "kind": all_rows[name].get("kind") or "task",
            "depth": depth,
            "via": "scope" if parent is None else "upstream",
            "via_node": node_id(parent) if parent is not None else None,
            "because": seeds.get(name, []),
        }
        for child in sorted(children.get(name, ())):
            queue.append((child, depth, name))

    nodes = sorted(kept.values(), key=lambda item: (item["depth"], item["node"]))
    edges: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for item in nodes:
        if item["via_node"] is None:
            continue
        pair = (item["via_node"], item["node"])
        if pair in seen:
            continue
        seen.add(pair)
        edges.append({"from": pair[0], "to": pair[1]})

    depth_counts: dict[str, int] = {}
    for node in nodes:
        key = str(node["depth"])
        depth_counts[key] = depth_counts.get(key, 0) + 1

    return {
        "columns": _column_rows(run, resolved, seeds),
        "nodes": nodes,
        "edges": sorted(edges, key=lambda item: (item["from"], item["to"])),
        "total": len(nodes),
        "depth_counts": depth_counts,
        "max_depth": max((node["depth"] for node in nodes), default=0),
        "scope_columns": scope_columns,
        "warnings": list(resolved["warnings"]),
    }
