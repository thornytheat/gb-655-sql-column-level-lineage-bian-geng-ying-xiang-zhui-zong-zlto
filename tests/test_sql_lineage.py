"""SQL 列级血缘反例与不变量。"""

from app.modules.m5_impact.sql_lineage import extract_edges, reverse_impact


def test_alias_columns_form_two_edges():
    result = extract_edges([{"target": "dm.gross", "expression": "o.amount + o.tax"}])
    assert [edge["source"] for edge in result["edges"]] == ["o.amount", "o.tax"]


def test_sources_are_order_independent():
    left = extract_edges([{"target": "gross", "expression": "o.tax + o.amount"}])
    right = extract_edges([{"target": "gross", "expression": "o.amount + o.tax"}])
    assert left["edges"] == right["edges"]


def test_missing_source_is_quarantined():
    result = extract_edges([{"target": "gross", "expression": "42"}])
    assert result["conflicts"][0]["reason"] == "LINEAGE_EMPTY"


def test_missing_target_is_quarantined():
    result = extract_edges([{"expression": "o.amount + o.tax"}])
    assert result["conflicts"][0]["target"] == "?"


def test_as_alias_supplies_target():
    result = extract_edges([{"expression": "o.amount + o.tax AS gross"}])
    assert result["targets"] == 1


def test_conflicting_target_keeps_evidence():
    result = extract_edges([{"target": "gross", "expression": "o.amount + o.tax"}, {"target": "gross", "expression": "o.amount"}])
    assert result["conflicts"] == [{"line": 2, "target": "gross", "reason": "TARGET_CONFLICT"}]


def test_reverse_impact_walks_multiple_hops():
    edges = [{"source": "ods.amount", "target": "dm.gross"}, {"source": "dm.gross", "target": "rpt.sales"}]
    assert reverse_impact(edges, ["ods.amount"]) == ["dm.gross", "rpt.sales"]


def test_reverse_impact_is_cycle_safe():
    edges = [{"source": "a", "target": "b"}, {"source": "b", "target": "a"}]
    assert reverse_impact(edges, ["a"]) == ["b"]
