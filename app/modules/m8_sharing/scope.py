"""共享授权范围：把外部协作方要求的列清单收敛成可判定的授权集合。

范围只认列：`表.列`、`{table, column}` 或 `{field_id}`。授权集合之外的
表名、列名、节点名与 SQL 原文一律不进入共享结果。
"""

from __future__ import annotations

import hashlib
import hmac

from app import config, errors

BROKEN_PREFIX = "断链 "


def _clean_text(value, field: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise errors.BadInput(
            "授权列不能为空", detail={"field": field}, code="SHARE_SCOPE_EMPTY"
        )
    if len(text) > 128:
        raise errors.BadInput("授权列名过长", detail={"field": field, "length": len(text)})
    if any(ch in text for ch in "\r\n\t\x00"):
        raise errors.BadInput("授权列名含控制字符", detail={"field": field})
    return text


def _parse_string(value: str, index: int) -> dict:
    raw = str(value).strip()
    table, sep, column = raw.rpartition(".")
    if not sep or not table or not column or "." in column:
        raise errors.BadInput(
            "授权列要写成 表.列",
            detail={"field": f"columns[{index}]", "value": value},
            code="SHARE_SCOPE_EMPTY",
        )
    return {"table": _clean_text(table, f"columns[{index}].table"),
            "column": _clean_text(column, f"columns[{index}].column")}


def parse_columns(raw) -> list[dict]:
    """把请求里的 columns 归一成去重后的 [{table, column}] 或 [{field_id}]。"""
    if not isinstance(raw, list) or not raw:
        raise errors.BadInput(
            "需要给出 columns 列表", detail={"field": "columns"}, code="SHARE_SCOPE_EMPTY"
        )
    if len(raw) > config.SHARE_MAX_SCOPE:
        raise errors.BadInput(
            "授权列过多", detail={"count": len(raw), "max": config.SHARE_MAX_SCOPE}
        )
    columns: list[dict] = []
    seen: set[tuple] = set()
    for index, item in enumerate(raw):
        if isinstance(item, str):
            entry = _parse_string(item, index)
            key = ("name", entry["table"].lower(), entry["column"].lower())
        elif isinstance(item, dict):
            if item.get("field_id") not in (None, ""):
                field_id = _clean_text(item.get("field_id"), f"columns[{index}].field_id")
                entry = {"field_id": field_id}
                key = ("id", field_id)
            else:
                entry = _parse_string(
                    f"{item.get('table') or ''}.{item.get('column') or item.get('name') or ''}",
                    index,
                )
                key = ("name", entry["table"].lower(), entry["column"].lower())
        else:
            raise errors.BadInput(
                "授权列只能是字符串或对象", detail={"field": f"columns[{index}]"}
            )
        if key in seen:
            # 重复列不放大授权，但也不静默吞掉：请求本身仍按去重处理
            continue
        seen.add(key)
        columns.append(entry)
    if not columns:
        raise errors.BadInput(
            "授权列去重后为空", detail={"field": "columns"}, code="SHARE_SCOPE_EMPTY"
        )
    return columns


def field_index(run: dict) -> tuple[dict, dict]:
    """(表,列) 与 field_id 两套索引；只读本批次已存字段，不重跑解析。"""
    by_name: dict[tuple[str, str], dict] = {}
    by_id: dict[str, dict] = {}
    for side in ("fields_old", "fields_new"):
        for field in run.get(side) or []:
            by_name.setdefault((field["table"].lower(), field["name"].lower()), field)
            by_id.setdefault(field["field_id"], field)
    return by_name, by_id


def resolve_scope(run: dict, requested: list[dict]) -> dict:
    """把请求列对到本批次的字段上；对不上的列只做提示，不当作授权。"""
    by_name, by_id = field_index(run)

    authorized_keys: set[tuple[str, str]] = set()
    fields: dict[str, dict] = {}
    display_by_field: dict[str, str] = {}
    unknown: list[str] = []
    canonical: list[dict] = []
    seen_fields: set[str] = set()

    for item in requested:
        if "field_id" in item:
            field = by_id.get(item["field_id"])
            if field is None:
                unknown.append(f"field:{item['field_id']}")
                continue
            display = f"field:{field['field_id']}"
        else:
            key = (item["table"].lower(), item["column"].lower())
            field = by_name.get(key)
            if field is None:
                unknown.append(f"{item['table']}.{item['column']}")
                continue
            display = f"{field['table']}.{field['name']}"

        field_id = field["field_id"]
        # 同一身份在旧版 / 新版里的名字都算授权键：
        # 下游可能引用旧名，按名授权时旧名同样落在范围内。
        for side in ("fields_old", "fields_new"):
            for other in run.get(side) or []:
                if other["field_id"] == field_id:
                    authorized_keys.add((other["table"].lower(),
                                         other["name"].lower()))
        fields.setdefault(field_id, field)
        display_by_field.setdefault(field_id, display)
        if field_id not in seen_fields:
            seen_fields.add(field_id)
            canonical.append({"column": display})

    if not fields:
        raise errors.BadInput(
            "授权列都不在本次批次中",
            detail={"unknown": unknown},
            code="SHARE_SCOPE_UNKNOWN",
        )

    labels = _authorized_labels(run, authorized_keys, fields, display_by_field)
    warnings: list[dict] = []
    if unknown:
        warnings.append({
            "code": "SHARE_SCOPE_UNKNOWN",
            "detail": "、".join(unknown),
            "columns": unknown,
        })
    return {
        "columns": canonical,
        "field_ids": set(fields),
        "keys": authorized_keys,
        "labels": labels,
        "display_by_field": display_by_field,
        "fields": fields,
        "warnings": warnings,
    }


def _authorized_labels(run: dict, keys: set[tuple[str, str]],
                       fields: dict[str, dict],
                       display_by_field: dict[str, str]) -> dict[str, str]:
    """影响面种子标签 → 授权列展示名；范围外的标签不进共享结果。

    种子标签有两种：`表.旧列名`（变更字段）和 `断链 表.列名`（引用断开）。
    """
    labels: dict[str, str] = {}
    for row in run.get("diff") or []:
        if row.get("verdict") != "BREAKING" or row.get("bucket") == "added":
            continue
        old_name = row.get("old_name")
        if not old_name or row.get("field_id") not in fields:
            continue
        labels[f"{row['table']}.{old_name}"] = display_by_field[row["field_id"]]
    for item in (run.get("resolution") or {}).get("broken") or []:
        key = (item["table"].lower(), item["column"].lower())
        if key not in keys:
            continue
        field_id = _field_id_for_key(run, key)
        if field_id is None or field_id not in fields:
            continue
        labels[f"{BROKEN_PREFIX}{item['ref']}"] = display_by_field[field_id]
    return labels


def _field_id_for_key(run: dict, key: tuple[str, str]) -> str | None:
    for side in ("fields_old", "fields_new"):
        for field in run.get(side) or []:
            if (field["table"].lower(), field["name"].lower()) == key:
                return field["field_id"]
    return None


class Anonymizer:
    """稳定的匿名编号：同一授权凭据下同名节点永远得到同一编号。

    编号用 HMAC 推导，节点名无法从编号反推，换凭据编号也不同。
    """

    def __init__(self, credential_hash: str, run_id: str, grant_id: str):
        self._key = credential_hash.encode("utf-8")
        self._seed = f"{run_id}|{grant_id}|".encode("utf-8")
        self._cache: dict[str, str] = {}

    def __call__(self, name: str) -> str:
        cached = self._cache.get(name)
        if cached is not None:
            return cached
        digest = hmac.new(self._key, self._seed + name.encode("utf-8"),
                          hashlib.sha256).hexdigest()[:12]
        label = f"anon-{digest}"
        self._cache[name] = label
        return label
