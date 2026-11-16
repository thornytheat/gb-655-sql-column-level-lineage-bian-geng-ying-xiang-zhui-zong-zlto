"""共享凭据：发放、校验、撤销、访问留痕。

凭据原文只在发放响应里出现一次；库里只存 sha256 摘要，事后无法取回。
校验顺序固定：有没有凭据 → 认不认 → 撤销/过期 → 批次绑定。
撤销与读取并发以撤销为准：读取在同一个事务里判定状态并留痕，
撤销先提交则读取被拒，读取先提交则发生在撤销之前。
"""

from __future__ import annotations

import hashlib
import secrets

from app import config, errors, store
from app.modules.m6_batches import window as window_mod
from app.modules.m8_sharing import redact, scope as scope_mod


def credential_hash(credential: str) -> str:
    return hashlib.sha256(credential.encode("utf-8")).hexdigest()


def _now() -> str:
    return config.now_utc().isoformat()


def _expiry(value) -> tuple[str | None, float | None]:
    if value in (None, ""):
        return None, None
    moment = window_mod.parse_instant(str(value), "expires_at")
    return moment.isoformat(), moment.timestamp()


def create(run_id: str | None, columns, label: str | None = None,
           expires_at=None, created_by: str | None = None) -> dict:
    """发放一份共享凭据：范围只认列，凭据明文只在本响应出现。"""
    if run_id:
        target = store.run_by_id(str(run_id))
        if target is None:
            raise errors.NotFound("批次不存在", detail={"run_id": run_id})
    else:
        target = store.latest_run()
        if target is None:
            raise errors.NotFound("还没有可共享的批次，先跑一次")

    requested = scope_mod.parse_columns(columns)
    resolved = scope_mod.resolve_scope(target, requested)

    if label is not None:
        label = str(label).strip()
        if len(label) > config.SHARE_LABEL_MAX:
            raise errors.BadInput("标签过长", detail={"field": "label",
                                                     "max": config.SHARE_LABEL_MAX})
        label = label or None
    creator = str(created_by or "local").strip() or "local"
    if len(creator) > config.AUDIT_ACTOR_MAX:
        raise errors.BadInput("创建人过长", detail={"field": "created_by"})

    expires_text, expires_epoch = _expiry(expires_at)
    if expires_epoch is not None and expires_epoch <= config.now_utc().timestamp():
        raise errors.BadInput("过期时间必须晚于当前时刻",
                              detail={"field": "expires_at"})

    credential = secrets.token_urlsafe(config.SHARE_TOKEN_BYTES)
    created_at = _now()
    frozen_scope = {
        "requested": requested,
        "columns": resolved["columns"],
        "field_ids": sorted(resolved["field_ids"]),
        "labels": resolved["labels"],
        "display_by_field": resolved["display_by_field"],
        "warnings": resolved["warnings"],
    }
    grant = {
        "grant_id": "gr-" + secrets.token_hex(8),
        "run_id": target["run_id"],
        "scope": frozen_scope,
        "credential_hash": credential_hash(credential),
        "label": label,
        "expires_at": expires_text,
        "expires_epoch": expires_epoch,
        "created_at": created_at,
        "created_by": creator,
    }
    if not store.insert_grant(grant):
        raise errors.Conflict("凭据摘要冲突，请重试")

    return {
        "grant_id": grant["grant_id"],
        "credential": credential,
        "run_id": grant["run_id"],
        "label": label,
        "columns": resolved["columns"],
        "created_at": created_at,
        "created_by": creator,
        "expires_at": expires_text,
        "revoked_at": None,
        "status": "active",
        "warnings": resolved["warnings"],
        "credential_notice": "凭据只在本次响应出现，服务端只保存摘要",
    }


def grant_status(grant: dict, at_epoch: float | None = None) -> str:
    if grant.get("revoked_at"):
        return "revoked"
    expires = grant.get("expires_epoch")
    if expires is not None:
        now = config.now_utc().timestamp() if at_epoch is None else at_epoch
        if now >= float(expires):
            return "expired"
    return "active"


def public_view(grant: dict) -> dict:
    """授权自身的对外视图：不含凭据摘要与内部字段。"""
    return {
        "grant_id": grant["grant_id"],
        "run_id": grant["run_id"],
        "label": grant.get("label"),
        "columns": (grant.get("scope") or {}).get("columns") or [],
        "created_at": grant["created_at"],
        "created_by": grant["created_by"],
        "expires_at": grant.get("expires_at"),
        "revoked_at": grant.get("revoked_at"),
        "revoke_note": grant.get("revoke_note"),
        "status": grant_status(grant),
    }


def _state_error(grant: dict) -> errors.FieldmapError | None:
    status = grant_status(grant)
    if status == "revoked":
        return errors.Gone(
            "共享已撤销",
            detail={"grant_id": grant["grant_id"], "reason": "SHARE_REVOKED"},
            code="SHARE_REVOKED", label="共享已撤销",
        )
    if status == "expired":
        return errors.Gone(
            "共享已过期",
            detail={"grant_id": grant["grant_id"], "reason": "SHARE_EXPIRED"},
            code="SHARE_EXPIRED", label="共享已过期",
        )
    return None


def grant_of_credential(credential: str | None) -> dict:
    """凭据 -> 授权；缺凭据或认不出一律 401。"""
    token = (credential or "").strip()
    if not token:
        raise errors.Unauthorized(
            "缺少共享凭据", detail={"credential": "missing"},
            code="SHARE_CREDENTIAL_INVALID", label="共享凭据无效",
        )
    grant = store.grant_by_credential_hash(credential_hash(token))
    if grant is None:
        raise errors.Unauthorized(
            "共享凭据无效", detail={"credential": "invalid"},
            code="SHARE_CREDENTIAL_INVALID", label="共享凭据无效",
        )
    return grant


def authenticate(credential: str | None, channel: str = "api") -> dict:
    """凭据 -> 可用授权；撤销或过期返回 410，并尽力留痕。"""
    grant = grant_of_credential(credential)
    failure = _state_error(grant)
    if failure is not None:
        _soft_record(grant, channel, "denied", _reason_of(failure))
        raise failure
    return grant


def _reason_of(failure: errors.FieldmapError) -> str:
    return str((failure.detail or {}).get("reason") or failure.code)


def require_run(grant: dict, run_id: str | None, channel: str = "api") -> dict:
    """凭据只能读自己被绑定的批次；换批次是越权，不是“没数据”。"""
    if run_id and run_id != grant["run_id"]:
        _soft_record(grant, channel, "denied", "SHARE_FORBIDDEN")
        raise errors.Forbidden(
            "共享凭据不能读取其他批次",
            detail={"reason": "SHARE_FORBIDDEN"},
            code="SHARE_FORBIDDEN", label="凭据越权访问",
        )
    run = store.run_by_id(grant["run_id"])
    if run is None:
        raise errors.NotFound("批次已不存在", detail={"run_id": grant["run_id"]})
    return run


def hydrated_scope(grant: dict, run: dict) -> dict:
    """从冻结范围 + 当前批次字段，复原渲染所需的查找表。"""
    scope = grant.get("scope") or {}
    field_ids = set(scope.get("field_ids") or [])
    fields: dict[str, dict] = {}
    for side in ("fields_old", "fields_new"):
        for field in run.get(side) or []:
            if field["field_id"] in field_ids:
                fields.setdefault(field["field_id"], field)
    return {
        "columns": scope.get("columns") or [],
        "labels": scope.get("labels") or {},
        "display_by_field": scope.get("display_by_field") or {},
        "fields": fields,
        "warnings": scope.get("warnings") or [],
    }


def shared_view(grant: dict, run: dict, channel: str = "api") -> dict:
    """按授权范围裁剪影响面并匿名化；成功读取在返回前完成留痕。"""
    resolved = hydrated_scope(grant, run)
    # 读取前重查一次状态：撤销已提交就不必构建，更不必返回。
    latest = store.grant_by_id(grant["grant_id"]) or grant
    failure = _state_error(latest)
    if failure is not None:
        _soft_record(grant, channel, "denied", _reason_of(failure))
        raise failure

    anon = scope_mod.Anonymizer(grant["credential_hash"], grant["run_id"],
                                grant["grant_id"])
    impact = redact.build(run, resolved, anon)

    _record_active_or_raise(grant, channel)

    return {
        "grant_id": grant["grant_id"],
        "run_id": run["run_id"],
        "version": {
            "old": run.get("version_label_old"),
            "new": run.get("version_label_new"),
        },
        "window": {
            "from": run.get("effective_from"),
            "to": run.get("effective_to"),
            "semantics": config.WINDOW_SEMANTICS,
        },
        "scope": {"columns": resolved["columns"]},
        "impact": impact,
        "redaction": {
            "outside_scope": "anonymous",
            "names_hidden": True,
            "sql_hidden": True,
        },
    }


def download_csv(grant: dict, run: dict) -> str:
    """下载入口与读取同权：撤销后同一凭据拿不到内容。"""
    view = shared_view(grant, run, channel="download")
    impact = view["impact"]
    lines = ["node,kind,depth,via,via_node,because"]
    for node in impact["nodes"]:
        cells = [
            node["node"], node["kind"], str(node["depth"]), node["via"],
            node["via_node"] or "", "|".join(node["because"]),
        ]
        lines.append(",".join(_csv_cell(cell) for cell in cells))
    lines.append("")
    lines.append("column,change,verdict,reason,direct_nodes")
    for row in impact["columns"]:
        cells = [
            row["column"], row.get("change") or "", row.get("verdict") or "",
            row.get("reason") or "", str(row.get("direct_nodes") or 0),
        ]
        lines.append(",".join(_csv_cell(cell) for cell in cells))
    return "\n".join(lines) + "\n"


def _csv_cell(value: str) -> str:
    text = str(value)
    if any(ch in text for ch in ',"\n'):
        return '"' + text.replace('"', '""') + '"'
    return text


def revoke(grant_id: str, note: str | None = None) -> dict:
    if note is not None:
        note = str(note).strip()
        if len(note) > config.SHARE_LABEL_MAX:
            raise errors.BadInput("撤销说明过长", detail={"field": "note"})
        note = note or None
    result = store.revoke_grant(grant_id, _now(), note)
    if not result["found"]:
        raise errors.NotFound("授权不存在", detail={"grant_id": grant_id})
    grant = store.grant_by_id(grant_id) or {}
    return {
        "grant_id": grant_id,
        "revoked_at": result["revoked_at"],
        "already_revoked": bool(result["already"]),
        "note": grant.get("revoke_note"),
        "status": grant_status(grant),
    }


def reads(grant_id: str) -> dict:
    grant = store.grant_by_id(grant_id)
    if grant is None:
        raise errors.NotFound("授权不存在", detail={"grant_id": grant_id})
    events = store.list_share_reads(grant_id=grant_id)
    return {
        "grant_id": grant_id,
        "status": grant_status(grant),
        "revoked_at": grant.get("revoked_at"),
        "revoke_note": grant.get("revoke_note"),
        "granted": sum(1 for row in events if row["outcome"] == "granted"),
        "denied": sum(1 for row in events if row["outcome"] != "granted"),
        "reads": events,
    }


# ---------- 访问留痕 ----------

def _record_active_or_raise(grant: dict, channel: str) -> None:
    """同一事务判定撤销/过期并记录成功读取。

    撤销先提交 -> 这里看到 revoked 并拒绝；这里先提交 -> 读取发生在撤销之前。
    任意写失败都不返回内容（留痕失败不返回原文）。
    """
    try:
        result = store.record_share_read_atomic(
            grant["grant_id"], channel, _now(), config.now_utc().timestamp()
        )
    except Exception as exc:  # noqa: BLE001 - 留痕故障必须转成拒绝
        raise errors.InternalFailure(
            "共享访问留痕失败，已拒绝返回",
            detail={"reason": "AUDIT_WRITE_FAILED", "cause": type(exc).__name__},
            code="AUDIT_WRITE_FAILED", label="查阅留痕失败",
        ) from exc
    if not result["found"]:
        raise errors.NotFound("授权不存在", detail={"grant_id": grant["grant_id"]})
    if not result["active"]:
        reason = result.get("reason") or "SHARE_REVOKED"
        raise errors.Gone(
            "共享已失效",
            detail={"grant_id": grant["grant_id"], "reason": reason},
            code=reason, label="共享已失效",
        )


def _soft_record(grant: dict, channel: str, outcome: str, reason: str) -> None:
    """拒绝路径尽力留痕；留痕故障不得掩盖原本的拒绝原因。"""
    try:
        store.append_share_read(grant["grant_id"], grant["run_id"], channel,
                                outcome, _now(), reason)
    except Exception:  # noqa: BLE001
        return
