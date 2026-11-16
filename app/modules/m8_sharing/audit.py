"""审计查阅：填写用途、记录查阅、失败不返回原文、重试不重复记账。

三段式留痕（均落库，进程中断可恢复）：
1. `pending`：收到查阅请求，先占住请求键，避免并发重复记账；
2. `complete`：用途与查阅人已确认，读取记录成立，此时才允许返回原件；
   原文确实返回过，才补这一步。
3. `interrupted`：启动恢复时把残留的 `pending` 标成中断，不计成功查阅。

重试带同一请求键命中同一行，把它补齐而不新增一条，所以重试不重复记账。
请求键缺省由 `run_id|actor|purpose` 推导，天然可复算。
"""

from __future__ import annotations

import hashlib

from app import config, errors, store


def _now() -> str:
    return config.now_utc().isoformat()


def request_key_for(run_id: str, actor: str, purpose: str,
                    supplied: str | None = None) -> str:
    raw = (supplied or "").strip()
    if raw:
        if not config.AUDIT_REQUEST_KEY_RE.match(raw):
            raise errors.BadInput(
                "请求键格式不合法",
                detail={"field": "request_key",
                        "pattern": "字母数字与 _.:- ，8 至 120 位"},
            )
        return raw
    digest = hashlib.sha256(f"{run_id}|{actor}|{purpose}".encode("utf-8")).hexdigest()
    return "auto-" + digest[:40]


def _clean_purpose(purpose) -> str:
    text = str(purpose or "").strip()
    if not text:
        raise errors.BadInput(
            "查阅原件必须填写用途",
            detail={"field": "purpose", "reason": "AUDIT_PURPOSE_REQUIRED"},
            code="AUDIT_PURPOSE_REQUIRED", label="查阅原件未填写用途",
        )
    if len(text) > config.AUDIT_PURPOSE_MAX:
        raise errors.BadInput("用途过长", detail={"field": "purpose",
                                                 "max": config.AUDIT_PURPOSE_MAX})
    if any(ch in text for ch in "\r\n\t\x00"):
        raise errors.BadInput("用途含控制字符", detail={"field": "purpose"})
    return text


def _clean_actor(actor) -> str:
    text = str(actor or "").strip()
    if not text:
        raise errors.BadInput(
            "查阅原件必须标明查阅人",
            detail={"field": "actor", "reason": "AUDIT_ACTOR_REQUIRED"},
            code="AUDIT_ACTOR_REQUIRED", label="查阅原件未标明查阅人",
        )
    if len(text) > config.AUDIT_ACTOR_MAX:
        raise errors.BadInput("查阅人过长", detail={"field": "actor",
                                                   "max": config.AUDIT_ACTOR_MAX})
    return text


def original(run_id: str, purpose, actor, request_key: str | None = None) -> dict:
    """查阅原件：先留痕再返回；留痕失败一律不返回原文。"""
    target_run = store.run_by_id(str(run_id or ""))
    if target_run is None:
        raise errors.NotFound("批次不存在", detail={"run_id": run_id})

    clean_purpose = _clean_purpose(purpose)
    clean_actor = _clean_actor(actor)
    key = request_key_for(target_run["run_id"], clean_actor, clean_purpose,
                          request_key)

    record = _claim_record(key, target_run["run_id"], clean_purpose, clean_actor)
    body = _original_body(target_run)
    # 只有访问记录确实成立后才返回原文；否则调用方拿到的是留痕异常。
    return {
        "run_id": target_run["run_id"],
        "request_key": key,
        "purpose": record["purpose"],
        "actor": record["actor"],
        "read_at": record["completed_at"] or record["created_at"],
        "reused": bool(record.get("reused")),
        "trace_status": record["status"],
        "original": body,
    }


def _claim_record(key: str, run_id: str, purpose: str, actor: str) -> dict:
    """占位并完成留痕；同一请求键重试复用同一行。"""
    at = _now()
    try:
        row = store.begin_audit_record(key, run_id, purpose, actor, at)
    except Exception as exc:  # noqa: BLE001
        raise _write_failure(exc) from exc

    if row["run_id"] != run_id:
        raise errors.Conflict(
            "请求键已用于其他批次",
            detail={"request_key": key, "run_id": row["run_id"]},
        )
    if row["purpose"] != purpose or row["actor"] != actor:
        raise errors.Conflict(
            "请求键已用于其他用途或查阅人",
            detail={"request_key": key,
                    "purpose": row["purpose"], "actor": row["actor"]},
        )

    if row["status"] == "complete":
        return dict(row, reused=True)

    try:
        done = store.complete_audit_read(key, at)
    except Exception as exc:  # noqa: BLE001
        raise _write_failure(exc) from exc

    if done["status"] != "complete":
        raise _write_failure(None)
    return dict(done, reused=row["status"] in ("interrupted",))


def _write_failure(exc: Exception | None) -> errors.InternalFailure:
    detail = {"reason": "AUDIT_WRITE_FAILED"}
    if exc is not None:
        detail["cause"] = type(exc).__name__
    return errors.InternalFailure(
        "查阅留痕失败，已拒绝返回原件", detail=detail,
        code="AUDIT_WRITE_FAILED", label="查阅留痕失败",
    )


def _original_body(run: dict) -> dict:
    """原件：内部表名、列名、SQL 与全部判定都在这里，仅供审计。"""
    return {
        "run_id": run["run_id"],
        "batch_key": run.get("batch_key"),
        "ruleset": run.get("ruleset"),
        "version_seq": run.get("version_seq"),
        "input_sha256": run.get("input_sha256"),
        "input_names": run.get("input_names") or {},
        "digests": run.get("digests") or {},
        "version": {
            "old": run.get("version_label_old"),
            "new": run.get("version_label_new"),
        },
        "window": {
            "from": run.get("effective_from"),
            "to": run.get("effective_to"),
            "semantics": config.WINDOW_SEMANTICS,
        },
        "fields_old": run.get("fields_old") or [],
        "fields_new": run.get("fields_new") or [],
        "diff": run.get("diff") or [],
        "refs": run.get("refs") or {},
        "resolution": run.get("resolution") or {},
        "impact": run.get("impact") or {},
        "mapping": run.get("mapping") or {},
        "ledger": run.get("ledger") or {},
        "quarantine": run.get("quarantine") or [],
        "warnings": run.get("warnings") or [],
        "created_at": run.get("created_at"),
    }


def reads(run_id: str | None = None) -> dict:
    rows = store.list_audit_reads(run_id=run_id)
    interrupted = sum(1 for row in rows if row["status"] == "interrupted")
    pending = sum(1 for row in rows if row["status"] == "pending")
    warnings = []
    if interrupted or pending:
        warnings.append({
            "code": "AUDIT_TRACE_GAP",
            "detail": f"中断 {interrupted} 条、登记中 {pending} 条；带原请求键重试可补齐",
        })
    return {
        "run_id": run_id,
        "total": len(rows),
        "complete": sum(1 for row in rows if row["status"] == "complete"),
        "interrupted": interrupted,
        "pending": pending,
        "warnings": warnings,
        "reads": rows,
    }


def recover_pending() -> dict:
    """启动恢复：把中断留下的 pending 标成 interrupted，不计成功查阅。

    记录仍可回读；重试同一请求键会把它补齐成 complete，账目仍是同一条。
    """
    pending = store.list_pending_audit_reads()
    recovered: list[str] = []
    for row in pending:
        if store.mark_audit_interrupted(row["request_key"], _now()):
            recovered.append(row["request_key"])
    return {"recovered": len(recovered), "request_keys": recovered, "at": _now()}
