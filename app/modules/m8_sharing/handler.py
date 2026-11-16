"""M8 入口：批次共享、凭据撤销、访问回读、审计查阅。

共享凭据只能看授权列与匿名下游；原件只有审计能看，且必须留用途。
内部接口（发放、撤销、审计）不接受共享凭据，防止普通共享凭据越权。
"""

from __future__ import annotations

from fastapi import APIRouter, Header, Request, Response
from fastapi.responses import HTMLResponse

from app import errors, store, web
from app.modules.m8_sharing import audit, gate, grants

router = APIRouter()

MAX_GRANT_LIST = 200


def _credential(header_value: str | None) -> str:
    """接受 `Authorization: Bearer <token>` 或裸凭据头。"""
    raw = (header_value or "").strip()
    if raw.lower().startswith("bearer "):
        return raw[7:].strip()
    return raw


def _body(payload: dict | None, allowed: set[str]) -> dict:
    body = payload or {}
    if not isinstance(body, dict):
        raise errors.BadInput("请求体必须是对象")
    unknown = set(body) - allowed
    if unknown:
        raise errors.BadInput("出现未知参数", detail={"keys": sorted(unknown)})
    return body


def _internal(authorization: str | None, internal_key: str | None) -> None:
    gate.require_internal(authorization, internal_key)


# ---------- 发放与撤销（内部） ----------

@router.post("/api/shares")
def create_share(payload: dict | None = None,
                 authorization: str | None = Header(default=None),
                 x_internal_key: str | None = Header(default=None)):
    _internal(authorization, x_internal_key)
    body = _body(payload, {"run_id", "columns", "label", "expires_at", "created_by"})
    if "columns" not in body:
        raise errors.BadInput("需要给出 columns 授权范围",
                              detail={"field": "columns"}, code="SHARE_SCOPE_EMPTY")
    return grants.create(
        run_id=body.get("run_id"),
        columns=body.get("columns"),
        label=body.get("label"),
        expires_at=body.get("expires_at"),
        created_by=body.get("created_by"),
    )


@router.get("/api/shares")
def list_shares(run_id: str | None = None,
                authorization: str | None = Header(default=None),
                x_internal_key: str | None = Header(default=None)):
    _internal(authorization, x_internal_key)
    rows = store.list_grants(run_id=run_id, limit=MAX_GRANT_LIST)
    return {"total": len(rows), "grants": [grants.public_view(row) for row in rows]}


@router.get("/api/shares/{grant_id}")
def share_detail(grant_id: str,
                 authorization: str | None = Header(default=None),
                 x_internal_key: str | None = Header(default=None)):
    _internal(authorization, x_internal_key)
    grant = store.grant_by_id(grant_id)
    if grant is None:
        raise errors.NotFound("授权不存在", detail={"grant_id": grant_id})
    return grants.public_view(grant)


@router.post("/api/shares/{grant_id}/revoke")
def revoke_share(grant_id: str, payload: dict | None = None,
                 authorization: str | None = Header(default=None),
                 x_internal_key: str | None = Header(default=None)):
    _internal(authorization, x_internal_key)
    body = _body(payload, {"note"})
    return grants.revoke(grant_id, note=body.get("note"))


@router.get("/api/shares/{grant_id}/reads")
def share_reads(grant_id: str,
                authorization: str | None = Header(default=None),
                x_internal_key: str | None = Header(default=None)):
    _internal(authorization, x_internal_key)
    return grants.reads(grant_id)


# ---------- 共享读取（凭据） ----------

@router.get("/api/shared/impact")
def shared_impact(run_id: str | None = None,
                  authorization: str | None = Header(default=None)):
    grant = grants.authenticate(_credential(authorization))
    run = grants.require_run(grant, run_id)
    return grants.shared_view(grant, run, channel="api")


@router.get("/api/shared/impact.csv")
def shared_impact_csv(run_id: str | None = None,
                      authorization: str | None = Header(default=None)):
    grant = grants.authenticate(_credential(authorization), channel="download")
    run = grants.require_run(grant, run_id, channel="download")
    body = grants.download_csv(grant, run)
    return Response(
        content=body,
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": 'attachment; filename="lineageguard-shared-impact.csv"',
            "Cache-Control": "no-store",
        },
    )


# ---------- 审计原件（内部） ----------

@router.post("/api/audit/reads")
def audit_original(payload: dict | None = None,
                   authorization: str | None = Header(default=None),
                   x_internal_key: str | None = Header(default=None)):
    _internal(authorization, x_internal_key)
    body = _body(payload, {"run_id", "purpose", "actor", "request_key"})
    run_id = body.get("run_id") or (store.latest_run() or {}).get("run_id")
    if not run_id:
        raise errors.NotFound("还没有批次")
    return audit.original(
        run_id=run_id,
        purpose=body.get("purpose"),
        actor=body.get("actor"),
        request_key=body.get("request_key"),
    )


@router.get("/api/audit/reads")
def audit_reads(run_id: str | None = None,
                authorization: str | None = Header(default=None),
                x_internal_key: str | None = Header(default=None)):
    _internal(authorization, x_internal_key)
    return audit.reads(run_id=run_id)


# ---------- 页面 ----------

@router.get("/shares", response_class=HTMLResponse)
def shares_page(request: Request):
    run = store.latest_run()
    rows = [grants.public_view(row) for row in store.list_grants(limit=MAX_GRANT_LIST)]
    share_reads = store.list_share_reads(limit=200)
    audits = store.list_audit_reads(limit=200)
    return web.page_or_404(
        request,
        "shares.html",
        "shares",
        run,
        grants=rows,
        share_reads=share_reads,
        audit_reads=audits,
    )
