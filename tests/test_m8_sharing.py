"""M8 共享与审计：授权范围、脱敏、撤销、留痕、审计原件。"""

from __future__ import annotations

import json
import threading
import time

import pytest

from app import errors, store
from app.modules.m8_sharing import audit, grants, redact, scope
from app.modules.m8_sharing import gate


def _create(client, columns, **extra):
    body = {"columns": columns, **extra}
    response = client.post("/api/shares", json=body)
    assert response.status_code == 200, response.text
    return response.json()


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_share_scope_only_lists_authorized_columns(client):
    created = _create(client, ["fct_pay.pay_amt", "dim_order.order_no"])
    assert created["columns"] == [
        {"column": "fct_pay.pay_amt"},
        {"column": "dim_order.order_no"},
    ]
    assert created["status"] == "active"
    assert created["credential"]
    # 凭据原文只在响应里；库里只有摘要
    stored = store.grant_by_id(created["grant_id"])
    assert created["credential"] not in json.dumps(stored)


def test_shared_view_redacts_out_of_scope_names(client):
    created = _create(client, ["fct_pay.pay_amt"])
    response = client.get("/api/shared/impact", headers=_bearer(created["credential"]))
    assert response.status_code == 200
    text = json.dumps(response.json(), ensure_ascii=False)
    for leaked in ("dw.", "ads.", "select", "pay_channel", "channel",
                   "order_code", "dim_user", "mv_", "rpt_", "task"):
        assert leaked not in text, leaked
    body = response.json()
    assert body["impact"]["nodes"]
    for node in body["impact"]["nodes"]:
        assert node["node"].startswith("anon-")
    assert body["redaction"]["names_hidden"] is True


def test_node_ids_are_stable_within_grant_but_differ_across_grants(client):
    first = _create(client, ["fct_pay.pay_amt"])
    second = _create(client, ["fct_pay.pay_amt"])
    one = client.get("/api/shared/impact", headers=_bearer(first["credential"])).json()
    again = client.get("/api/shared/impact", headers=_bearer(first["credential"])).json()
    other = client.get("/api/shared/impact", headers=_bearer(second["credential"])).json()
    assert [n["node"] for n in one["impact"]["nodes"]] == [
        n["node"] for n in again["impact"]["nodes"]
    ]
    assert [n["node"] for n in one["impact"]["nodes"]] != [
        n["node"] for n in other["impact"]["nodes"]
    ]


def test_shared_view_keeps_edges_between_visible_nodes(client):
    created = _create(client, ["fct_pay.pay_amt"])
    impact = client.get("/api/shared/impact",
                        headers=_bearer(created["credential"])).json()["impact"]
    assert impact["edges"]
    visible = {node["node"] for node in impact["nodes"]}
    assert all(edge["from"] in visible and edge["to"] in visible
               for edge in impact["edges"])


def test_unknown_scope_column_is_warned_not_authorized(client):
    created = _create(client, ["fct_pay.pay_amt", "no_such_table.no_such_column"])
    assert [row["column"] for row in created["columns"]] == ["fct_pay.pay_amt"]
    codes = [item["code"] for item in created["warnings"]]
    assert "SHARE_SCOPE_UNKNOWN" in codes


def test_empty_or_unknown_scope_rejected(client):
    empty = client.post("/api/shares", json={"columns": []})
    assert empty.status_code == 400
    assert empty.json()["error"] == "SHARE_SCOPE_EMPTY"
    unknown = client.post("/api/shares", json={"columns": ["nope.nope"]})
    assert unknown.status_code == 400
    assert unknown.json()["error"] == "SHARE_SCOPE_UNKNOWN"


def test_share_without_credential_is_401(client):
    response = client.get("/api/shared/impact")
    assert response.status_code == 401
    assert response.json()["error"] == "SHARE_CREDENTIAL_INVALID"
    bad = client.get("/api/shared/impact", headers=_bearer("not-a-real-token"))
    assert bad.status_code == 401


def test_grant_is_bound_to_its_run(client):
    created = _create(client, ["fct_pay.pay_amt"])
    other = client.post("/api/runs", json={"params": {"wave": "second"}}).json()
    response = client.get(f"/api/shared/impact?run_id={other['run_id']}",
                          headers=_bearer(created["credential"]))
    assert response.status_code == 403
    assert response.json()["error"] == "SHARE_FORBIDDEN"


def test_share_credential_cannot_use_internal_endpoints(client):
    created = _create(client, ["fct_pay.pay_amt"])
    headers = _bearer(created["credential"])
    for method, url, body in (
        ("post", "/api/shares", {"columns": ["dim_order.order_id"]}),
        ("post", f"/api/shares/{created['grant_id']}/revoke", {}),
        ("get", "/api/shares", None),
        ("post", "/api/audit/reads", {"purpose": "x", "actor": "y"}),
        ("get", "/api/audit/reads", None),
    ):
        call = getattr(client, method)
        response = call(url, headers=headers, **({"json": body} if body is not None else {}))
        assert response.status_code == 403, (method, url, response.text)
        assert response.json()["error"] == "SHARE_FORBIDDEN"


def test_share_credential_cannot_read_unredacted_endpoints(client):
    """拿到凭据也不能绕过共享入口去读原文接口或导出。"""
    created = _create(client, ["fct_pay.pay_amt"])
    headers = _bearer(created["credential"])
    for url in (
        "/api/impact",
        "/api/mapping",
        "/api/reconcile",
        "/api/export/evidence.csv",
        "/api/export/fields.csv",
        "/api/export/spec.md",
        "/api/schemas/quarantine",
        "/",
        "/spec",
    ):
        response = client.get(url, headers=headers)
        assert response.status_code == 403, (url, response.text)
        assert response.json()["error"] == "SHARE_FORBIDDEN"
    # 共享入口本身仍可用
    ok = client.get("/api/shared/impact", headers=headers)
    assert ok.status_code == 200


def test_revoke_invalidates_old_credential_and_download(client):
    created = _create(client, ["fct_pay.pay_amt"])
    token = created["credential"]
    assert client.get("/api/shared/impact", headers=_bearer(token)).status_code == 200
    assert client.get("/api/shared/impact.csv", headers=_bearer(token)).status_code == 200

    revoked = client.post(f"/api/shares/{created['grant_id']}/revoke",
                          json={"note": "项目结束"})
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked"

    read = client.get("/api/shared/impact", headers=_bearer(token))
    assert read.status_code == 410
    assert read.json()["error"] == "SHARE_REVOKED"
    download = client.get("/api/shared/impact.csv", headers=_bearer(token))
    assert download.status_code == 410


def test_revoke_is_idempotent_and_keeps_first_note(client):
    created = _create(client, ["fct_pay.pay_amt"])
    first = client.post(f"/api/shares/{created['grant_id']}/revoke",
                        json={"note": "第一次"}).json()
    second = client.post(f"/api/shares/{created['grant_id']}/revoke",
                         json={"note": "第二次"}).json()
    assert first["revoked_at"] == second["revoked_at"]
    assert second["already_revoked"] is True
    assert second["note"] == "第一次"


def test_revoke_wins_when_concurrent_with_read(client, monkeypatch):
    created = _create(client, ["fct_pay.pay_amt"])
    token = created["credential"]
    grant = grants.authenticate(token)

    # 让读取在构建视图时停住，撤销先落库，再放行读取：读取必须被撤销拦下
    entered = threading.Event()
    release = threading.Event()
    original = redact.build

    def slow_build(*args, **kwargs):
        entered.set()
        release.wait(timeout=5)
        return original(*args, **kwargs)

    monkeypatch.setattr(redact, "build", slow_build)
    outcome: dict = {}

    def reader():
        try:
            grants.shared_view(grants.authenticate(token),
                               store.run_by_id(grant["run_id"]), channel="api")
            outcome["ok"] = True
        except errors.FieldmapError as exc:
            outcome["error"] = exc.code

    worker = threading.Thread(target=reader)
    worker.start()
    assert entered.wait(timeout=5)
    grants.revoke(created["grant_id"], note="并发撤销")
    release.set()
    worker.join(timeout=5)
    assert outcome.get("error") == "SHARE_REVOKED"
    assert "ok" not in outcome


def test_access_log_records_granted_and_denied(client):
    created = _create(client, ["fct_pay.pay_amt"])
    token = created["credential"]
    client.get("/api/shared/impact", headers=_bearer(token))
    client.get("/api/shared/impact.csv", headers=_bearer(token))
    client.post(f"/api/shares/{created['grant_id']}/revoke", json={})
    client.get("/api/shared/impact", headers=_bearer(token))

    records = client.get(f"/api/shares/{created['grant_id']}/reads").json()
    assert records["granted"] == 2
    assert records["denied"] == 1
    assert records["status"] == "revoked"
    assert [row["channel"] for row in records["reads"]][:2] == ["api", "download"]


def test_grant_listing_and_detail_are_readable_back(client):
    created = _create(client, ["fct_pay.pay_amt"], label="协作方甲")
    listing = client.get("/api/shares").json()
    assert listing["total"] == 1
    assert listing["grants"][0]["grant_id"] == created["grant_id"]
    assert listing["grants"][0]["label"] == "协作方甲"
    detail = client.get(f"/api/shares/{created['grant_id']}").json()
    assert detail["columns"] == [{"column": "fct_pay.pay_amt"}]
    assert "credential" not in detail
    assert client.get("/api/shares/gr-nope").status_code == 404


def test_expired_grant_is_rejected(client):
    created = _create(client, ["fct_pay.pay_amt"],
                      expires_at="2099-01-01T00:00:00Z")
    grant = store.grant_by_id(created["grant_id"])
    assert grants.grant_status(grant) == "active"
    # 直接把过期时刻挪到过去，模拟时间流逝
    with store._connect() as conn:  # noqa: SLF001 - 测试直接改库
        conn.execute("UPDATE share_grants SET expires_epoch=? WHERE grant_id=?",
                     (time.time() - 1, created["grant_id"]))
        conn.commit()
    response = client.get("/api/shared/impact",
                          headers=_bearer(created["credential"]))
    assert response.status_code == 410
    assert response.json()["error"] == "SHARE_EXPIRED"


# ---------- 审计 ----------

def test_audit_requires_purpose_and_actor(client):
    missing_purpose = client.post("/api/audit/reads", json={"actor": "alice"})
    assert missing_purpose.status_code == 400
    assert missing_purpose.json()["error"] == "AUDIT_PURPOSE_REQUIRED"
    missing_actor = client.post("/api/audit/reads", json={"purpose": "复核"})
    assert missing_actor.status_code == 400
    assert missing_actor.json()["error"] == "AUDIT_ACTOR_REQUIRED"


def test_audit_returns_original_with_internal_names(client):
    response = client.post("/api/audit/reads",
                           json={"purpose": "复核上线影响", "actor": "alice"})
    assert response.status_code == 200
    body = response.json()
    assert body["trace_status"] == "complete"
    text = json.dumps(body["original"], ensure_ascii=False)
    assert "fct_pay" in text and "pay_amount" not in text
    assert "select" in text.lower()


def test_audit_retry_does_not_double_count(client):
    first = client.post("/api/audit/reads",
                        json={"purpose": "复核", "actor": "alice"}).json()
    second = client.post("/api/audit/reads",
                         json={"purpose": "复核", "actor": "alice"}).json()
    assert first["reused"] is False
    assert second["reused"] is True
    assert first["request_key"] == second["request_key"]
    listing = client.get("/api/audit/reads").json()
    assert listing["total"] == 1
    assert listing["complete"] == 1


def test_audit_request_key_collision_with_other_purpose_conflicts(client):
    client.post("/api/audit/reads",
                json={"purpose": "复核", "actor": "alice", "request_key": "req-0001"})
    response = client.post(
        "/api/audit/reads",
        json={"purpose": "别的用途", "actor": "alice", "request_key": "req-0001"},
    )
    assert response.status_code == 409


def test_audit_trace_failure_returns_no_original(client, monkeypatch):
    def boom(*_args, **_kwargs):
        raise RuntimeError("disk full")

    monkeypatch.setattr(store, "begin_audit_record", boom)
    response = client.post("/api/audit/reads",
                           json={"purpose": "复核", "actor": "alice"})
    assert response.status_code == 500
    body = response.json()
    assert body["error"] == "AUDIT_WRITE_FAILED"
    assert "original" not in body
    assert store.list_audit_reads() == []


def test_audit_completion_failure_returns_no_original(client, monkeypatch):
    def boom(*_args, **_kwargs):
        raise RuntimeError("write failed")

    monkeypatch.setattr(store, "complete_audit_read", boom)
    response = client.post("/api/audit/reads",
                           json={"purpose": "复核", "actor": "alice"})
    assert response.status_code == 500
    assert response.json()["error"] == "AUDIT_WRITE_FAILED"
    rows = store.list_audit_reads()
    # pending 不算成功查阅
    assert len(rows) == 1 and rows[0]["status"] == "pending"


def test_interrupted_read_is_recovered_and_completable(client):
    client.post("/api/audit/reads",
                json={"purpose": "复核", "actor": "alice",
                      "request_key": "req-recover-1"})
    # 手工把记录压回 pending，模拟进程在完成前中断
    with store._connect() as conn:  # noqa: SLF001 - 测试直接改库
        conn.execute("UPDATE audit_reads SET status='pending', completed_at=NULL "
                     "WHERE request_key='req-recover-1'")
        conn.commit()

    recovered = audit.recover_pending()
    assert recovered["recovered"] == 1
    assert store.audit_read("req-recover-1")["status"] == "interrupted"
    # 中断记录可回读，并给出待补齐提示
    listing = client.get("/api/audit/reads").json()
    assert listing["interrupted"] == 1
    assert listing["warnings"][0]["code"] == "AUDIT_TRACE_GAP"

    retried = client.post("/api/audit/reads",
                          json={"purpose": "复核", "actor": "alice",
                                "request_key": "req-recover-1"}).json()
    assert retried["trace_status"] == "complete"
    after = client.get("/api/audit/reads").json()
    assert after["total"] == 1
    assert after["complete"] == 1
    assert after["interrupted"] == 0


def test_audit_is_visible_on_shares_page(client):
    client.post("/api/audit/reads",
                json={"purpose": "复核上线影响", "actor": "alice"})
    _create(client, ["fct_pay.pay_amt"], label="协作方甲")
    page = client.get("/shares")
    assert page.status_code == 200
    assert "共享与审计" in page.text
    assert "复核上线影响" in page.text
    assert "协作方甲" in page.text


# ---------- 纯规则 ----------

def test_scope_parser_rejects_bare_column():
    with pytest.raises(errors.BadInput):
        scope.parse_columns(["pay_amt"])


def test_scope_parser_defaults_field_id_mode():
    parsed = scope.parse_columns([{"field_id": 2003}])
    assert parsed == [{"field_id": "2003"}]


def test_anonymizer_is_deterministic_and_keyed():
    first = scope.Anonymizer("hash-a", "run-1", "gr-1")
    second = scope.Anonymizer("hash-b", "run-1", "gr-2")
    assert first("dw.mv_pay_daily") == first("dw.mv_pay_daily")
    assert first("dw.mv_pay_daily") != second("dw.mv_pay_daily")
    assert "dw" not in first("dw.mv_pay_daily")


def test_gate_rejects_share_credential_even_without_internal_key(client):
    created = _create(client, ["fct_pay.pay_amt"])
    with pytest.raises(errors.Forbidden):
        gate.require_internal(created["credential"])
    gate.require_internal(None)


def test_internal_endpoint_rejects_share_credential(client):
    created = _create(client, ["fct_pay.pay_amt"])
    response = client.post("/api/audit/reads",
                           json={"purpose": "复核", "actor": "alice"},
                           headers=_bearer(created["credential"]))
    assert response.status_code == 403
    assert response.json()["error"] == "SHARE_FORBIDDEN"


def test_gate_requires_configured_internal_key(client, monkeypatch):
    monkeypatch.setattr("app.modules.m8_sharing.gate.config.INTERNAL_KEY", "s3cret")
    with pytest.raises(errors.Unauthorized):
        gate.require_internal(None)
    with pytest.raises(errors.Forbidden):
        gate.require_internal(None, "wrong")
    gate.require_internal(None, "s3cret")
