"""SQLite 读写：批次快照、运行清单、隔离行、共享授权、审计留痕、键值状态。

只放数据访问，不放判定；调用方拿到的是普通字典。
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from pathlib import Path

from app import config

_LOCK = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS snapshots (
    schema_id      TEXT PRIMARY KEY,
    version_label  TEXT NOT NULL,
    source_path    TEXT NOT NULL,
    source_sha256  TEXT NOT NULL,
    encoding       TEXT NOT NULL,
    bom            INTEGER NOT NULL,
    field_count    INTEGER NOT NULL,
    blocked_count  INTEGER NOT NULL,
    created_at     TEXT NOT NULL,
    payload_json   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS runs (
    run_id         TEXT PRIMARY KEY,
    batch_key      TEXT NOT NULL UNIQUE,
    old_schema_id  TEXT NOT NULL,
    new_schema_id  TEXT NOT NULL,
    version_seq    INTEGER NOT NULL,
    input_sha256   TEXT NOT NULL,
    ruleset        TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    effective_from TEXT NOT NULL,
    effective_to   TEXT,
    summary_json   TEXT NOT NULL,
    payload_json   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS quarantine (
    schema_id     TEXT NOT NULL,
    line          INTEGER,
    table_name    TEXT,
    column_name   TEXT,
    reason        TEXT NOT NULL,
    blocking      INTEGER NOT NULL,
    detail        TEXT,
    raw           TEXT
);
CREATE TABLE IF NOT EXISTS kv (
    k TEXT PRIMARY KEY,
    v TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS share_grants (
    grant_id        TEXT PRIMARY KEY,
    run_id          TEXT NOT NULL,
    scope_json      TEXT NOT NULL,
    credential_hash TEXT NOT NULL UNIQUE,
    label           TEXT,
    expires_at      TEXT,
    expires_epoch   REAL,
    created_at      TEXT NOT NULL,
    created_by      TEXT NOT NULL,
    revoked_at      TEXT,
    revoke_note     TEXT
);
CREATE TABLE IF NOT EXISTS share_reads (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    grant_id    TEXT NOT NULL,
    run_id      TEXT NOT NULL,
    channel     TEXT NOT NULL,
    outcome     TEXT NOT NULL,
    at          TEXT NOT NULL,
    note        TEXT
);
CREATE TABLE IF NOT EXISTS audit_reads (
    request_key  TEXT PRIMARY KEY,
    run_id       TEXT NOT NULL,
    purpose      TEXT NOT NULL,
    actor        TEXT NOT NULL,
    status       TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    completed_at TEXT,
    note         TEXT
);
CREATE INDEX IF NOT EXISTS idx_quarantine_schema ON quarantine(schema_id);
CREATE INDEX IF NOT EXISTS idx_share_grants_run ON share_grants(run_id);
CREATE INDEX IF NOT EXISTS idx_audit_reads_run ON audit_reads(run_id);
"""


def db_path() -> Path:
    raw = os.environ.get("LINEAGEGUARD_DB", "").strip()
    path = Path(raw) if raw else config.DEFAULT_DB
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(db_path(), timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db() -> None:
    with _LOCK, _connect() as conn:
        conn.executescript(SCHEMA)


def reset() -> None:
    """测试与重建用：清空全部业务表。"""
    with _LOCK, _connect() as conn:
        conn.executescript(SCHEMA)
        for table in ("snapshots", "runs", "quarantine", "kv", "share_grants",
                      "share_reads", "audit_reads"):
            conn.execute(f"DELETE FROM {table}")


def _dumps(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _loads(value):
    if not value:
        return None
    return json.loads(value)


# ---------- 快照 ----------

def save_snapshot(snapshot: dict) -> None:
    with _LOCK, _connect() as conn:
        conn.execute(
            """INSERT INTO snapshots (schema_id, version_label, source_path, source_sha256,
                   encoding, bom, field_count, blocked_count, created_at, payload_json)
               VALUES (?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(schema_id) DO UPDATE SET
                   version_label=excluded.version_label,
                   source_path=excluded.source_path,
                   source_sha256=excluded.source_sha256,
                   encoding=excluded.encoding,
                   bom=excluded.bom,
                   field_count=excluded.field_count,
                   blocked_count=excluded.blocked_count,
                   created_at=excluded.created_at,
                   payload_json=excluded.payload_json""",
            (
                snapshot["schema_id"], snapshot["version_label"], snapshot["source_path"],
                snapshot["source_sha256"], snapshot["encoding"], int(bool(snapshot["bom"])),
                int(snapshot["field_count"]), int(snapshot["blocked_count"]),
                snapshot["created_at"], _dumps(snapshot),
            ),
        )


def load_snapshot(schema_id: str) -> dict | None:
    with _LOCK, _connect() as conn:
        row = conn.execute(
            "SELECT payload_json FROM snapshots WHERE schema_id=?", (schema_id,)
        ).fetchone()
    return _loads(row["payload_json"]) if row else None


def list_snapshots(limit: int = 20) -> list[dict]:
    with _LOCK, _connect() as conn:
        rows = conn.execute(
            """SELECT schema_id, version_label, source_path, source_sha256, encoding, bom,
                      field_count, blocked_count, created_at
               FROM snapshots ORDER BY created_at DESC, schema_id LIMIT ?""",
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def save_quarantine(schema_id: str, rows: list[dict]) -> None:
    with _LOCK, _connect() as conn:
        conn.execute("DELETE FROM quarantine WHERE schema_id=?", (schema_id,))
        conn.executemany(
            """INSERT INTO quarantine (schema_id, line, table_name, column_name, reason,
                   blocking, detail, raw) VALUES (?,?,?,?,?,?,?,?)""",
            [
                (
                    schema_id, int(row.get("line") or 0), row.get("table") or "",
                    row.get("column") or "", row["reason"], int(bool(row.get("blocking"))),
                    row.get("detail") or "", row.get("raw") or "",
                )
                for row in rows
            ],
        )


def list_quarantine(schema_id: str) -> list[dict]:
    with _LOCK, _connect() as conn:
        rows = conn.execute(
            """SELECT line, table_name, column_name, reason, blocking, detail, raw
               FROM quarantine WHERE schema_id=? ORDER BY line, reason""",
            (schema_id,),
        ).fetchall()
    return [
        {
            "line": row["line"],
            "table": row["table_name"],
            "column": row["column_name"],
            "reason": row["reason"],
            "blocking": bool(row["blocking"]),
            "detail": row["detail"],
            "raw": row["raw"],
        }
        for row in rows
    ]


# ---------- 运行清单 ----------

def save_run(run: dict) -> None:
    with _LOCK, _connect() as conn:
        conn.execute(
            """INSERT INTO runs (run_id, batch_key, old_schema_id, new_schema_id, version_seq,
                   input_sha256, ruleset, created_at, effective_from, effective_to,
                   summary_json, payload_json)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                run["run_id"], run["batch_key"], run["old_schema_id"], run["new_schema_id"],
                int(run["version_seq"]), run["input_sha256"], run["ruleset"],
                run["created_at"], run["effective_from"], run["effective_to"],
                _dumps(run["summary"]), _dumps(run),
            ),
        )


def find_run_by_key(batch_key: str) -> dict | None:
    with _LOCK, _connect() as conn:
        row = conn.execute(
            "SELECT payload_json FROM runs WHERE batch_key=?", (batch_key,)
        ).fetchone()
    return _loads(row["payload_json"]) if row else None


def run_by_id(run_id: str) -> dict | None:
    with _LOCK, _connect() as conn:
        row = conn.execute(
            "SELECT payload_json FROM runs WHERE run_id=?", (run_id,)
        ).fetchone()
    return _loads(row["payload_json"]) if row else None


def latest_run() -> dict | None:
    with _LOCK, _connect() as conn:
        row = conn.execute(
            "SELECT payload_json FROM runs ORDER BY version_seq DESC LIMIT 1"
        ).fetchone()
    return _loads(row["payload_json"]) if row else None


def list_runs(limit: int = 30) -> list[dict]:
    with _LOCK, _connect() as conn:
        rows = conn.execute(
            """SELECT summary_json FROM runs ORDER BY version_seq DESC, run_id LIMIT ?""",
            (limit,),
        ).fetchall()
    return [_loads(row["summary_json"]) for row in rows]


def count_runs() -> int:
    with _LOCK, _connect() as conn:
        row = conn.execute("SELECT COUNT(*) AS n FROM runs").fetchone()
    return int(row["n"])


def next_version_seq() -> int:
    with _LOCK, _connect() as conn:
        row = conn.execute("SELECT COALESCE(MAX(version_seq), 0) AS n FROM runs").fetchone()
    return int(row["n"]) + 1


def current_version_seq() -> int:
    with _LOCK, _connect() as conn:
        row = conn.execute("SELECT COALESCE(MAX(version_seq), 0) AS n FROM runs").fetchone()
    return int(row["n"])


def list_windows() -> list[dict]:
    with _LOCK, _connect() as conn:
        rows = conn.execute(
            "SELECT run_id, effective_from, effective_to FROM runs ORDER BY version_seq"
        ).fetchall()
    return [dict(row) for row in rows]


# ---------- 键值 ----------

def set_kv(key: str, value) -> None:
    with _LOCK, _connect() as conn:
        conn.execute(
            "INSERT INTO kv (k, v) VALUES (?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
            (key, _dumps(value)),
        )


def get_kv(key: str, default=None):
    with _LOCK, _connect() as conn:
        row = conn.execute("SELECT v FROM kv WHERE k=?", (key,)).fetchone()
    return _loads(row["v"]) if row else default


# ---------- 共享授权 ----------
# 只存凭据摘要；原文凭据只在创建响应里出现一次，库里再也取不回来。

def insert_grant(grant: dict) -> bool:
    """凭据摘要已存在时返回 False（重复登记），不覆盖已有授权。"""
    with _LOCK, _connect() as conn:
        try:
            conn.execute(
                """INSERT INTO share_grants (grant_id, run_id, scope_json, credential_hash,
                       label, expires_at, expires_epoch, created_at, created_by)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    grant["grant_id"], grant["run_id"], _dumps(grant["scope"]),
                    grant["credential_hash"], grant.get("label"),
                    grant.get("expires_at"), grant.get("expires_epoch"),
                    grant["created_at"], grant["created_by"],
                ),
            )
        except sqlite3.IntegrityError:
            return False
    return True


def _grant_row(row) -> dict | None:
    if row is None:
        return None
    data = dict(row)
    data["scope"] = _loads(data.pop("scope_json")) or {}
    return data


def grant_by_id(grant_id: str) -> dict | None:
    with _LOCK, _connect() as conn:
        row = conn.execute(
            "SELECT * FROM share_grants WHERE grant_id=?", (grant_id,)
        ).fetchone()
    return _grant_row(row)


def grant_by_credential_hash(credential_hash: str) -> dict | None:
    with _LOCK, _connect() as conn:
        row = conn.execute(
            "SELECT * FROM share_grants WHERE credential_hash=?", (credential_hash,)
        ).fetchone()
    return _grant_row(row)


def list_grants(run_id: str | None = None, limit: int = 200) -> list[dict]:
    with _LOCK, _connect() as conn:
        if run_id:
            rows = conn.execute(
                """SELECT * FROM share_grants WHERE run_id=?
                   ORDER BY created_at DESC, grant_id LIMIT ?""",
                (run_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT * FROM share_grants
                   ORDER BY created_at DESC, grant_id LIMIT ?""",
                (limit,),
            ).fetchall()
    return [_grant_row(row) for row in rows]


def revoke_grant(grant_id: str, at: str, note: str | None) -> dict:
    """撤销：以第一次撤销时间为准，重复撤销不覆盖原留痕。

    撤销与读取的并发由 `BEGIN IMMEDIATE` + 进程内锁共同约束：
    撤销先拿到写锁，之后的读取只看得到已撤销状态，因此以撤销为准。
    """
    with _LOCK, _connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute(
                "SELECT revoked_at FROM share_grants WHERE grant_id=?", (grant_id,)
            ).fetchone()
            if row is None:
                conn.execute("ROLLBACK")
                return {"found": False, "already": False, "revoked_at": None}
            if row["revoked_at"]:
                conn.execute("COMMIT")
                return {"found": True, "already": True, "revoked_at": row["revoked_at"]}
            conn.execute(
                "UPDATE share_grants SET revoked_at=?, revoke_note=? WHERE grant_id=?",
                (at, note, grant_id),
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
    return {"found": True, "already": False, "revoked_at": at}


# ---------- 共享读取留痕 ----------

def append_share_read(grant_id: str, run_id: str, channel: str, outcome: str,
                      at: str, note: str | None = None) -> int:
    with _LOCK, _connect() as conn:
        cursor = conn.execute(
            """INSERT INTO share_reads (grant_id, run_id, channel, outcome, at, note)
               VALUES (?,?,?,?,?,?)""",
            (grant_id, run_id, channel, outcome, at, note),
        )
        return int(cursor.lastrowid)


def list_share_reads(grant_id: str | None = None, run_id: str | None = None,
                     limit: int = 500) -> list[dict]:
    clauses: list[str] = []
    params: list = []
    if grant_id:
        clauses.append("grant_id=?")
        params.append(grant_id)
    if run_id:
        clauses.append("run_id=?")
        params.append(run_id)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with _LOCK, _connect() as conn:
        rows = conn.execute(
            f"""SELECT id, grant_id, run_id, channel, outcome, at, note
                FROM share_reads {where} ORDER BY id LIMIT ?""",
            (*params, limit),
        ).fetchall()
    return [dict(row) for row in rows]


# ---------- 审计查阅 ----------
# 请求键由 (run_id, actor, purpose) 复算；完成标记与访问记录同一事务落库。
# 留痕写失败则整体回滚，调用方据此拒绝返回原文；重试命中同一键不重复记账。

AUDIT_FIELDS = """request_key, run_id, purpose, actor, status, created_at,
                  completed_at, note"""


def audit_read(request_key: str) -> dict | None:
    with _LOCK, _connect() as conn:
        row = conn.execute(
            f"SELECT {AUDIT_FIELDS} FROM audit_reads WHERE request_key=?",
            (request_key,),
        ).fetchone()
    return dict(row) if row else None


def begin_audit_record(request_key: str, run_id: str, purpose: str, actor: str,
                       at: str, note: str | None = None) -> dict:
    """登记一次查阅：不存在则落 pending；已存在则原样返回。

    使用 INSERT ... ON CONFLICT DO NOTHING 保证并发重试只产生一条记录。
    """
    with _LOCK, _connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute(
                """INSERT INTO audit_reads (request_key, run_id, purpose, actor, status,
                       created_at, completed_at, note)
                   VALUES (?,?,?,?,?,?,?,?)
                   ON CONFLICT(request_key) DO NOTHING""",
                (request_key, run_id, purpose, actor, "pending", at, None, note),
            )
            row = conn.execute(
                f"SELECT {AUDIT_FIELDS} FROM audit_reads WHERE request_key=?",
                (request_key,),
            ).fetchone()
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
    return dict(row)


def complete_audit_read(request_key: str, at: str) -> dict:
    """pending / interrupted -> complete；已 complete 的行保持不变（重试不重复记账）。

    中断恢复把残留记录标成 interrupted，之后同一请求键重试仍可补齐成 complete：
    原文此前从未返回过，补齐才算这一次查阅真正完成。
    """
    with _LOCK, _connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute(
                """UPDATE audit_reads SET status='complete', completed_at=?
                   WHERE request_key=? AND status IN ('pending','interrupted')""",
                (at, request_key),
            )
            row = conn.execute(
                f"SELECT {AUDIT_FIELDS} FROM audit_reads WHERE request_key=?",
                (request_key,),
            ).fetchone()
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
    if row is None:
        raise KeyError(request_key)
    return dict(row)


def mark_audit_interrupted(request_key: str, at: str) -> bool:
    """中断恢复：只把 pending 标成 interrupted，已完成的记录不动。"""
    with _LOCK, _connect() as conn:
        cursor = conn.execute(
            """UPDATE audit_reads SET status='interrupted', completed_at=?
               WHERE request_key=? AND status='pending'""",
            (at, request_key),
        )
        return cursor.rowcount > 0


def list_audit_reads(run_id: str | None = None, limit: int = 500) -> list[dict]:
    with _LOCK, _connect() as conn:
        if run_id:
            rows = conn.execute(
                f"""SELECT {AUDIT_FIELDS} FROM audit_reads
                    WHERE run_id=? ORDER BY created_at, request_key LIMIT ?""",
                (run_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                f"""SELECT {AUDIT_FIELDS} FROM audit_reads
                    ORDER BY created_at, request_key LIMIT ?""",
                (limit,),
            ).fetchall()
    return [dict(row) for row in rows]


def list_pending_audit_reads() -> list[dict]:
    """重启恢复用：进程中断留下的未完成记录。"""
    with _LOCK, _connect() as conn:
        rows = conn.execute(
            f"""SELECT {AUDIT_FIELDS} FROM audit_reads
                WHERE status='pending' ORDER BY created_at, request_key"""
        ).fetchall()
    return [dict(row) for row in rows]


def record_share_read_atomic(grant_id: str, channel: str, at: str,
                             now_epoch: float) -> dict:
    """同一事务里判定撤销/过期并记录一次成功读取。

    撤销事务与本事务按 SQLite 写锁串行：撤销先提交则这里看到已撤销并拒记；
    本事务先提交则该次读取发生在撤销之前，属合法读取。故撤销为准。
    """
    with _LOCK, _connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute(
                """SELECT run_id, revoked_at, expires_epoch FROM share_grants
                   WHERE grant_id=?""",
                (grant_id,),
            ).fetchone()
            if row is None:
                conn.execute("ROLLBACK")
                return {"found": False, "active": False, "run_id": None}
            if row["revoked_at"]:
                conn.execute("ROLLBACK")
                return {"found": True, "active": False,
                        "reason": "SHARE_REVOKED", "run_id": row["run_id"]}
            expires = row["expires_epoch"]
            if expires is not None and now_epoch >= float(expires):
                conn.execute("ROLLBACK")
                return {"found": True, "active": False,
                        "reason": "SHARE_EXPIRED", "run_id": row["run_id"]}
            conn.execute(
                """INSERT INTO share_reads (grant_id, run_id, channel, outcome, at, note)
                   VALUES (?,?,?,?,?,?)""",
                (grant_id, row["run_id"], channel, "granted", at, None),
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
    return {"found": True, "active": True, "run_id": row["run_id"]}
