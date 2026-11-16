"""应用装配：路由注册、静态资源、启动时把样例跑一遍。"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app import config, errors, store
from app.modules.m1_intake import handler as m1_handler
from app.modules.m2_types import handler as m2_handler
from app.modules.m3_compat import handler as m3_handler
from app.modules.m4_mapping import handler as m4_handler
from app.modules.m5_impact import handler as m5_handler
from app.modules.m6_batches import handler as m6_handler
from app.modules.m6_batches import service as batch_service
from app.modules.m7_migration import handler as m7_handler
from app.modules.m8_sharing import audit as audit_service
from app.modules.m8_sharing import handler as m8_handler

STATIC_DIR = Path(__file__).resolve().parent / "static"


@asynccontextmanager
async def lifespan(_: FastAPI):
    store.init_db()
    batch_service.ensure_seeded()
    # 中断恢复：上次进程留下的未完成查阅标成 interrupted，不计成功查阅
    audit_service.recover_pending()
    yield


app = FastAPI(title=config.APP_TITLE, docs_url="/docs", redoc_url=None,
              lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

for module_handler in (m1_handler, m2_handler, m3_handler, m4_handler,
                       m5_handler, m6_handler, m7_handler, m8_handler):
    app.include_router(module_handler.router)

errors.install(app)

# 共享凭据只放行共享读取入口，其余一律按越权拒绝。
# 少了这一层，拿到凭据的外部协作方可以直接调 /api/impact 或导出接口拿到原文。
SHARE_ONLY_PREFIX = "/api/shared/"
SHARE_SAFE_PREFIXES = ("/static/",)


@app.middleware("http")
async def confine_share_credential(request, call_next):
    header = request.headers.get("authorization")
    token = (header or "").strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    if token:
        from app.modules.m8_sharing import gate

        if gate.is_share_credential(token):
            path = request.url.path
            if not (path.startswith(SHARE_ONLY_PREFIX)
                    or path.startswith(SHARE_SAFE_PREFIXES)):
                from fastapi.responses import JSONResponse

                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "SHARE_FORBIDDEN",
                        "label": "凭据越权访问",
                        "message": "共享凭据只能读取脱敏影响路径",
                        "detail": {"reason": "SHARE_FORBIDDEN", "path": path},
                    },
                )
    return await call_next(request)


@app.get("/api/health")
def health() -> dict:
    run = store.latest_run()
    return {
        "status": "ok",
        "app": config.APP_NAME,
        "ruleset": config.RULESET_VERSION,
        "db": str(store.db_path()),
        "runs": store.count_runs(),
        "run_id": (run or {}).get("run_id"),
        "window_semantics": config.WINDOW_SEMANTICS,
    }


@app.get("/api/reasons")
def reasons_api() -> dict:
    from app import reasons

    return {
        "codes": [
            {"code": code, "label": reasons.label(code), "severity": reasons.severity(code)}
            for code in reasons.known_codes()
        ]
    }
