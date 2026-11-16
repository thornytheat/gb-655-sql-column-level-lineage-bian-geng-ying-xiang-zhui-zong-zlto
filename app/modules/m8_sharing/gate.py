"""内部接口门禁：共享凭据不得进入发放、撤销与审计原件。

两道关：
1. 请求带着共享凭据 -> 一律按越权拒绝。普通共享凭据只能读自己范围内的脱敏视图，
   不能发放新凭据、不能撤销、不能查原件、不能列授权。
2. 配置了 `LINEAGEGUARD_INTERNAL_KEY` 时，内部接口还要求 `X-Internal-Key`；
   对外共享前应配置该口令，否则内部接口沿用本项目的内网单用户假设。
"""

from __future__ import annotations

import hmac

from app import config, errors, store
from app.modules.m8_sharing import grants


def _token(header_value: str | None) -> str:
    raw = (header_value or "").strip()
    if raw.lower().startswith("bearer "):
        return raw[7:].strip()
    return raw


def is_share_credential(token: str) -> bool:
    if not token:
        return False
    return store.grant_by_credential_hash(grants.credential_hash(token)) is not None


def require_internal(authorization: str | None,
                     internal_key: str | None = None) -> None:
    token = _token(authorization)
    if is_share_credential(token):
        raise errors.Forbidden(
            "共享凭据不能访问内部接口",
            detail={"reason": "SHARE_FORBIDDEN"},
            code="SHARE_FORBIDDEN", label="凭据越权访问",
        )
    expected = config.INTERNAL_KEY
    if not expected:
        return
    supplied = (internal_key or "").strip()
    if not supplied:
        raise errors.Unauthorized(
            "缺少内部口令", detail={"header": "X-Internal-Key"},
            code="SHARE_CREDENTIAL_INVALID", label="共享凭据无效",
        )
    if not hmac.compare_digest(supplied, expected):
        raise errors.Forbidden(
            "内部口令不正确", detail={"header": "X-Internal-Key"},
            code="SHARE_FORBIDDEN", label="凭据越权访问",
        )
