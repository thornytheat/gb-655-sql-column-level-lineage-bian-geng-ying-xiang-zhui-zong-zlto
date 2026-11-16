# 运行手册 lineageguard

## 1 启动

```bash
docker compose up -d --build
curl -s localhost:18214/api/health
```

宿主端口 `18214`，容器内 `8000`。启动时如果库是空的，服务会自动把 `sample_data/` 里的样例跑一遍，页面打开即有数据。

## 2 截图与验收命令

```bash
docker compose config --quiet
docker compose exec -T app python -m pytest -q
```

## 3 主流程

1. 打开 `http://localhost:18214/`，看规格单的字段清单与采信诊断。
2. `/types` 比较两个类型写法，看读者 / 写者两向结论。
3. `/mapping` 看旧名到新名、别名 SQL、冲突项。
4. `/impact` 看受影响节点、环、断链、单边登记。
5. `/batches` 点「跑一次」，再点「陈旧提交」验证 409。
6. `/spec` 导出迁移单与三份账目 CSV。

## 4 重建数据库

```bash
docker compose down -v
docker compose up -d --build
```

命名卷 `lineageguard-data` 挂着 `/data/lineageguard.sqlite`。删卷即清空批次、快照与隔离区。

## 5 接口

| 方法 | 路径 | 作用 |
|---|---|---|
| GET | `/api/health` | 服务与库状态、当前批次号 |
| POST | `/api/schemas/import` | 采信样例文件，返回快照摘要与诊断 |
| GET | `/api/schemas/quarantine` | 隔离区 JSON |
| GET | `/api/schemas/quarantine.csv` | 隔离区 CSV |
| GET | `/api/types` | 类型格与别名表 |
| POST | `/api/types/compare` | 两个类型写法比较 |
| POST | `/api/compat` | 一对版本的两向判定 |
| GET | `/api/mapping` | 映射表、别名、冲突 |
| GET | `/api/impact` | 影响面、环、断链 |
| POST | `/api/runs` | 跑批次，可带基线版本号与生效区间 |
| GET | `/api/batches` | 批次历史 |
| GET | `/api/reconcile` | 四账对账 |
| GET | `/api/export/spec.md` | 迁移单 Markdown |
| GET | `/api/export/fields.csv` | 字段账 CSV |
| GET | `/api/export/refs.csv` | 引用账 CSV |
| GET | `/api/export/ledger.csv` | 账目 CSV |
| GET | `/api/export/manifest.json` | 运行清单 |
| POST | `/api/shares` | 按列发放共享凭据（内部；响应含一次性凭据） |
| GET | `/api/shares` | 授权列表（不含凭据） |
| GET | `/api/shares/{grant_id}` | 单个授权详情 |
| POST | `/api/shares/{grant_id}/revoke` | 撤销授权 |
| GET | `/api/shares/{grant_id}/reads` | 该授权的访问留痕 |
| GET | `/api/shared/impact` | 凭据读取脱敏影响路径 |
| GET | `/api/shared/impact.csv` | 凭据下载脱敏影响路径 CSV |
| POST | `/api/audit/reads` | 填用途查阅原件（内部，返回原文并留痕） |
| GET | `/api/audit/reads` | 原件查阅留痕 |

共享读取用 `Authorization: Bearer <凭据>`；普通共享凭据访问内部接口一律 403。设了 `LINEAGEGUARD_INTERNAL_KEY` 时，内部接口还要带 `X-Internal-Key` 头。

## 6 共享与审计操作

1. 在 `/shares` 或 `POST /api/shares` 发放凭据：`{"columns": ["fct_pay.pay_amt"], "label": "协作方甲"}`。
   响应里的 `credential` 只出现一次，转交后服务端无法再取回。
2. 协作方用该凭据读 `/api/shared/impact`，只看到授权列与匿名节点；表名、列名、SQL 原文都不出现。
3. 收回时 `POST /api/shares/{grant_id}/revoke`。旧凭据与下载入口立即失效，访问留痕可回读。
4. 审计查原件：`POST /api/audit/reads`，必须带 `purpose` 与 `actor`；留痕失败一律不返回原文。
   重试带同一 `request_key`（或缺省推导键）不会重复记账。

## 7 失败处置

| 现象 | 原因 | 处置 |
|---|---|---|
| 409 `VERSION_STALE` | 提交带的基线序号落后 | 去掉 `base_version_seq` 或填当前序号 |
| 400 `WINDOW_INVERTED` | 生效区间起点不早于终点 | 检查 `effective_from` / `effective_to` |
| 400 `BAD_INPUT` | 文件名、参数或 JSON 结构不对 | 看返回的 `detail` |
| 404 `NOT_FOUND` | 还没跑过批次 | 先在 `/batches` 点「跑一次」 |
| 401 `SHARE_CREDENTIAL_INVALID` | 没带凭据或凭据认不出 | 检查 `Authorization: Bearer` |
| 403 `SHARE_FORBIDDEN` | 共享凭据访问内部接口，或换了批次 | 用该授权绑定的批次与对应范围的读取接口 |
| 410 `SHARE_REVOKED` / `SHARE_EXPIRED` | 授权已撤销或过期 | 重新发放；撤销后旧凭据与下载入口一并失效 |
| 400 `SHARE_SCOPE_EMPTY` / `SHARE_SCOPE_UNKNOWN` | 授权列为空或全部不在本批次 | 按 `表.列` 或 `{field_id}` 给出本批次存在的列 |
| 400 `AUDIT_PURPOSE_REQUIRED` / `AUDIT_ACTOR_REQUIRED` | 查原件没填用途或查阅人 | 补齐 `purpose` 与 `actor` |
| 500 `AUDIT_WRITE_FAILED` | 留痕写失败 | 修复存储后重试；原文不会返回，重试同一请求键不重复记账 |

## 8 端口与并发

本服务固定 18214。同时起多个栈时改 `docker-compose.yml` 的端口映射与 `lineageguard-data` 卷名，避免与本机其他项目抢端口、串数据。
