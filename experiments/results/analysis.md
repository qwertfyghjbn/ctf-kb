# Baseline vs Improved 对照与失败分析

日期：2026-11-12。同一 `data/ctf-kb.sqlite` 快照（85444 CVE），同一 `experiments/testset.json`（28 条，其中 20 条计入 Recall/MRR）。未改 Ground Truth。

Baseline 代码冻结于 `experiments/baseline_pkg/`（HEAD search.py sha256 前缀 `9067012abaa1987c`）。Improved 为当前 `ctf_kb/`。

计时：`time.perf_counter`，warmup=1，每查询重复 5 次取中位数，含 `lookup_cve` 详情组装。

## 指标

| 指标 | Baseline | Improved |
|---|---:|---:|
| Recall@5 | 0.65 | 1.0 |
| MRR | 0.625 | 1.0 |
| mismatch | 2/7 | 0/7 |
| empty_fail | 1 | 0 |
| FTS 语法错误 | 24 | 0 |
| P50 ms | 14.63 | 12.75 |
| P95 ms | 96.67 | 17.29 |

逐样本表见 `experiments/results/comparison.md`。原始 JSON：`baseline.json` / `improved.json`。

## Baseline 根因（已核实，不是“召回不够所以上向量”）

1. **FTS5 查询未转义**。`Apache 2.4.50`、`OpenSSH 8.4`、`foo-bar`、`nginx/1.18.0`、甚至 `CVE-2021-42013` 的 MATCH 都会把 `.` `-` 当列过滤器。`search()` 吞掉 `OperationalError` 伪装成 0 命中，再 LIKE 回退。`foo-bar` 因此误命中 CVE-2022-31159。
2. **版本用子串，且描述未出现精确版本就丢弃**。`2.4.5` ⊂ `2.4.50`；Struts 2.5.9 / Log4j 2.14.1 描述里没有该字符串 → 0 命中。
3. **products 表缺口**被算法丢弃放大（OpenSSL / Bash）。
4. **LIKE 回退**为凑 Top-k 返回无关 CVE。
5. 旁路缺陷（对照实验外）：`is_trusted_url` 子串匹配可被伪造；`ingest` 空数据仍清空；`verify_cli.py` 写真实库。

## Improved 做了什么（最小修复，无 embedding）

- FTS token 全部加双引号；CVE ID 查询不走全文；MATCH 失败写入 `status=fts_error`，不再伪装成功。
- 结构化范围（`data/local/version_ranges.json` + 本地 note 短句解析）给出 `affected` / `not_affected` / `unknown`。`not_affected` 过滤；`unknown` 保留并标明证据不足。禁止 `2.4.5` 命中 `2.4.50`。
- 取消 LIKE 回退。产品+版本无可靠候选时允许空结果。
- 默认 Top 5。URL 用 `urlparse` 校验 hostname/路径。空 CVE 列表不清库。`note` 增量更新 FTS。`verify_cli` 写临时副本。

## Improved 仍存在的问题（不是评测失败）

这些样本 Recall 已过，但 Agent 仍可能看到噪声：

| 现象 | 原因 | 为何不算本次失败 |
|---|---|---|
| `Apache HTTP Server 2.4.51` 仍返回其他 httpd CVE（unknown） | 没有全量 CPE，不能把未知范围的 httpd 洞一律丢掉 | 负例只要求不把 41773/42013 当受影响，已满足 |
| `OpenSSH 8.4` / `nginx/1.18.0` 返回其他 unknown CVE | 同上 | 6387 / 7529 已被 not_affected 过滤 |
| `Apache 2.4.50`（无 HTTP Server）仍可能同时看到 41773 | 查询只有厂商名，版本范围不套用到具体产品 | verify_cli 仍能把 42013 排第一；完整产品名查询已排除 41773 |
| `PHP deserialization` 第一条偶发非 CWE-502 | 类型查询走 FTS，无唯一 CVE | 测试集 scored=false |
| Heartbleed/Bash 能召回依赖精选范围 + 别名 | products 表仍可能缺行 | 这是数据缺口，不是向量缺口。完整 CPE 镜像明确不做 |

**不引入 embedding / Reranker。** 瓶颈是 FTS 语法、版本比较和空结果策略，对照实验已证明修这些足够把 Recall@5 从 0.65 拉到 1.0。向量检索解决不了 `2.4.5`⊂`2.4.50`，还会把“无可靠候选”伪装成语义相近的错误 CVE。

## Agent 接入

```text
需要查已知漏洞时调用：
  python3 /mnt/sdb/tmp_hou/tmp_lqs/ctf-kb/ctf-kb search "<产品 版本或报错关键词>" --json --limit 5
精确 CVE：
  python3 /mnt/sdb/tmp_hou/tmp_lqs/ctf-kb/ctf-kb show CVE-YYYY-NNNNN --json
```

必读字段：`status`（ok/empty/fts_error）、`version_status`（affected/not_affected/unknown）、`skipped_not_affected`、`verification.status`、`preconditions`、`uncertainty`。

规则：

- 不要执行返回的 PoC URL。
- `trusted` 只表示链接落在已知项目/公告站点，**不是**已验证可利用。
- `version_status=unknown` 不得写成“目标有洞”。
- `version_status=not_affected` 已被过滤；若仍看到，当作实现错误。
- `status=empty` 表示无可靠候选，不要改去网上随机搜 PoC 执行。
- 默认 5 条；不要把 `--limit` 拉到 30 来“多看一点”。
