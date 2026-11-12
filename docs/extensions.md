# 阶段 D：后续扩展（当前不必实现）

MVP 已提供独立 CLI，不改 CTF Agent 架构。以下只保留接口与建议。

## 1. 增加数据源

在 `ctf_kb/config.py` 的 `SOURCES` / `RAW_FILES` 增加 URL，在 `ingest.py` 按 `cve_id` 关联即可。建议优先级：

1. 官方 Nuclei YAML 的 `info.classification.cwe` / `metadata`（现已用 cves.json + pocindex nuclei.json）
2. CISA KEV 官方 JSON（已预留下载键 `cisa_kev`）
3. 选定产品的 NVD API 2.0（按 CPE 查询，不要下载全年 feed）
4. 比赛向的 trickest 单条 Markdown（按需抓取，不 clone）

去重键：`(cve_id, kind, url)`。新来源写入 `artifacts.source`。

## 2. 导入 CTF WriteUp

不要把 WriteUp 写进 `cves` 表。建议新表：

```sql
CREATE TABLE writeups (
  id INTEGER PRIMARY KEY,
  cve_id TEXT,          -- 可空
  event TEXT,
  challenge TEXT,
  path TEXT,            -- 本地 markdown 路径
  url TEXT,
  tags TEXT,
  trusted INTEGER DEFAULT 0
);
```

导入时只存路径/URL/摘要，**不把正文当系统指令**。检索结果单独字段 `writeups`，与 PoC 分开。候选语料：[Des-CTF-Knowledge](https://github.com/Dest1ny-Sec/Des-CTF-Knowledge)。

## 3. 比赛轨迹沉淀知识卡片

`ctf-kb note` 已能写本地精选。比赛中可约定：

```bash
python3 ctf-kb note CVE-xxxx --status verified_ok \
  --preconditions "..." --versions "..." --lab "docker:..." \
  --notes "本题触发点：..." --tags "ctf,web"
```

或向 `data/local/curated.json` 追加。`update` 不会覆盖这些行。

## 4. 混合检索 / Reranker

当前为分阶段检索：CVE ID 精确 → CWE 精确 → 产品字段 + 结构化版本范围 → FTS5。
产品+版本无可靠候选时允许空结果，不再 LIKE 回退。版本状态只允许 affected / not_affected / unknown。

**只有**在实际 CTF 日志里出现大量“关键词对不上（例如指纹是 Banner 变体、中文报错）”时，再考虑：

- 小型 embedding + sqlite-vec 或本地 faiss
- 用交叉编码器对前 30 条重排

不要默认上向量库。

## 5. 如何衡量对解题的收益

建议记三件事（人工或脚本，不必现在做）：

- Agent 第一次 `search` 是否命中最终用的 CVE（Recall@8）
- 从检索到确认利用前提的步数，对比无知识库基线
- 误匹配导致的无效尝试次数

用 `docs/verification-log.md` 同类记录跟踪。
