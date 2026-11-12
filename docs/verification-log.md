# 阶段 C 验证记录

日期：2026-11-12。环境：本机 CLI，未对外部目标执行 PoC。

自动化：`python3 tests/test_kb.py`（夹具，13/13 PASS）+ `python3 tests/test_quality.py`（7/7 PASS）  
真实库：`python3 scripts/verify_cli.py` 写操作改走临时副本；历史 `verification-script-marker` 已按 curated 恢复为 unverified。

| # | 场景 | 结果 | 说明 |
|---|---|---|---|
| 1 | 已知 CVE ID | **通过** | `ctf-kb search CVE-2021-42013` / `cve` / `show` 均命中 |
| 2 | 软件名+版本 | **通过** | `Apache HTTP Server 2.4.50` 命中 42013 且过滤 41773；Struts 2.5.9 能召回（描述无该版本字符串） |
| 3 | 漏洞类型 | **通过** | `PHP deserialization` 以 CWE-502 为主；`CWE-22` 精确过滤 |
| 4 | PoC 来源 | **通过** | 42013：poc/nuclei/msf/edb/vulhub 均有；官方 nuclei 标 trusted |
| 5 | 验证状态区分 | **通过** | 42013=`static_review`，44228=`unverified` |
| 6 | 更新保留本地 | **通过** | `note` 写入后 `update --cached` 仍保留 status/preconditions；curated 未被覆盖 |
| 7 | 明显误匹配 | **通过（有限度）** | PHP 反序列化未混入无关 OpenSSL 夹具 CVE；`Apache 2.4.50` 不再被 Log4j 抢第一。CWE 检索按 EPSS/KEV 排序，热门穿越洞会排在前面，不一定是 httpd |
| 8 | Agent CLI | **通过** | `--json` 可解析；子命令前后均可 |

未做 / 不能报通过：

- 未在隔离环境实际打 CVE-2021-42013，故验证状态只到 `static_review`。
- 未接入 Codex 真机会话，仅用同一 CLI 接口验证 JSON。
- 未导入 NVD 全集与 WriteUp 正文。
- 社区 PoC URL 未逐条存活检测。
- 对照实验（同一库、同一测试集）：Baseline Recall@5=0.65 / FTS 错误 24；Improved Recall@5=1.0 / FTS 错误 0。见 `experiments/results/analysis.md`。不引入向量检索。

统计口径见 README 与 `ctf-kb stats`。
