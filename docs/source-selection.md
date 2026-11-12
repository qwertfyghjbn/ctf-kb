# 阶段 A：开源资源选型

检查时间：2026-11-12。原则：优先复用已有索引，不整库克隆无法利用的数据。

## 采用（主数据）

### [0xMarcio/pocindex](https://github.com/0xMarcio/pocindex) + CDN `https://pocindex.io/`

- 维护活跃（检查当日仍在同步），MIT。
- 提供结构化 JSON，无需克隆 git 历史：
  - `CVE_list.json`（约 50MB / 85444 条“带公开利用相关资料的 CVE”）
  - `cve_metadata.json`（CVSS + advisory）
  - `epss.json` / `kev.json` / `nuclei.json` / `repo_meta.json`
- 每条可含 `desc`、`title`、`vendor`、`product`、`poc`、`nuclei`、`msf`、`edb`、`vulhub`、`collections`。
- **适合作为 CVE 主索引 + PoC/检测/复现环境链接层。**
- 限制：只覆盖“被索引到公开 PoC/模板/EDB 等”的 CVE，不是 NVD 全集；产品/版本不是完整 CPE；社区 PoC 质量混杂。

### [projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) 的 `cves.json`

- MIT，社区维护的检测模板索引（NDJSON）。
- 用于补全官方模板路径、标题，并提供部分 CWE（pocindex 的 `nuclei.json` 含 cwe 字段）。
- **作为检测模板层，不作为利用代码。**
- 未克隆 1 万+ YAML 模板正文，避免把扫描 payload 和体积带进知识库。

## 采用（补充，链接级，不下载代码）

### [vulhub/vulhub](https://github.com/vulhub/vulhub)

- Docker 复现环境，按 `产品/CVE` 组织。pocindex 已给出约 250 条 vulhub URL。
- **作为“可启动的本地实验环境”指针，不导入 compose 文件。**

### CISA KEV

- 用于标记已知在野利用。pocindex `kev.json` 已覆盖；可选再拉官方 feed。

## 不作为主库 / 不完整下载

### [trickest/cve](https://github.com/trickest/cve)

- 一年一个目录、一 CVE 一个 Markdown，PoC 链接来自 CVE 引用和 GitHub。
- 对 Agent 不友好（非 JSON），与 pocindex 高度重叠，完整 clone 体积大。
- **排除原因：已被 pocindex 结构化覆盖。**

### [nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)

- 按年存放 GitHub 仓库元数据 JSON，CC0，明确警告可能含恶意软件。
- 只含 repo 链接/stars，不含 CVE 描述、产品、CWE。
- pocindex 的 `poc` + `repo_meta` 已聚合同类信息。
- **排除原因：与主索引重复，且完整历史 clone 不必要。**

### [Dest1ny-Sec/Des-CTF-Knowledge](https://github.com/Dest1ny-Sec/Des-CTF-Knowledge)

- CTF WriteUp / 手法卡片 / RAG 语料，不是 CVE 数据库。
- 质量说明里承认 WP 与代码未充分校验。
- **适合后续作为 WriteUp 补充源，不适合当 CVE 主库。** MVP 只留扩展接口。

## 不存在可直接复用的“现成本地 CLI 知识库”

检索未发现同时满足以下条件的成熟项目：SQLite FTS、区分 PoC/检测/WriteUp、保留本地验证状态、面向 Agent 的 JSON CLI。因此基于 pocindex JSON **做薄封装**，而不是再造爬虫。
