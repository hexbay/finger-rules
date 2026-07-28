---
name: supplement-finger-rules
description: >-
  为"有插件(POC)但未验证"的漏洞补齐组件指纹与关联。当用户要求排查未验证漏洞、
  补齐漏洞的关联组件、或为缺指纹的产品新增指纹规则时使用。基于 corridor MCP 拉取
  漏洞/Nuclei 模板,按"仅根响应 HTTP 指纹"标准判定,把指纹写入本仓库 http/*.yaml。
  触发词:未验证漏洞、补齐组件、补齐指纹、新增指纹、finger rule、组件指纹。
---

# 补齐漏洞组件指纹(supplement-finger-rules)

为「有插件支持(`poc_support=1`)但未人工验证(`checked=false`)」的漏洞补齐**关联组件**与**产品指纹**。
指纹以 YAML 形式写入**当前工作目录**的 `http/*.yaml`(不走 MCP 建 PR 工具),后续随仓库常规 PR 合并。

## 核心原则(必须遵守)

1. **只匹配根响应**:指纹只能基于访问根 URL(`/`)拿到的响应做匹配 —— `part` 仅限
   `title` / `body` / `header` / `headers.<Name>` / `icon_hash`。
2. **禁止 plugins / 路径型指纹**:不得使用 `plugins: - path: /xxx`。任何"标识只出现在特定子路径"的
   产品(配置文件泄露、监控端点、漏洞利用路径、子面板)一律**跳过**,不硬做。
3. **指纹是"识别产品",不是"复现漏洞"**:markers 必须是稳定的产品身份特征,而非利用响应。
4. **动手前先查重、查仓库**:产品可能已在 `http/*.yaml` 里有指纹(DB 的 `has_finger=false` 可能只是未同步)。
   已存在则跳过。
5. **通用模板保持不动**:open redirect / XSS fuzz / JWT·JDBC 泄露 / dockerfile / config listing / SSRF 等
   无具体产品的通用检测,既不建指纹也不强行关联。

## 数据来源(corridor MCP)

- `query_vulnerability_list(poc_support=1, checked=false, page, page_size)` —— 拉未验证且有插件的漏洞。
  结果很大,会落盘成文件;用 Python 解析,勿直接读进上下文。
- `get_nuclei_template(key)` —— 用漏洞 `key`(或 CVE)拉 POC 模板,是判定指纹的**权威依据**。
- `query_product(key=...)` / `search_product(keyword=...)` —— 查产品是否存在、`has_finger`、`vendor`。
- `link_vulnerability_products(vulnerability_id, product_ids, full=false)` —— 回写漏洞↔组件关联(增量)。

## 流程

### 1. 拉取并分类
调用 `query_vulnerability_list(poc_support=1, checked=false, page_size=300)`,落盘后用 Python 分桶:
- **无组件**:`products` 为空 —— 多为通用模板(跳过);少数能对上真实产品(候选做关联)。
- **有组件但组件无指纹**(`products[].has_finger` 全 false)—— 指纹主战场。
- **有组件且有指纹** —— 无需处理。

对候选产品再按性质预筛并剔除:
- **SaaS 子域名接管服务**(aftership/aha/wufoo/ngrok/readme 等)—— 靠 CNAME+报错页,无法做资产指纹,跳过。
- **纯网络/TCP 产品**(tidb/clamav/sql_server 等,模板 `transport` 非 http 或模板体是 `tcp:`)—— 本仓库是 HTTP 指纹,跳过。
  注意 `transport` 字段不完全可靠,最终以 Nuclei 模板内容为准。

### 2. 逐产品判定(拉模板)
对每个候选产品,取其一个漏洞 `key` 调 `get_nuclei_template`,读模板判断:
- 模板是 `http:` 且存在**根页面可见的稳定标识** → **建指纹**。可用来源:
  - `metadata.fofa-query` / `shodan-query` / `zoomeye-query` 里的 `title=` / `body=` / favicon hash;
  - `matchers` 里针对产品页(而非利用 payload)的 `title` / `body` word;
  - 特有响应头(如 `X-Drp-`、`X-Magento-Tags`)。
- 标识只在子路径 / 是配置文件或利用响应 / 过于宽泛(如 title「Netgear」)/ 已有通用指纹 → **跳过**。

### 3. 写指纹到 http/*.yaml
**格式约定**(与仓库现状一致):
```yaml
- name: <产品 key>            # 必须等于 corridor 产品 key,便于 DB 同步 has_finger
  vendor: <厂商 key>          # 可选,已知则填(=vendor key)
  matchers:
    - part: title             # title | body | header | headers.<Name> | icon_hash
      type: word              # word | regex
      condition: and          # 多 words 时可选 and/or
      words:
        - "稳定标识"
```
- **优先英文/ASCII 标识**;中文标题易受编码影响,除非必要不用。多标识用 `condition: and` 收紧,降低误报。
- **放置文件**:通用 Web 应用 → `http/app.yaml`(catch-all);其余按品类归入对应文件
  (router/camera/device/database/cms/framework/server 等)。
- **落地前**:`grep -ril "<name>\|<关键标识>" http/*.yaml` 查重;**落地后**:用 `python -c "import yaml; yaml.safe_load(open(f))"` 校验解析。
- 已知 `http/plugins.yaml` 是路径型指纹专用文件 —— 本流程**禁止**往里加。

### 4. (可选)补齐关联组件
对"无组件但能对上真实产品"的漏洞:先 `search_product`/`query_product` 确认产品存在(不存在可 `create_product`),
再 `link_vulnerability_products(vulnerability_id, [product_id])` 增量关联。通用模板不处理。

### 5. 汇报
输出:本批建了哪些指纹(name/文件/匹配依据)、跳过了哪些及原因、关联了哪些漏洞↔组件。
大批量时**先做 10~20 个小批验证**给用户确认格式,再放量。

## 判定速查表

| 模板特征 | 处理 |
|---|---|
| 根页面 title/body/favicon 有稳定产品标识 | ✅ 建指纹(app.yaml 或对应品类文件) |
| 特有响应头(X-Xxx-) | ✅ 建指纹(part: header) |
| 标识只在子路径 / `/config`、`/.xxx.yml`、`/monitoring` 等 | ⏭️ 跳过(禁止 plugins) |
| 仅漏洞利用 payload 响应,无产品页标识 | ⏭️ 跳过 |
| 网络/TCP 模板(非 HTTP) | ⏭️ 跳过 |
| SaaS 子域名接管服务 | ⏭️ 跳过 |
| 通用检测(open redirect/xss fuzz/JWT 泄露等) | ⏭️ 跳过,不关联 |
| title 过泛(如厂商名)或已有通用指纹 | ⏭️ 跳过 |
| 产品在 http/*.yaml 已有指纹 | ⏭️ 跳过 |

## 示例(已落地)

```yaml
# http/app.yaml —— 根响应型
- name: sftpgo
  vendor: sftpgo_project
  matchers:
    - part: title
      type: word
      words:
        - "SFTPGo"

- name: octoprint
  vendor: octoprint
  matchers:
    - part: title
      type: word
      words:
        - "OctoPrint"

- name: digital_rebar
  matchers:
    - part: header
      type: word
      words:
        - "X-Drp-"
```
