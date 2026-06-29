# 设计：域名黑白名单 + IP/域名 ACL 架构统一

- 日期：2026-06-29
- 状态：待评审
- 主题：在 SNI/Host 层新增域名（mosdns 风格）黑白名单；并把 IP 层 `[egress]` 与域名 ACL 统一为同一套「配置基层 + 运行时 add/del 增量 + 最具体者赢优先级 + 运行时 API」架构。

## 1. 背景与现状

v6proxy 嗅探 HTTP `Host` / TLS `SNI` / QUIC `SNI`，按随机 IPv6 源地址转发。当前：

- **有** IP 层出站过滤 `[egress]`（`src/config.rs` 的 `EgressConfig`/`EgressFilter`）：CIDR `allow`/`deny` + 内置屏蔽内网/特殊段，作用于**解析出目标 IP 之后**；语义是"allow 覆盖一切，否则 deny，allow 非空即白名单"；仅配置文件、启动后不可变（`Arc<EgressFilter>` 经参数传入监听器）。
- **没有** 针对域名（SNI/Host）的黑白名单。

域名在两处被提取，正是加 ACL 的位置：
- TCP：`src/dataplane/tcp.rs` `handle_tcp` 中 `dst_host`（`resolve_dst` 之前）
- QUIC：`src/dataplane/quic.rs` `handle_quic_packet` 中 `sni`（`resolve_dst` 之前）

## 2. 目标 / 非目标

**目标**
1. 在 DNS 解析之前对域名做放行/拦截，TCP（Host+SNI）与 QUIC 都覆盖。
2. 域名匹配采用 mosdns 风格：`full:` / `domain:`（裸写默认）/ `keyword:`。**不含 `regexp:`**（不引入 regex 依赖、无 ReDoS 面）。
3. allow/deny 优先级采用"**最具体者赢**"（model B），IP 与域名两个过滤器**共用**判定函数。
4. **IP 与域名两套 ACL 对称**：都支持 配置文件基层 + 运行时 admin API；运行时改动以 add/del 增量持久化、热替换生效。

**非目标**
- 不做 IDN/punycode 转换（SNI/Host 通常已是 A-label）。
- 不改写用户的 `config.toml`（程序绝不回写配置文件）。

## 3. 域名匹配语义（mosdns 风格）

主机名先**归一化**：转小写、去掉结尾的 `.`。

| 前缀 | 含义 | 示例 |
|------|------|------|
| `full:` | 精确匹配 | `full:example.com` 仅匹配 `example.com` |
| `domain:`（裸写默认） | 域名 + 子域 | `domain:example.com` 匹配 `example.com`、`www.example.com` |
| `keyword:` | 子串包含 | `keyword:ads` 匹配 `ads.x.com` |

裸写（无前缀）等同 `domain:`。

## 4. 优先级模型 B：最具体者赢（IP 与域名共用）

对某个目标（域名或 IP），分别在 allow 与 deny 两侧求出"命中规则中最具体者"的**具体度**，由更具体的一侧决定；都不命中再走白名单兜底。

**共用判定函数**（泛型于可比较的具体度 `S: Ord`）：

```
fn decide<S: Ord>(best_allow: Option<S>, best_deny: Option<S>, allow_is_empty: bool) -> bool {
    match (best_allow, best_deny) {
        (None, None)        => allow_is_empty, // 无命中：allow 非空=白名单→拦；为空=默认放行
        (Some(_), None)     => true,           // 仅 allow 命中 → 放行
        (None, Some(_))     => false,          // 仅 deny 命中 → 拦截
        (Some(a), Some(d))  => a > d,          // 更具体者赢；平局(a==d) → deny 赢（更保险）
    }
}
```

> `allow_is_empty` 指**生效后的** allow 是否为空（IP 侧不含内置 deny，内置段只在 deny）。

**具体度定义**
- **IP**：命中 CIDR 的前缀长度 `prefix_len`（越长越具体）。裸 IP 作为 `/32`(v4)/`/128`(v6) 主机路由，最具体。内置屏蔽段并入 deny，按各自前缀长度参与比较。
- **域名**：用 `(tier, detail)` 字典序比较。
  - `full:` 命中 → `(3, 0)`
  - `domain:` 命中 → `(2, 该规则标签数)`，例：`domain:a.b.example.com` → `(2,4)` 胜过 `domain:example.com` → `(2,2)`
  - `keyword:` 命中 → `(1, 0)`（所有 keyword 同级；平局→deny）

**行为示例（域名）**

| 想要 | 规则 | 结果 |
|---|---|---|
| 封 `example.com` 但放行 `safe.example.com` | `deny: domain:example.com` + `allow: full:safe.example.com` | `safe`→放行（full 更具体），其余→拦 |
| 放行 `example.com` 但单独封 `ads.example.com` | `allow: domain:example.com` + `deny: full:ads.example.com` | `ads`→拦（full 更具体），其余→放行 |

**白名单模式提醒（footgun）**：只要某侧生效 allow 非空，所有"无命中"目标都会被拦（API 加一条 allow 即触发）。文档需写明。

## 5. 统一架构：两层（配置基层 + 运行时增量）

IP 与域名两套 ACL 用**同一套**两层机制，仅"规则类型/匹配器/具体度"不同。

- **静态基层**：`config.toml` 的 `[egress]`（已存在）与新增 `[domain]`，各含 `allow`/`deny`。每次启动读取、解析、校验后存入各自的 `OnceCell`。API 只读、不可改；程序绝不回写配置文件。
- **动态层**：admin API 下发，持久化进现有 `policies.json`。复用一个增量结构：

```
#[derive(Default, Serialize, Deserialize, Clone)]
struct AclDelta {
    #[serde(default)] allow_add: Vec<String>,
    #[serde(default)] allow_del: Vec<String>,
    #[serde(default)] deny_add:  Vec<String>,
    #[serde(default)] deny_del:  Vec<String>,
}
```

  `Policies` 增两字段（均 `#[serde(default)]`，旧文件无字段→空，向后兼容）：`domain_acl: AclDelta`、`egress_acl: AclDelta`。域名侧存规则字符串，IP 侧存 CIDR/IP 字符串。

- **生效集合**（两侧同公式）：
  - `effective_allow = (base.allow ∪ allow_add) − allow_del`
  - `effective_deny  = (base.deny  ∪ deny_add)  − deny_del`（IP 侧再并入内置屏蔽段）
- **编译 + 热替换**：各自编译为过滤器对象，放进全局 `ArcSwap`（仿 `state::POLICIES`）：`DOMAIN_FILTER`、`EGRESS_FILTER`。任何配置/动态变更后用 `(base, delta)` 重建并 `store` 热替换。

**add/del 操作语义（幂等、集合最小）**
- add(rule)：`*_del` 移除该规则；若该规则不在基层则加入 `*_add`。
- del(rule)：`*_add` 移除该规则；若该规则在基层则加入 `*_del`（抑制基层规则）。

## 6. 数据面接入

- 监听器**不再用参数传 egress**；TCP/QUIC 直接读全局 `EGRESS_FILTER.load()` / `DOMAIN_FILTER.load()`（与读 `POLICIES` 一致），监听器签名简化。
- TCP `handle_tcp`：取得 `dst_host` 后、`resolve_dst` 前：`if !DOMAIN_FILTER.load().is_allowed(&dst_host) { 日志+计数; return Ok(()) }`（丢弃，与"no SNI/Host found, dropping"一致）。
- QUIC `handle_quic_packet`：取得 `sni` 后、`resolve_dst` 前同样判断。
- `forward::resolve_dst` 仍按 egress 过滤目标 IP，但改为在调用处从 `EGRESS_FILTER.load()` 取（或保留 `&EgressFilter` 形参、由调用处加载后传入）。

## 7. IP 层 `[egress]` 改造

- `EgressFilter::is_allowed` 由"allow 覆盖一切"改为 model B（最长前缀者赢，调用共用 `decide`）。
- 由"仅配置 / 启动后不可变"升级为与域名对称的两层：`[egress]` 为基层，`policies.json.egress_acl` 为动态增量，`EGRESS_FILTER` 为 `ArcSwap` 热替换。
- 重建时合并 `base.allow/deny ∪ delta` 后，**再并入内置屏蔽段到 deny**（与现 `build_filter` 一致）。
- 现有 3 个 egress 测试仍通过：显式 allow 的更具体段照样盖过内置 deny；公网地址在白名单模式下被拒；deny 段照常生效。
- 新增测试：`allow: 2001:db8::/32` + `deny: 2001:db8:dead::/48` → `/48` 内地址被拦、其余 `/32` 内地址放行（放行大段、单独封小段）。
- 更新 `EgressFilter` 文档注释为最长前缀语义。
- **行为变化（更安全，需知会）**：旧模型下"allow 覆盖一切"，一条很宽的 allow（如 `::/0`）会盖过内置 deny 把 loopback/内网打开；新模型下更具体的内置 deny（如 `::1/128`）会赢，宽 allow 不再误开内网。现有 3 个测试不涉及此情形，均不受影响；仅"allow 段比某内置 deny 段更宽"时行为变化。

## 8. Admin API（Tier 1：allowlist + token，与 bindings 同级）

域名与 IP 两组**对称端点**，共用一套处理逻辑（按"操作哪个 `AclDelta` + 校验函数 + 重建函数"参数化）：

```
GET    /v1/domains                 列出 base / add / del / 以及最终 effective(allow,deny)
POST   /v1/domains/allow           {"rules":[...]}  追加到 allow
POST   /v1/domains/deny            {"rules":[...]}  追加到 deny
DELETE /v1/domains/allow           {"rules":[...]}  从 allow 删除（含抑制基层）
DELETE /v1/domains/deny            {"rules":[...]}  从 deny 删除（含抑制基层）

GET    /v1/egress                  同上，IP/CIDR
POST   /v1/egress/allow            {"rules":[...]}
POST   /v1/egress/deny             {"rules":[...]}
DELETE /v1/egress/allow            {"rules":[...]}
DELETE /v1/egress/deny             {"rules":[...]}
```

- 规则用 JSON body 传递（含 `:` 或 `/`，不放 URL path）。
- 写入前**校验**：域名侧前缀合法（`full:`/`domain:`/`keyword:`/裸写）且域名部分非空；IP 侧为合法 IP 或 CIDR。非法返回 `400` 且不落盘。
- 经 `state::apply_and_save` 原子落盘 + 版本号自增，随后重建对应 `*_FILTER` 热替换。
- 路由挂在现有 `authenticated`（token + allowlist）层。

## 9. 校验与错误

- 配置基层非法规则：`--check-config` / 启动阶段报错（与现 egress 一致）。
- API 非法规则：`400` 且不落盘。
- `policies.json` 中存在非法规则（异常情况）：加载时告警并跳过该条（防御式，不影响启动）。

## 10. 可观测性

- 命中拦截：`info`/`debug` 日志含 `peer`、被拦目标、`list=allow|deny`、`filter=domain|egress`。
- 计数器（复用 `metrics`）：`v6proxy_acl_blocked_total`，标签 `filter=domain|egress`、`proto=tcp|quic`。

## 11. 测试计划（TDD）

- `decide` 共用函数：四象限 + 平局 deny 赢。
- `DomainMatcher`：`full`/`domain`(含多级子域)/`keyword` 各匹配；归一化（大小写、尾点）。
- 域名 `DomainFilter::is_allowed`：第 4 节两个示例、白名单模式、纯黑名单。
- `AclDelta` 合并：`(base∪add)−del`；add/del 幂等、删基层抑制、再加撤销 del（域名与 IP 各一组）。
- 配置解析：`[domain]` 与 `[egress]` allow/deny（仿 `config.rs` 现有 egress 测试风格）。
- egress：保留旧 3 测试 + 新增"大段放行小段封" + 最长前缀语义。

## 12. 涉及文件

- `src/config.rs`：新增 `DomainConfig`（`[domain]`）、域名规则解析/校验；`EgressFilter::is_allowed` 改 model B（调用 `acl::decide`）；`EgressFilter::build` + `parse_net` / `canonicalize_net`。
- `src/acl.rs`（新，**顶层模块**而非 `dataplane/` 下，避免 `config`↔`dataplane` 循环）：`decide`、`Rule`/`DomainMatcher`/`DomainFilter`、`build_domain_filter`/`build_egress_filter`、全局 `DOMAIN_FILTER`/`EGRESS_FILTER`（`ArcSwap`）+ `*_BLOCKED` 计数、基层 `OnceCell`、`init_*`/`rebuild_*` 与 `canonicalize_rule`。`AclDelta`（含合并/add/del）放在 `src/state.rs`（随 `Policies` 一起序列化）。
- `src/main.rs`：声明 `mod acl;`。
- `src/dataplane/tcp.rs` / `quic.rs`：去掉 egress 形参、读全局；接入域名拦截判断 + 日志/计数。
- `src/dataplane/forward.rs`：`resolve_dst` 改为从全局取 egress（或调用处加载后传入）。
- `src/state.rs`：`Policies` 增 `domain_acl` / `egress_acl: AclDelta`（`#[serde(default)]`）。
- `src/api/handlers.rs` / `mod.rs`：新增 `/v1/domains` 与 `/v1/egress` 路由与共用处理。
- `src/main.rs`：启动时解析 `[domain]`/`[egress]` 基层、初始化两个全局过滤器；监听器不再传 egress。
- `deploy/examples/config.toml`、`README.md`：补 `[domain]` 段与 ACL API 文档。

## 13. 假设（请评审确认）

1. IP 与域名两套 ACL **完全对称**：都改 model B、都加运行时 API（add/del 增量持久化）。
2. 动态 add/del 增量存 `policies.json`，`config.toml` 只读不回写。
3. 不支持 `regexp:`；不做 IDN 转换。
