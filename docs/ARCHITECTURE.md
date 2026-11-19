# 架构说明

本文说明 nginxrs 如何按 Nginx 的模块模型组织代码，以及如何新增一个模块。目标：**新增 Nginx 模块只新增文件，不改 HTTP 核心的阶段顺序和路由逻辑**。

## 分层

```
main.rs ──► config.rs ──► core/http_core.rs（请求引擎）
                │                    │
                │                    ├─► modules/registry.rs（指令归属表）
                │                    └─► modules/<module>.rs（阶段处理器）
                └─► modules/http_core.rs（HttpCompiler：把指令树编译成 HttpConfig）
```

| 层 | 职责 | 不应该做的事 |
|---|---|---|
| `main.rs` | 读取配置、启动 Pingora、开启上游健康检查后台服务、打开访问日志 | 解析指令 |
| `config.rs` | 组织状态槽，调用编译器，把结果交给运行时 | 了解具体模块类型 |
| `core/syntax.rs` | 把文件变成 `Directive` 树（含 `include`、注释、引号、转义） | 判断指令含义 |
| `core/value.rs` | 共享值解析（`1m30s`、`10k`、地址） | 模块语义 |
| `core/http.rs` | `RequestState`：连接、请求行、头部、类型化槽位 | 模块特定字段 |
| `core/variables.rs` | `$var` 模板与变量注册表 | 业务逻辑 |
| `core/state.rs` | 模块状态的类型化存储 | 具体状态类型 |
| `core/http_core.rs` | 阶段顺序：realip → 路由 → rewrite → access → content → 响应头过滤 → 日志 | 模块配置细节 |
| `modules/*.rs` | 指令解析、配置类型、处理器、变量 | 修改核心阶段 |

## Nginx 概念对照

| Nginx | nginxrs |
|---|---|
| `ngx_command_t` 指令表 | `Module::directives() -> Vec<DirectiveSpec>` |
| `NGX_HTTP_LOC_CONF` 等上下文标志 | `DirectiveSpec.contexts: &[Context]` |
| `loc_conf` 数组 | `modules/location.rs` 中的 `Location`（`TypeId → Arc<dyn Any>`） |
| `ngx_http_merge_locations` | `Location::inherit_from`，由 `LocationConf::inherit()` 决定是否继承 |
| `ngx_http_phases` | `core/http_core.rs::request_filter` 中的顺序调用 |
| `ngx_http_module_t` 变量 | `Module::variables()` + `core/variables.rs` |
| `ngx_core_conf_t`（`worker_processes` 等） | 注册表里的 `main` 状态槽 |

## 新增模块清单

以 `ngx_http_realip_module` 为例：

1. **新建文件** `src/modules/<name>.rs`，实现 `core::Module`：
   ```rust
   impl Module for RealipModule {
       fn name(&self) -> &'static str { "ngx_http_realip_module" }
       fn kind(&self) -> ModuleKind { ModuleKind::Http }
       fn directives(&self) -> Vec<DirectiveSpec> { /* 名称 + 上下文 + 处理函数 */ }
       fn variables(&self) -> Vec<(&'static str, &'static dyn VariableProvider)> { /* 可选 */ }
   }
   ```
2. **配置类型**：为 location/server 配置定义一个实现 `LocationConf` 的结构体；需要从 `http`/`server` 继承就保持默认 `inherit() == true`。
3. **处理函数**：在 `DirectiveView` 上解析参数，用 `view.update_conf::<T>(...)` 写入 location 配置，或在需要进程级状态时用 `view.state::<T>()` 读写本模块自己的状态槽（`Module::http_state()` 提供）。
4. **注册**：在 `src/modules/mod.rs` 增加 `pub mod <name>;`，并在 `Registry::default_modules()` 中加一行。
5. **请求处理**：若模块参与请求生命周期，在 `core/http_core.rs` 的相应阶段调用其纯函数（realip 在路由前；rewrite 在 rewrite 阶段；content 模块在 content 阶段；响应头模块在响应过滤链）。
6. **测试**：模块内单元测试覆盖解析与语义；如涉及网络行为，在 `tests/end_to_end.rs` 增加真实进程测试。

## 阶段顺序（与 Nginx 对齐）

| 阶段 | 当前模块 |
|---|---|
| `POST_READ` | `realip`：在任何模块观察 `$remote_addr` 之前改写 |
| `FIND_CONFIG` | `http_core`：`server_name` 与 `location` 选择 |
| `REWRITE` | `rewrite`：`rewrite` 规则、`last` 重新选 location、`return` |
| `PREACCESS` | `limit_conn`、`limit_req` |
| `ACCESS` | `access`（allow/deny）、`lua` 的 `access_by_lua_*` |
| `CONTENT` | `lua` 内容处理器、`proxy`、`static` |
| 响应头过滤 | `headers`（`add_header`）、`proxy_hide_header`、Lua header filter |
| 状态端点 | `stub_status`、`prometheus_metrics` 在 content 阶段直接应答 |
| `LOG` | `log`（combined 格式） |

## 已知限制

- 模块状态通过 `StateAccess` 以模块名查找；`main`/`events` 上下文的指令统一落在 `main` 槽位。
- `Location` 中继承的值使用 `Arc` 共享，写入前会写时复制（`get_mut`），与 Nginx 的 `loc_conf` 复制语义一致。
- 不支持嵌套 `location`；`alias`、`if`、`ssl_verify_client` 等尚未实现，遇到会明确报错而非静默忽略。
- 限流与连接计数保存在进程内 `Mutex<HashMap>`，单进程语义正确；多 worker 进程共享需接入 Pingora 共享内存。
- 重载通过 `ArcSwap` 替换引擎：在途请求使用旧快照，新请求立即看到新配置。

## 已实现模块

| Nginx 模块 | 文件 |
|---|---|
| `ngx_http_core_module` | `http_core.rs` |
| `ngx_http_rewrite_module` | `rewrite.rs` |
| `ngx_http_realip_module` | `realip.rs` |
| `ngx_http_access_module` | `access.rs` |
| `ngx_http_limit_req_module` | `limit_req.rs` |
| `ngx_http_limit_conn_module` | `limit_conn.rs` |
| `ngx_http_stub_status_module` + Prometheus | `stub_status.rs` |
| `ngx_http_ssl_module`（下游 TLS） | `ssl.rs` |
| `ngx_http_headers_module` | `headers.rs` |
| `ngx_http_log_module` | `log.rs` |
| `ngx_http_proxy_module` | `proxy.rs` |
| `ngx_http_upstream_module` | `upstream.rs` |
| 后端选择 | `balancer.rs` |
| `ngx_http_static_module` | `static_files.rs` + `static_files/file.rs` |
| `ngx_http_lua_module` | `lua.rs` |
| 请求体限制 | `body.rs` |
| 配置重载 | `core/reload.rs` |

每个模块实现前先阅读 `c/nginx/src/http/modules` 下的对应 C 源文件，核对指令表、合并规则与请求阶段；
差异会记录在提交说明与 `docs/DIRECTIVES.md` 中。
