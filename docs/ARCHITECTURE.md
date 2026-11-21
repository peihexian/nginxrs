# 架构说明

本文说明 nginxrs 如何按 Nginx 的模块模型组织代码，以及如何新增一个模块。目标：**新增 Nginx 模块只新增文件，不改 HTTP 核心的阶段顺序和路由逻辑**；**一个模块内部再按职责拆目录，避免单文件上千行**。

## 分层

```
main.rs ──► config.rs ──► core/http_core.rs（请求引擎）
                │                    │
                │                    ├─► modules/registry.rs（指令归属表）
                │                    └─► modules/<module>.rs 或 modules/<module>/*.rs（阶段处理器）
                └─► modules/http_core.rs（HttpCompiler：把指令树编译成 HttpConfig）
```

| 层 | 职责 | 不应该做的事 |
|---|---|---|
| `main.rs` | 读取配置、启动 Pingora、开启上游健康检查后台服务、打开访问日志 | 解析指令 |
| `config.rs` | 组织状态槽，调用编译器，把结果交给运行时 | 了解具体模块类型 |
| `core/syntax.rs` | 把文件变成 `Directive` 树（含 `include`、注释、引号、转义） | 判断指令含义 |
| `core/value.rs` | 共享值解析（`1m30s`、`10k`、地址） | 模块语义 |
| `core/bytes.rs` | 字节级字符串工具（`ngx_escape_html`、`ngx_escape_uri`） | 业务逻辑 |
| `core/crypt.rs` | `ngx_crypt`：`$apr1$`/`{PLAIN}`/`{SHA}`/`{SSHA}` | 认证流程 |
| `core/limits.rs` | 由核心指令得到的请求时限（`client_header_timeout` 等） | 读取配置 |
| `core/http.rs` | `RequestState`：连接、请求行、头部、类型化槽位、`set` 变量 | 模块特定字段 |
| `core/variables.rs` | `$var` 模板、变量注册表、`set` 覆盖值 | 业务逻辑 |
| `core/state.rs` | 模块状态的类型化存储 | 具体状态类型 |
| `core/http_core.rs` | 阶段顺序：realip → 路由 → rewrite → preaccess → access（auth_basic）→ content → 响应头过滤 → 日志 | 模块配置细节 |
| `modules/*` | 指令解析、配置类型、处理器、变量 | 修改核心阶段 |

## Nginx 概念对照

| Nginx | nginxrs |
|---|---|
| `ngx_command_t` 指令表 | `Module::directives() -> Vec<DirectiveSpec>`（同名指令可分别声明互不重叠的上下文） |
| `NGX_HTTP_LOC_CONF` 等上下文标志 | `DirectiveSpec.contexts: &[Context]` |
| `loc_conf` 数组 | `modules/location.rs` 中的 `Location`（`TypeId → Arc<dyn Any>`） |
| `ngx_http_merge_locations` | `Location::inherit_from`，由 `LocationConf::inherit()` 决定是否继承；`http {}` 与 `server {}` 各自作为一个父级 |
| `ngx_http_phases` | `core/http_core/route.rs::route_request` 中的顺序调用 |
| `ngx_http_script_if_code`（`if` 块） | `modules/rewrite/condition.rs` 的 `Action::If` 列表 |
| `ngx_http_module_t` 变量 | `Module::variables()` + `core/variables.rs` |
| `ngx_core_conf_t`（`worker_processes` 等） | 注册表里的 `main` 状态槽 |

## 模块目录拆分

行数增长较大的模块按 nginx 的职责边界拆成目录，对外仍是一个 `Module`：

| 模块 | 目录与文件 | 职责 |
|---|---|---|
| rewrite | `modules/rewrite/mod.rs` | 指令、`rewrite`/`return` 解析、阶段处理器 |
| | `modules/rewrite/condition.rs` | `if` 条件、`set`、`break` 与求值 |
| upstream | `modules/upstream/mod.rs` | `upstream` 块、`server` 行、负载均衡选择 |
| | `modules/upstream/options.rs` | `keepalive*`、`max_fails`/`fail_timeout` |
| static | `modules/static_files.rs` | `root`/`alias`/`index`/`try_files`/`autoindex` |
| | `modules/static_files/file.rs` | URI→路径映射、Range、SSI 分支、自动索引 |
| core 配置 | `modules/core_conf.rs` | `server_tokens`、缓冲、超时、`max_ranges`、哈希调优 |
| headers | `modules/headers.rs` | `add_header`、`add_header_inherit` |
| | `modules/expires.rs` | `expires`（`ngx_http_set_expires`） |
| ssi | `modules/filters/ssi/conf.rs` | 指令与命令表 |
| | `modules/filters/ssi/parser.rs` | `<!--#…-->` 词法器（`ngx_http_ssi_parse` 的移植） |
| | `modules/filters/ssi/expr/` | 值展开、`if` 表达式、`timefmt` |
| | `modules/filters/ssi/filter.rs` | 渲染器与命令处理器 |
| | `modules/filters/ssi/include.rs` | `include` 解析（按 location 的 `root`/`alias`） |
| 上游协议 | `modules/upstream_protocols.rs` | `fastcgi_*`/`uwsgi_*`/`scgi_*` 的接受与校验 |
| gzip | `modules/gzip/conf.rs` | `gzip*` 指令与合并规则 |
| | `modules/gzip/negotiate.rs` | `ngx_http_gzip_ok`（版本、`gzip_disable`、`Via`、`Accept-Encoding`） |
| | `modules/gzip/filter.rs` | 判定、压缩（flate2）、响应头改写、`$gzip_ratio` |
| gunzip | `modules/gunzip/` | `gunzip`/`gunzip_buffers` 与 inflate |
| gzip_static | `modules/gzip_static.rs` | `.gz` 兄弟文件的内容处理器 |
| 编码链 | `modules/filters/encode.rs` | 统一 `gunzip` → `gzip` 的响应体变换 |
| grpc | `modules/grpc/conf.rs` | `grpc_*` 指令（复用 `proxy` 的 upstream/TLS 配置） |
| | `modules/grpc/request.rs` | `ngx_http_grpc_create_request`（伪首部与字段过滤） |
| | `modules/grpc/response.rs` | `:status`、隐藏头、trailers |
| | `modules/grpc/client.rs` | `h2` 客户端传输 |
| | `core/http_core/grpc.rs` | `ngx_http_grpc_handler` 与重试 |
| geo | `modules/geo/mod.rs` | 指令、变量、请求期地址选择（`ngx_http_geo_addr`） |
| | `modules/geo/conf.rs` | 编译结果 `GeoBlock` 与值表（`ngx_http_geo_variable_value_node_t` 的去重） |
| | `modules/geo/lookup.rs` | 双 radix 树与 65536 桶区间表（`ngx_radix_tree_t`、`ngx_http_geo_range_t`） |
| | `modules/geo/parser.rs` | 块解析器（`ngx_http_geo`/`ngx_http_geo_cidr`/`ngx_http_geo_range`/`geo_include`） |
| | `core/geo.rs` | `ngx_ptocidr` 与 `ngx_http_get_forwarded_addr`（`geo` 与 `geoip` 共用） |
| geoip | `modules/geoip/mod.rs` | 指令、16 个变量、`MMDB_lookup_sockaddr` 的地址选择 |
| | `modules/geoip/conf.rs` | 数据库集合与字段路径表、alpha-2→alpha-3 |
| | `modules/geoip/mmdb.rs` | MaxMind DB 只读解析器（搜索树 + 数据段 + metadata） |

## 新增模块清单

以 `ngx_http_auth_basic_module` 为例：

1. **新建文件** `src/modules/auth_basic.rs`（或目录），实现 `core::Module`：
   ```rust
   impl Module for AuthBasicModule {
       fn name(&self) -> &'static str { "ngx_http_auth_basic_module" }
       fn kind(&self) -> ModuleKind { ModuleKind::Http }
       fn directives(&self) -> Vec<DirectiveSpec> { /* 名称 + 上下文 + 处理函数 */ }
       fn variables(&self) -> Vec<(&'static str, &'static dyn VariableProvider)> { /* 可选 */ }
   }
   ```
2. **配置类型**：为 location/server 配置定义一个实现 `LocationConf` 的结构体；需要从 `http`/`server` 继承就保持默认 `inherit() == true`。
3. **处理函数**：在 `DirectiveView` 上解析参数，用 `view.update_conf::<T>(...)` 写入 location 配置，或用 `view.state::<T>()` / `view.process_state()` 读写状态槽。
4. **注册**：在 `src/modules/mod.rs` 增加 `pub mod <name>;`，并在 `Registry::default_modules()` 中加一行。
5. **请求处理**：若模块参与请求生命周期，在 `core/http_core/` 的相应阶段调用其纯函数。
6. **测试**：模块内单元测试覆盖解析与语义；涉及网络行为时在 `tests/<领域>/` 增加真实进程测试，并在 `Cargo.toml` 声明 `[[test]]`。

## 阶段顺序（与 Nginx 对齐）

| 阶段 | 当前模块 |
|---|---|
| `POST_READ` | `realip`：在任何模块观察 `$remote_addr` 之前改写 |
| `FIND_CONFIG` | `http_core`：`server_name` 与 `location` 选择 |
| `REWRITE` | `rewrite`：`if`/`set`/`break` 动作、`rewrite` 规则、`return` |
| `PREACCESS` | `limit_conn`、`limit_req` |
| `ACCESS` | `auth_basic`、`access`（allow/deny）、`lua` 的 `access_by_lua_*` |
| `CONTENT` | `lua` 内容处理器、`proxy`、`static`（含 SSI 过滤） |
| 响应头过滤 | `expires` + `add_header`、`proxy_hide_header`、Lua header filter |
| 状态端点 | `stub_status`、`prometheus_metrics` 在 content 阶段直接应答 |
| `LOG` | `log`（combined 格式） |

## 响应头的生成

- `Server`：`ngx_http_header_filter` 为每个响应生成，值由所选 location 的 `server_tokens` 决定（`core/http_core/types.rs::server_header`）。
- `expires` 先于 `add_header` 执行，因此 location 自己写的 `Cache-Control` 覆盖 `expires` 生成的值——与 `ngx_http_headers_filter` 的顺序一致。

## 已知限制

- 模块状态通过 `StateAccess` 以模块名查找；`main`/`events` 上下文的指令统一落在 `main` 槽位。
- `Location` 中继承的值使用 `Arc` 共享，写入前会写时复制（`get_mut`），与 Nginx 的 `loc_conf` 复制语义一致。
- 嵌套 `location` 在编译期展平：每个子块是一个独立条目，父配置全部完成后作为它的继承父级。
- 限流与连接计数保存在进程内 `Mutex<HashMap>`，单进程语义正确；多 worker 进程共享需接入 Pingora 共享内存。
- 重载通过 `ArcSwap` 替换引擎：在途请求使用旧快照，新请求立即看到新配置。
- Pingora 只为 `ProxyHttp` 实现下游 `ServerApp`，所以 TLS 终止放在 `core/http_core/bridge.rs::Bridge`：
  `Bridge::process_new` 先握手（SNI 选 `server {}`，得到 `$ssl_*` 事实），再与普通监听共用
  `ngx_http_wait_request_handler`/`keepalive` 会话循环调用 `HttpCoreApp::route_request`。
- `proxy_pass` 的上游交换由 `HttpCoreApp::proxy_pass` 直接驱动 pingora 的 HTTP/1 客户端会话。
- 响应缓冲由 `modules/proxy_buffer.rs::ResponseBuffer` 实现 `ngx_event_pipe` 的决策。
- 缓存由 `modules/proxy_cache.rs` 承载；条目是按键 MD5 与 `levels` 分级的磁盘文件。
- SSI 在完整缓冲的 body 上一次性渲染（nginx 是流式过滤器）；`include` 通过 `IncludeResolver` 读取目标文件，不经过子请求管线的重写与变量重算。
- `fastcgi_*`/`uwsgi_*`/`scgi_*` 只解析不执行。
- `geo`/`geoip` 的变量在编译期注册（`geo` 是每个块一个变量），因此通过 `modules::dynamic_providers()` 与编译后的变量表提供给请求状态；`geoip` 的数据库在编译后发布，`RequestState::apply_published_modules` 在状态重建时补回。
- `geo` 的 `include` 直接按块规则解析文件；nginx 还会优先尝试 `name.bin` 二进制基址，本实现不支持该二进制格式。
- `geoip` 只实现 MaxMind DB（`.mmdb`）；旧版 `GeoIP.dat` 格式不支持，配置时按 `invalid GeoIP database` 报错。

## 下游 TLS 与会话循环

```text
accept ─► Bridge::process_new
            │
            ├─ listen ... ssl? ─► core/tls.rs::accept（LazyConfigAcceptor + SNI → ServerConfig）
            │                       └─ SslSession：协议、套件、SNI、client 证书链、复用状态
            │
            └─ HTTP/1.x ─► Session::new_h1 ─► read_request
                                                │
                                                └─ HttpCoreApp::route_request
                                                     POST_READ → FIND_CONFIG → REWRITE
                                                     → PREACCESS → ACCESS → CONTENT
                                                     ├─ Answered：响应已写出
                                                     └─ Proxy：HttpCoreApp::proxy_pass
```

## 已实现模块

| Nginx 模块 | 文件 |
|---|---|
| `ngx_http_core_module` | `http_core.rs` + `core_conf.rs` |
| `ngx_http_rewrite_module` | `rewrite/`（`mod.rs`、`condition.rs`） |
| `ngx_http_realip_module` | `realip.rs` |
| `ngx_http_access_module` | `access.rs` |
| `ngx_http_auth_basic_module` | `auth_basic.rs`（+ `core/crypt.rs`） |
| `ngx_http_limit_req_module` / `ngx_http_limit_conn_module` | `limit_req.rs`、`limit_conn.rs` |
| `ngx_http_stub_status_module` + Prometheus | `stub_status.rs` |
| `ngx_http_ssl_module`（下游 TLS） | `ssl/` |
| `ngx_http_headers_module` | `headers.rs` + `expires.rs` |
| `ngx_http_ssi_filter_module` | `filters/ssi/` |
| `ngx_http_log_module` | `log.rs` |
| `ngx_http_proxy_module` | `proxy.rs` + `proxy_rewrite.rs` + `proxy_buffer.rs` + `proxy_cache.rs` + `proxy_tls.rs` |
| `ngx_http_upstream_module` | `upstream/` |
| 后端选择 | `balancer.rs` |
| `ngx_http_static_module`（`root`/`alias`/`try_files`/`index`/`autoindex`） | `static_files.rs` + `static_files/file.rs` |
| `ngx_http_gzip_filter_module` | `gzip/` |
| `ngx_http_gunzip_filter_module` | `gunzip/` |
| `ngx_http_gzip_static_module` | `gzip_static.rs` |
| `ngx_http_grpc_module` | `grpc/` + `core/http_core/grpc.rs` |
| `ngx_http_geo_module` | `geo/`（`mod.rs`、`conf.rs`、`lookup.rs`、`parser.rs`） |
| `ngx_http_geoip_module` | `geoip/`（`mod.rs`、`conf.rs`、`mmdb.rs`） |
| `ngx_http_fastcgi/uwsgi/scgi_module`（仅配置） | `upstream_protocols.rs` |
| `ngx_http_lua_module` | `lua.rs` |
| 请求体限制 | `body.rs` |
| 配置重载 | `core/reload.rs` |
| 进程级控制面 | `core/runner/` |

每个模块实现前先阅读 `c/nginx/src/http/modules` 下的对应 C 源文件，核对指令表、合并规则与请求阶段；
差异会记录在提交说明与 `docs/DIRECTIVES.md` 中。生产配置的校验方法与缺口分析见
`docs/COMPAT_GAPS.md`。
