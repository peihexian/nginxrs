# 生产配置兼容差距分析

本文记录「拿真实生产配置校验 nginxrs」的结论，以及为补齐差距所做的架构拆分。

## 校验方法

生产配置在 `test_conf/`（不入库、不改动）。校验时把整棵树复制到 `tmp_v/` 下，把
`include /etc/nginx/...` 里的绝对前缀改写成副本路径（Windows 上没有 `/etc`；Linux 上可直接
把副本挂到 `/etc/nginx`），再执行：

```powershell
target\debug\nginxrs.exe -c tmp_v/probe_full.conf -t
```

每次 `-t` 只报第一个错误，因此用脚本循环：解析 stderr 里的 `file:line: directive: message`，
注释掉该行后再跑，直到通过，得到完整的缺口清单。

> 真实域名、IP、证书路径与口令哈希一律不进入源码、测试或文档；`tests/config/production_shape.rs`
> 只保留**配置形态**（同样的指令混排），取值全部换成 `example.test`、`127.0.0.1` 之类的占位值。

## 结论

补齐后，生产配置整树 `-t` 通过（8 个 listener、135 个 server、308 个 location），
包括 `include` 出来的各地区 vhost、`if`/`set`、嵌套 `location`、SSI、`expires`、
上游 `keepalive`、`max_fails`/`fail_timeout` 等等。

## 指令缺口与落地

| 指令 | nginx 模块 | 补齐方式 |
|---|---|---|
| `server_tokens` | `ngx_http_core_module` | `modules/core_conf.rs::TokensConf` + 统一 `Server` 头生成（`core/http_core/types.rs::server_header`） |
| `sendfile` `sendfile_max_chunk` `tcp_nopush` `tcp_nodelay` `postpone_output` | 核心 | 语法与取值校验，记录传输策略 |
| `keepalive_timeout` `keepalive_requests` | 核心 | `CoreTimeouts` → `core/limits.rs::RequestLimits` |
| `client_header_buffer_size` `large_client_header_buffers` | 核心 | `ClientBuffers`，按 nginx 规则校验（≥2 个、≥8192） |
| `client_body_buffer_size` `client_body_timeout` `client_header_timeout` `send_timeout` `max_headers` `connection_pool_size` `request_pool_size` | 核心 | `CoreTimeouts`/校验 |
| `server_names_hash_bucket_size` `server_names_hash_max_size` `types_hash_max_size` `types_hash_bucket_size` | 核心 | `HashTuning`，仅校验 |
| `underscores_in_headers` `ignore_invalid_headers` `merge_slashes` | 核心 | `UnderscoresInHeaders` + 校验 |
| `max_ranges` | `ngx_http_range_filter_module` | `MaxRanges`，`0` 关闭 Range、超限忽略 `Range` |
| `ssi` `ssi_silent_errors`（及 `ssi_*` 调优） | `ngx_http_ssi_filter_module` | `modules/filters/ssi/`：词法器、表达式、`timefmt`、渲染器、include 解析 |
| `auth_basic` `auth_basic_user_file` | `ngx_http_auth_basic_module` | `modules/auth_basic.rs` + `core/crypt.rs`（`$apr1$`/`{PLAIN}`/`{SHA}`/`{SSHA}`） |
| `expires` | `ngx_http_headers_filter_module` | `modules/expires.rs`，由 `HeadersConf` 承载 |
| `add_header_inherit` | 同上 | `modules/headers.rs::Inherit` |
| `alias` | 核心 | `StaticConf.alias` + `MapMode::{Alias, AliasAll}`（`ngx_http_map_uri_to_path`） |
| 嵌套 `location` | 核心 | 编译期展平，子块以父配置为继承父级 |
| `if` `set` `break` | `ngx_http_rewrite_module` | `modules/rewrite/condition.rs`（条件与动作），任选 `rewrite`/`return`/`set`/`break` |
| `proxy_temp_file_write_size` | `ngx_http_proxy_module` | `ProxyConf.temp_file_write_size` |
| `upstream { keepalive N; keepalive_timeout; keepalive_requests }` | `ngx_http_upstream_keepalive_module` | `modules/upstream/options.rs::KeepaliveConfig` |
| `server … max_fails= fail_timeout=` | `ngx_http_upstream_module` | `modules/upstream/options.rs::PassiveHealth` |
| `geo` 块（含 `ranges`/`proxy`/`delete`/`include`） | `ngx_http_geo_module` | `modules/geo/`：radix 树 + 区间表 + 块解析器 |`n| `geoip_country` `geoip_city` `geoip_org` `geoip_proxy` | `ngx_http_geoip_module` | `modules/geoip/`：内置 MaxMind DB 读取器 |`n| `access_log` 在 server/location | `ngx_http_log_module` | 上下文放宽，按 location 记录目标 |
| `gzip` `gzip_types` `gzip_min_length` `gzip_vary` `gzip_static` 等 | `ngx_http_gzip_filter_module` / `ngx_http_gzip_static_module` | `modules/gzip/`、`gzip_static.rs`、`filters/encode.rs` |
| `gunzip` | `ngx_http_gunzip_filter_module` | `modules/gunzip/` |
| `grpc_pass` 及 `grpc_*` | `ngx_http_grpc_module` | `modules/grpc/` + `core/http_core/grpc.rs`（h2 crate） |
| `geoip_country` `geoip_city` `geoip_org` `geoip_proxy` `geoip_proxy_recursive` | `ngx_http_geoip_module` | `modules/geoip/`：内置 MaxMind DB 只读解析器，16 个变量 |
| `gzip` `gzip_types` `gzip_min_length` `gzip_vary` `gzip_static` 等 | `ngx_http_gzip_filter_module` / `ngx_http_gzip_static_module` | `modules/gzip/`、`gzip_static.rs`、`filters/encode.rs` |
| `gunzip` | `ngx_http_gunzip_filter_module` | `modules/gunzip/` |
| `grpc_pass` 及 `grpc_*` | `ngx_http_grpc_module` | `modules/grpc/` + `core/http_core/grpc.rs`（h2 crate） |
| `error_log` 在 http/server/location | 核心 | 接受，统一走进程日志并记告警 |
| `fastcgi_param` `uwsgi_*` `scgi_*` | 三个上游协议模块 | `modules/upstream_protocols.rs`：按 nginx 的 setter 校验参数，协议未实现，`-t` 通过但会在日志中说明 |

## 其它修正（由真实配置暴露）

- 注册表允许同一模块对**互不重叠**的上下文重复声明同名指令；重叠则启动即 panic。
- nginx 的 `$X` 语义差异：`ssl_ciphers` 中列举了运行时没有的套件（DHE/3DES/CBC）不会被当作错误
  （与 `SSL_CTX_set_cipher_list` 仅在整个列表为空时报错一致）。
- 同一块内重复 `real_ip_header` 后写生效（`ngx_conf_merge_ptr_value`），include 片段经常重复它。
- 未匹配任何套件的 `proxy_*`/`ssl_*` 选择器不再让配置加载失败。

## 架构原则

- 新增能力一律按 nginx 模块边界拆文件；`core/http_core/*` 只做阶段编排。
- 一个模块的指令、配置类型、运行时行为放在同一目录，目录内再按职责拆（`conf.rs`、
  `parser.rs`、`filter.rs`…），避免单文件上千行。
- 模块之间不互相 import 配置类型：共享结构放 `modules/core_conf.rs`（对应 nginx 的
  `clcf`），响应改写通过 `HeadersConf::apply` 等过滤器完成。
- `server_tokens`、`expires`、`add_header` 的顺序按 `ngx_http_headers_filter` 实际顺序实现
  （`expires` 先写，`add_header` 后写并覆盖）。
