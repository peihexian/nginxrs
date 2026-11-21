# 配置指令兼容表

解析器支持 Nginx 的注释、单/双引号、转义、块、`;`、`include`（含 glob）和循环 include 检测。错误信息包含文件与行号，并指出指令所属模块。

指令由各模块注册；注册表同时记录允许的上下文（`Main`、`Events`、`Http`、`Server`、`Location`、`Upstream`）。在错误上下文使用会报 `directive is not allowed here`，未知指令报 `unknown directive`，均不会被静默忽略。同一模块可对**互不重叠**的上下文重复声明一条指令（`error_log` 同时存在于 `main` 与 `http`/`server`/`location`），注册表会合并上下文表。

## 核心（`ngx_http_core_module`）

| 上下文 | 指令 |
|---|---|
| main | `worker_processes`、`pid <file>`；`user`/`daemon`/`master_process`/`worker_rlimit_nofile` 接受并给出兼容性警告（由 Pingora 进程管理）；`error_log` 在各上下文均接受（统一走进程日志） |
| events | `worker_connections`/`multi_accept`/`use` 仅做语法兼容，事件循环由 Pingora 管理 |
| main | `http { ... }` |
| http | `server`、`upstream`、`types`、`default_type` |
| server | `listen address[:port] [default_server] [ssl] [http2] [reuseport]`、`server_name`、`location` |
| server/location | `location`（含嵌套，展平后按 nginx 顺序查找） |

### 核心 loc/srv 配置（`modules/core_conf.rs`）

| 指令 | 行为 |
|---|---|
| `server_tokens on\|off\|build` | 控制 `Server` 头：`off` → `nginx`，`on` → `nginxrs/<ver>`，`build` → 带构建类型 |
| `keepalive_timeout [time [header_time]]`、`keepalive_requests N` | 下游连接保活与请求上限 |
| `client_header_timeout`、`client_body_timeout`、`send_timeout`、`client_body_buffer_size`、`client_header_buffer_size`、`large_client_header_buffers`、`max_headers`、`connection_pool_size`、`request_pool_size` | 解析、校验并进入 `RequestLimits`；缓冲区选项按 nginx 规则校验 |
| `sendfile on\|off`、`sendfile_max_chunk`、`tcp_nopush`、`tcp_nodelay`、`postpone_output`、`socket_keepalive` | 传输调优，语法与取值校验 |
| `max_ranges 0\|N` | `0` 关闭 Range；超过 `N` 段的 `Range` 被忽略 |
| `server_names_hash_bucket_size`、`server_names_hash_max_size`、`types_hash_max_size`、`types_hash_bucket_size` | 哈希调优，仅校验 |
| `underscores_in_headers on\|off`、`ignore_invalid_headers`、`merge_slashes` | 请求头/URI 解析开关（记录并在 `-t` 校验） |
| `reset_timedout_connection`、`absolute_redirect`、`server_name_in_redirect`、`port_in_redirect`、`etag` | 接受并校验 |

## 模块指令

| 模块 | 指令 | 上下文 |
|---|---|---|
| realip | `set_real_ip_from addr\|cidr\|hostname\|unix:`、`real_ip_header X-Real-IP\|X-Forwarded-For\|proxy_protocol\|name`（同一块内后写生效，与 `ngx_conf_merge_ptr_value` 一致）、`real_ip_recursive on\|off` | http、server、location（可继承） |
| access | `allow`、`deny`（`all`、CIDR、单 IP、`unix:`），按顺序首个匹配生效 | http、server、location |
| auth_basic | `auth_basic realm\|off`（支持变量）、`auth_basic_user_file path`（支持变量，相对路径按配置目录解析） | http、server、location |
| limit_req | `limit_req_zone <key> zone=NAME:SIZE rate=Nr/s\|Nr/m`、`limit_req zone=NAME [burst=N] [delay=N\|nodelay]`、`limit_req_status code`、`limit_req_dry_run on\|off` | zone 在 http；其余 http/server/location |
| limit_conn | `limit_conn_zone <key> zone=NAME:SIZE`、`limit_conn zone_name number`、`limit_conn_status code`、`limit_conn_dry_run on\|off` | zone 在 http；其余 http/server/location |
| stub_status | `stub_status`（Nginx 三行格式） | server、location |
| metrics（扩展） | `prometheus_metrics`（Prometheus 文本格式） | server、location |
| ssl | `ssl_certificate [name:path ...]`、`ssl_certificate_key [name:path ...]`、`ssl_password_file`、`ssl_dhparam`、`ssl_protocols`、`ssl_ciphers`、`ssl_buffer_size`、`ssl_verify_client off\|on\|optional\|optional_no_ca`、`ssl_verify_depth`、`ssl_client_certificate`、`ssl_trusted_certificate`、`ssl_prefer_server_ciphers`、`ssl_session_cache off\|none\|builtin\|shared:NAME:SIZE`、`ssl_session_tickets on\|off`、`ssl_session_ticket_key`、`ssl_session_timeout`、`ssl_crl`、`ssl_early_data on\|off`、`ssl_ecdh_curve`、`ssl_reject_handshake on\|off`；OCSP：`ssl_stapling`、`ssl_ocsp on\|leaf`、`ssl_ocsp_cache`、`ssl_stapling_file`、`ssl_stapling_responder`、`ssl_ocsp_responder`、`ssl_stapling_verify` | server（`ssl_verify_depth` 也接受 http） |
| rewrite | `rewrite regex replacement [last\|break\|redirect\|permanent]`（无 flag 且目标是 `http(s)://`/`$scheme` 时按 302 处理）、`return status [text\|url]`、`if (condition) { … }`、`set $var value`、`break`、`rewrite_log`、`uninitialized_variable_warn` | http、server、location |
| static | `root`、`alias`（前缀 location 替换前缀，正则 location 拼接整个 URI）、`index`、`try_files`、`autoindex` | http、server、location |
| proxy | 上游与 TLS：`proxy_pass`、`proxy_ssl_protocols`、`proxy_ssl_ciphers`、`proxy_ssl_server_name`、`proxy_ssl_name`、`proxy_ssl_verify`、`proxy_ssl_verify_depth`、`proxy_ssl_trusted_certificate`、`proxy_ssl_crl`、`proxy_ssl_certificate`、`proxy_ssl_certificate_key`、`proxy_ssl_session_reuse`；请求构造：`proxy_set_header`、`proxy_pass_request_headers`、`proxy_pass_request_body`、`proxy_method`、`proxy_set_body`、`proxy_http_version`；响应处理：`proxy_hide_header`、`proxy_pass_header`、`proxy_ignore_headers`、`proxy_redirect off\|default\|on\|pattern [replacement]`、`proxy_cookie_domain`、`proxy_cookie_path`、`proxy_cookie_flags`、`proxy_intercept_errors`；缓冲：`proxy_buffering`、`proxy_buffers`、`proxy_buffer_size`、`proxy_busy_buffers_size`、`proxy_max_temp_file_size`、`proxy_temp_path`、`proxy_temp_file_write_size`；超时与重试：`proxy_connect_timeout`、`proxy_read_timeout`、`proxy_send_timeout`、`proxy_next_upstream error\|timeout\|invalid_header\|http_500\|http_502\|http_503\|http_504\|http_403\|http_404\|http_429\|non_idempotent\|off`（默认 `error timeout`）、`proxy_next_upstream_tries`、`proxy_next_upstream_timeout`；缓存：`proxy_cache_path`（http）、`proxy_cache`、`proxy_cache_key`、`proxy_cache_valid`、`proxy_cache_bypass`、`proxy_no_cache`、`proxy_cache_methods`、`proxy_cache_min_uses`、`proxy_cache_use_stale`、`proxy_cache_revalidate`、`proxy_cache_background_update`、`proxy_cache_lock`；其他：`proxy_limit_rate`、`proxy_store`、`proxy_store_access` | http、server、location |
| upstream | `server address [weight=N] [max_fails=N] [fail_timeout=T] [down]`、`least_conn`、`ip_hash`、`random`、`keepalive N`、`keepalive_requests M`、`keepalive_timeout T`、`health_check interval=...`（扩展） | upstream 块内 |
| headers | `add_header name value [always]`、`add_header_inherit off\|on\|merge`、`expires [modified] time\|epoch\|max\|off\|@time` | http、server、location |
| geo | `geo $var [$source]` 块：`default value`、`network value`、`delete network`、`ranges`、`start-end value`、`delete start-end`、`include file`、`proxy addr\|CIDR`、`proxy_recursive`、`volatile` | 仅 http |`n| geoip | `geoip_country file [utf8]`、`geoip_city file [utf8]`、`geoip_org file [utf8]`、`geoip_proxy addr\|CIDR`、`geoip_proxy_recursive on\|off` | 仅 http |`n| ssi | `ssi on\|off`、`ssi_silent_errors`、`ssi_ignore_recycled_buffers`、`ssi_min_file_chunk`、`ssi_value_length`、`ssi_types` | http、server、location |
| geoip | `geoip_country file [utf8]`、`geoip_city file [utf8]`、`geoip_org file [utf8]`、`geoip_proxy addr\|CIDR`、`geoip_proxy_recursive on\|off`（MaxMind DB `.mmdb`） | 仅 http |
| gzip | `gzip on\|off`、`gzip_buffers number size`、`gzip_comp_level 1..9`、`gzip_disable regex ...`、`gzip_hash size`、`gzip_http_version 1.0\|1.1`、`gzip_min_length size`、`gzip_no_buffer on\|off`、`gzip_proxied off\|expired\|no-cache\|no-store\|private\|no_last_modified\|no_etag\|auth\|any`、`gzip_types mime-type ...`、`gzip_vary on\|off`、`gzip_window size`、`postpone_gzipping size` | http、server、location |
| gunzip | `gunzip on\|off`、`gunzip_buffers number size` | http、server、location |
| gzip_static | `gzip_static on\|off\|always` | http、server、location |
| grpc | `grpc_pass grpc://host:port` \| `grpcs://host:port` \| `upstream` 名（仅 location）、`grpc_connect_timeout`、`grpc_send_timeout`、`grpc_read_timeout`、`grpc_buffer_size`、`grpc_next_upstream`、`grpc_next_upstream_tries`、`grpc_next_upstream_timeout`、`grpc_set_header`、`grpc_pass_header`、`grpc_hide_header`、`grpc_intercept_errors`、`grpc_bind`、`grpc_socket_keepalive`、`grpc_socket_rcvbuf`、`grpc_socket_sndbuf`、`grpc_ssl_protocols`、`grpc_ssl_ciphers`、`grpc_ssl_server_name`、`grpc_ssl_name`、`grpc_ssl_verify`、`grpc_ssl_verify_depth`、`grpc_ssl_trusted_certificate`、`grpc_ssl_crl`、`grpc_ssl_certificate`、`grpc_ssl_certificate_key`、`grpc_ssl_certificate_cache`、`grpc_ssl_password_file`、`grpc_ssl_session_reuse` | http、server、location |
| log | `log_format name string`、`access_log path\|off [format]` | http、server、location |
| lua | `access_by_lua_block/file`、`rewrite_by_lua_block/file`、`content_by_lua_block/file`、`header_filter_by_lua_block/file` | http、server、location |
| body | `client_max_body_size` | http、server、location |
| fastcgi/uwsgi/scgi | 三个协议的常用指令（`*_pass`、`*_read_timeout`、`*_buffer_size`、`*_param`、`*_hide_header` …）解析并校验参数 | http、server、location |

### `if` 条件（`modules/rewrite/condition.rs`）

支持 nginx 的全部分支形式：

| 形式 | 语义 |
|---|---|
| `if ($var)` | 值非空且不为 `"0"` |
| `if ($a = value)` / `!=` | 字面比较；两侧都能解析为整数时按数值比较（`$a = 0` 对空 `$a` 成立） |
| `if ($a ~ re)` / `~*` / `!~` / `!~*` | 正则匹配，正则捕获写入 `$1`…`$9` |
| `if (-f\|!-f\|-d\|!-d\|-e\|!-e\|-x\|!-x file)` | 文件测试 |

块内支持 `rewrite`、`return`、`set`、`break` 与嵌套 `if`。其他指令（如 `proxy_pass`）在 nginx 中位于 `LIF_CONF`，这里接受但记一条告警，不会静默改变代理目标。

## `ssi` 支持的指令标签

`include virtual="…" [file=] [wait=] [set=] [stub=]`、`echo var="…" [default=] [encoding=none|url|entity]`、`config errmsg= timefmt=`、`set var= value=`、`if/elif/else/endif expr=`、`block name=` / `endblock`。`$date_local`/`$date_gmt` 使用当前 `timefmt`。静态文件与代理响应都会过滤（`ssi on` 且内容类型在 `ssi_types` 内）。

## 变量

内置：`$uri`、`$document_uri`、`$request_uri`、`$args`/`$query_string`、`$is_args`、`$host`、`$http_host`、`$request_method`、`$scheme`、`$https`、`$server_name`、`$server_addr`、`$server_port`、`$hostname`、`$remote_addr`、`$remote_port`、`$binary_remote_addr`、`$request`、`$request_time`、`$msec`、`$status`、`$body_bytes_sent`、`$upstream_addr`、`$server_protocol`、`$http_<header>`。

`set $x value` 写入的变量优先于内置与模块变量（`ngx_http_get_indexed_variable` 的索引槽语义）。

## 与 nginx 的已知差异

- `large_client_header_buffers` 等缓冲开关只做校验并进入 `RequestLimits`：请求行读取由 Pingora 完成。
- `underscores_in_headers on` 被接受；Pingora 的头部解析器对非法字符的处理与 nginx 不同，`-t` 会提示。
- 多段 `Range` 请求不生成 `multipart/byteranges`，按 nginx 允许的方式退化为忽略 `Range`（单段 `Range` 正常返回 `206`）。
- `gzip`/`gunzip` 在完整 body 上一次性压缩/解压（nginx 是流式 zlib 过滤器）；判定条件、响应头变化、`$gzip_ratio`、`Vary`、`ETag` 弱化与 nginx 一致。`gzip_window`/`gzip_hash`/`postpone_gzipping`/`gzip_no_buffer` 按 nginx 规则校验并记录，实际压缩使用 flate2。
- `gzip_static` 作为内容处理器在静态文件之前尝试 `.gz` 兄弟文件；`on` 只对接受 gzip 的客户端生效并设置 `Vary`，`always` 无条件返回。
- `grpc_pass` 用 `h2` crate 说 HTTP/2（明文 prior-knowledge 或 `grpcs` TLS）。`grpc_ssl_certificate_cache` 只校验参数（证书在配置期一次性加载），`grpc_ssl_conf_command` 不支持（rustls 无对应接口）。trailers 在响应头中合并返回（`grpc-status`/`grpc-message`），因为下游是 HTTP/1.1。

### `geo` / `geoip` 变量

`geo` 每个块注册一个变量（`ngx_http_geo_block` 中的 `ngx_http_add_variable`）：纯网络条目走双radix树（最长前缀），`ranges` 模式走 65536 桶区间表（首个命中区间，未命中取 `default`）。`$source` 形式（`geo $tag $http_x_tag`）改用该变量的地址；`proxy`/`proxy_recursive` 与 `realip` 相同地从右向左遍历 `X-Forwarded-For`。`volatile` 标记变量不可缓存。

`geoip` 提供 nginx 的全部 16 个变量：`$geoip_country_code`、`$geoip_country_code3`、`$geoip_country_name`、`$geoip_city_continent_code`、`$geoip_city_country_code`、`$geoip_city_country_code3`、`$geoip_city_country_name`、`$geoip_region`、`$geoip_region_name`、`$geoip_city`、`$geoip_postal_code`、`$geoip_latitude`、`$geoip_longitude`、`$geoip_city_metro_code`、`$geoip_area_code`、`$geoip_org`。字段路径与 C 模块的 `ngx_http_geoip_*_paths` 一致；alpha-2 → alpha-3 用同一张 `ngx_http_geoip_country_codes` 表；坐标按 `ngx_http_geoip_float` 校验 ±180 度。
- `expires modified` 在响应没有 `Last-Modified` 时按访问时间计算（同 `ngx_http_set_expires`）。
- `fastcgi_*`/`uwsgi_*`/`scgi_*` 只解析不执行：参数与类型校验与 nginx 一致，但没有对应上游协议实现，因此这些 `*_pass` 目标不会真正被访问；`-t` 通过时按告警提示。

## 明确拒绝

未列出的指令会报错，不会被当作配置成功。目前仍不支持的包括 `updating` 重试条件、`ssl_certificate_cache`、`ssl_conf_command`、`ssl_ech_file`、`log_format ... escape=`、`ssl_certificate_compression`。
