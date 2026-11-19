# 配置指令兼容表

解析器支持 Nginx 的注释、单/双引号、转义、块、`;`、`include`（含 glob）和循环 include 检测。错误信息包含文件与行号，并指出指令所属模块。

指令由各模块注册；注册表同时记录允许的上下文（`Main`、`Events`、`Http`、`Server`、`Location`、`Upstream`）。在错误上下文使用会报 `directive is not allowed here`，未知指令报 `unknown directive`，均不会被静默忽略。

## 核心（`ngx_http_core_module`）

| 上下文 | 指令 |
|---|---|
| main | `worker_processes`、`pid <file>`；`user`/`error_log`/`daemon`/`master_process`/`worker_rlimit_nofile` 接受并给出兼容性警告（由 Pingora 进程管理） |
| events | `worker_connections`/`multi_accept`/`use` 仅做语法兼容，事件循环由 Pingora 管理 |
| main | `http { ... }` |
| http | `server`、`upstream`、`types`、`default_type` |
| server | `listen address[:port] [default_server] [ssl] [http2] [reuseport]`、`server_name`、`location` |
| location | `location`（不支持嵌套） |

## 模块指令

| 模块 | 指令 | 上下文 |
|---|---|---|
| realip | `set_real_ip_from addr\|cidr\|hostname\|unix:`、`real_ip_header X-Real-IP\|X-Forwarded-For\|proxy_protocol\|name`、`real_ip_recursive on\|off` | http、server、location（可继承） |
| access | `allow`、`deny`（`all`、CIDR、单 IP、`unix:`），按顺序首个匹配生效 | http、server、location |
| limit_req | `limit_req_zone <key> zone=NAME:SIZE rate=Nr/s\|Nr/m`、`limit_req zone=NAME [burst=N] [delay=N\|nodelay]`、`limit_req_status code`、`limit_req_dry_run on\|off` | zone 在 http；其余 http/server/location |
| limit_conn | `limit_conn_zone <key> zone=NAME:SIZE`、`limit_conn zone_name number`、`limit_conn_status code`、`limit_conn_dry_run on\|off` | zone 在 http；其余 http/server/location |
| stub_status | `stub_status`（Nginx 三行格式） | server、location |
| metrics（扩展） | `prometheus_metrics`（Prometheus 文本格式） | server、location |
| ssl | `ssl_certificate`、`ssl_certificate_key`、`ssl_protocols`（`ssl_verify_client`/`ssl_ciphers`/`ssl_session_*` 明确拒绝） | server |
| rewrite | `rewrite regex replacement [last\|break\|redirect\|permanent]`、`return status [text\|url]` | http、server、location |
| static | `root`、`index`、`try_files`、`autoindex` | http、server、location |
| proxy | `proxy_pass`、`proxy_set_header`、`proxy_hide_header`、`proxy_connect_timeout`、`proxy_read_timeout`、`proxy_send_timeout`、`proxy_next_upstream_tries` | http、server、location |
| upstream | `server address [weight=N] [down]`、`least_conn`、`ip_hash`、`random`、`health_check interval=...`（扩展） | upstream 块内 |
| headers | `add_header name value [always]` | http、server、location |
| log | `log_format name string`、`access_log path\|off [format]` | http |
| lua | `access_by_lua_block/file`、`rewrite_by_lua_block/file`、`content_by_lua_block/file`、`header_filter_by_lua_block/file` | http、server、location |
| body | `client_max_body_size` | http、server、location |

## 变量

内置：`$uri`、`$document_uri`、`$request_uri`、`$args`/`$query_string`、`$is_args`、`$host`、`$http_host`、`$request_method`、`$scheme`、`$https`、`$server_name`、`$server_addr`、`$server_port`、`$hostname`、`$remote_addr`、`$remote_port`、`$binary_remote_addr`、`$request`、`$request_time`、`$msec`、`$status`、`$body_bytes_sent`、`$upstream_addr`、`$server_protocol`、`$http_<header>`。

模块变量：

- realip：`$realip_remote_addr`、`$realip_remote_port`
- limit_req：`$limit_req_status`（`PASSED`/`DELAYED`/`REJECTED`/`DELAYED_DRY_RUN`/`REJECTED_DRY_RUN`）
- limit_conn：`$limit_conn_status`（`PASSED`/`REJECTED`/`REJECTED_DRY_RUN`）
- stub_status：`$connections_active`、`$connections_reading`、`$connections_writing`、`$connections_waiting`

rewrite 替换串支持正则捕获组 `$1`…；其余变量展开后按模板求值。未设置的变量展开为空字符串。

## 阶段顺序（与 Nginx 对齐）

`POST_READ`(realip) → `FIND_CONFIG`(server/location) → `REWRITE`(rewrite/return) →
`PREACCESS`(limit_conn、limit_req) → `ACCESS`(allow/deny、access_by_lua) →
`CONTENT`(return 输出、stub_status、content_by_lua、proxy_pass、静态文件) → 响应头过滤(add_header、Lua header filter) → 日志。

`return` 在 rewrite 阶段只记录动作，文本在 content 阶段求值，因此 `return 200 "$limit_req_status"` 能看到限流结果。

## 继承与匹配

- `root/index/autoindex/try_files`、代理设置、`add_header`、Lua 钩子、rewrite 规则、realip 与 access 规则可从 `http` 继承到 `server`、`location`；子级声明会覆盖父级。
- location 顺序：精确匹配 `=` → 最长前缀；若最长前缀带 `^~` 则停止 → 按声明顺序匹配正则 → 使用最长前缀。
- `rewrite ... last` 重新选择 location，最多 10 次以防止内部跳转循环；`break` 保留在当前 location。`redirect`/`permanent` 生成 302/301，并在替换目标不含 `?` 时保留原始查询串。
- `add_header` 仅对 `200 201 204 206 301 302 303 304 307 308` 生效，`always` 时对所有响应生效。
- `limit_req` 使用泄漏桶：每次请求计入 1000 毫请求，按 `rate` 随时间排空；超过 `burst` 拒绝，超过 `delay` 延迟 `(excess-delay)/rate` 毫秒；`nodelay` 只拒绝不延迟。
- `limit_conn` 按 key 统计在途请求，请求结束（含代理完成）才释放槽位。

## 运维

- `nginxrs -c <conf> -t`：语法、Lua、上游与 TLS 证书校验。
- `nginxrs -c <conf> -s reload`：重新加载配置（失败则保留旧配置）；Unix 上也可 `kill -HUP`。
- `nginxrs -c <conf> -s stop`：停止。
- pid 文件由 `pid` 指令指定，控制端点地址写在 `<pidfile>.ctl`。

## 明确拒绝

未列出的指令会报错，不会被当作配置成功。特别是 `alias`、`if`、`proxy_cache`、`ssl_verify_client`、`ssl_ciphers`、`ssl_session_*`、`log_format ... escape=`、`upstream keepalive*` 目前不支持。
