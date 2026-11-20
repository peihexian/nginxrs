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
| ssl | `ssl_certificate [name:path ...]`、`ssl_certificate_key [name:path ...]`、`ssl_password_file`、`ssl_dhparam`、`ssl_protocols`、`ssl_ciphers`、`ssl_buffer_size`、`ssl_verify_client off\|on\|optional\|optional_no_ca`、`ssl_verify_depth`、`ssl_client_certificate`、`ssl_trusted_certificate`、`ssl_prefer_server_ciphers`、`ssl_session_cache off\|none\|builtin\|shared:NAME:SIZE`、`ssl_session_tickets on\|off`、`ssl_session_ticket_key`、`ssl_session_timeout`、`ssl_crl`、`ssl_early_data on\|off`、`ssl_ecdh_curve`、`ssl_reject_handshake on\|off`；OCSP：`ssl_stapling`、`ssl_ocsp on\|leaf`、`ssl_ocsp_cache`、`ssl_stapling_file`、`ssl_stapling_responder`、`ssl_ocsp_responder`、`ssl_stapling_verify` | server（`ssl_verify_depth` 也接受 http） |
| rewrite | `rewrite regex replacement [last\|break\|redirect\|permanent]`、`return status [text\|url]` | http、server、location |
| static | `root`、`index`、`try_files`、`autoindex` | http、server、location |
| proxy | 上游与 TLS：`proxy_pass`、`proxy_ssl_protocols`、`proxy_ssl_ciphers`、`proxy_ssl_server_name`、`proxy_ssl_name`、`proxy_ssl_verify`、`proxy_ssl_verify_depth`、`proxy_ssl_trusted_certificate`、`proxy_ssl_crl`、`proxy_ssl_certificate`、`proxy_ssl_certificate_key`、`proxy_ssl_session_reuse`；请求构造：`proxy_set_header`、`proxy_pass_request_headers`、`proxy_pass_request_body`、`proxy_method`、`proxy_set_body`、`proxy_http_version`；响应处理：`proxy_hide_header`、`proxy_pass_header`、`proxy_ignore_headers`、`proxy_redirect off\|default\|on\|pattern [replacement]`、`proxy_cookie_domain`、`proxy_cookie_path`、`proxy_cookie_flags`、`proxy_intercept_errors`；缓冲：`proxy_buffering`、`proxy_buffers`、`proxy_buffer_size`、`proxy_busy_buffers_size`、`proxy_max_temp_file_size`、`proxy_temp_path`；超时与重试：`proxy_connect_timeout`、`proxy_read_timeout`、`proxy_send_timeout`、`proxy_next_upstream error|timeout|invalid_header|http_500|http_502|http_503|http_504|http_403|http_404|http_429|non_idempotent|off`（默认 `error timeout`）、`proxy_next_upstream_tries`、`proxy_next_upstream_timeout`；缓存：`proxy_cache_path`（http）、`proxy_cache`、`proxy_cache_key`、`proxy_cache_valid`、`proxy_cache_bypass`、`proxy_no_cache`、`proxy_cache_methods`、`proxy_cache_min_uses`、`proxy_cache_use_stale`、`proxy_cache_revalidate`、`proxy_cache_background_update`、`proxy_cache_lock`；其他：`proxy_limit_rate`、`proxy_store`、`proxy_store_access` | http、server、location |
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
- ssl（对齐 `ngx_http_ssl_variable`）：`$ssl_protocol`、`$ssl_cipher`、`$ssl_ciphers`、`$ssl_curve`、`$ssl_curves`、`$ssl_sigalg`、`$ssl_sigalgs`、`$ssl_session_id`、`$ssl_session_reused`（复用为 `r`，否则 `.`）、`$ssl_early_data`、`$ssl_server_name`、`$ssl_alpn_protocol`、`$ssl_client_cert`（PEM，续行缩进）、`$ssl_client_raw_cert`、`$ssl_client_escaped_cert`、`$ssl_client_s_dn`、`$ssl_client_i_dn`、`$ssl_client_s_dn_legacy`、`$ssl_client_i_dn_legacy`、`$ssl_client_serial`、`$ssl_client_fingerprint`、`$ssl_client_verify`（`SUCCESS`/`FAILED`/`NONE`）、`$ssl_client_v_start`、`$ssl_client_v_end`、`$ssl_client_v_remain`、`$ssl_client_sigalg`

rewrite 替换串支持正则捕获组 `$1`…；其余变量展开后按模板求值。未设置的变量展开为空字符串。

## 阶段顺序（与 Nginx 对齐）

`POST_READ`(realip) → `FIND_CONFIG`(server/location) → `REWRITE`(rewrite/return) →
`PREACCESS`(limit_conn、limit_req) → `ACCESS`(allow/deny、access_by_lua) →
`CONTENT`(return 输出、stub_status、content_by_lua、proxy_pass、静态文件) → 响应头过滤(add_header、Lua header filter) → 日志。

TLS 握手在 HTTP 解析之前完成，相当于 `ngx_http_ssl_servername` + `ngx_http_ssl_handshake_handler`：
SNI 选择 `server {}`，并据此产生 `$ssl_*` 变量；普通监听与 `listen ... ssl` 监听共用同一条
`ngx_http_wait_request_handler`/`ngx_http_keepalive_handler` 会话循环。

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
- `nginxrs -c <conf> -s stop`：向控制端点发送 `stop` 后进程退出并清理 pid/控制描述符。
- pid 文件由 `pid` 指令指定，控制端点地址写在 `<pidfile>.ctl`。

`listen` 与 `upstream` 的 `server` 都接受主机名：按 `ngx_inet_resolve_host` 用
`getaddrinfo` 解析后取第一个地址，解析失败是配置错误。

`listen ... http2` 通过 ALPN 通告 `h2`；客户端选择 `h2` 后由 HTTP/2 会话循环按流处理，
升级/keepalive 语义由 Pingora 的连接循环提供。

## 缓存

`proxy_cache_path path [levels=1:2] [keys_zone=NAME:SIZE] [inactive=time] [max_size=size] [use_temp_path=on|off]`
定义缓存域（http 上下文），`proxy_cache zone|off` 启用；新鲜度依次取 `X-Accel-Expires`、
`Cache-Control: max-age`、`Expires`，最后落到 `proxy_cache_valid`（`X-Accel-Expires: 0`、
`no-cache`/`no-store`/`private` 视为不可缓存；带 `Set-Cookie` 的响应同样不可缓存，除非用 `proxy_ignore_headers Set-Cookie` 放行——与 `ngx_http_upstream_process_set_cookie` 一致）。缓存文件按 key 的
MD5 与 `levels` 分级存放（`ngx_http_file_cache_name`），`$upstream_cache_status` 给出
`MISS`/`HIT`/`BYPASS` 等状态。`proxy_cache_key` 默认 `$scheme$proxy_host$request_uri`。

## ssl 行为说明

- `ssl_reject_handshake on`：该 `server` 可以没有 `ssl_certificate`，握手阶段直接以
  `unrecognized_name` 拒绝（`ngx_http_ssl_servername` 的 `handshake_rejected` 分支）。
- `ssl_stapling on` 配合 `ssl_stapling_file` 时把文件中的 OCSP 响应（DER 或 PEM）作为 stapling
  附在叶子证书上（`ngx_ssl_stapling_file` → `CertifiedKey::ocsp`）；未提供文件而配置了
  `ssl_stapling_responder` 时，会在配置加载阶段向该 responder 发送 `application/ocsp-request`
  的 HTTP POST 并保存返回的 `application/ocsp-response`（`ngx_ssl_stapling_responder`）。
  `ssl_stapling_verify on` 时会按 `ngx_ssl_stapling_verify` 的顺序校验响应：状态必须为
  `successful`、`CertID` 必须匹配被服务的证书（且签发者一致）、`thisUpdate`/`nextUpdate`
  必须有效，`revoked` 直接报错；`ssl_ocsp`（client 证书的 OCSP 校验）仍未实现。
- `ssl_early_data on` 打开 rustls 的 0-RTT 上限，`$ssl_early_data` 取自握手信息。

## 明确拒绝

未列出的指令会报错，不会被当作配置成功。目前仍不支持的包括 `alias`、`if` 作为条件块、
`updating` 重试条件、`ssl_certificate_cache`、`ssl_conf_command`、`ssl_ech_file`、
`log_format ... escape=`、`upstream keepalive*`。

`proxy_buffering on`（默认）按 `ngx_event_pipe` 的语义工作：响应先进入 `proxy_buffers * proxy_buffer_size`
的内存缓冲，缓冲用尽且临时文件还有空间（`proxy_temp_path` 下的文件不超过
`proxy_max_temp_file_size`）时转存临时文件，客户端侧一次最多积压 `proxy_busy_buffers_size`；
`proxy_buffering off` 逐块转发。`proxy_limit_rate` 限制发往客户端的速率。
`proxy_store`/`proxy_store_access` 仍会解析并校验，但不会落盘（缓存域尚未实现）。


