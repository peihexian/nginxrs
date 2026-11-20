# nginxrs

基于 **Cloudflare Pingora 0.9.1** 的 Rust HTTP 服务器。它读取 Nginx 风格配置，提供静态文件、反向代理、URL 重写、虚拟主机和负载均衡，并集成 Lua 5.4 钩子与 `ngx_http_realip_module` 的客户端地址还原。

> 这是一个可运行的 MVP，不是 Nginx 的逐指令替代品。未知或未实现的指令会在启动/`-t` 检查时报错，不会被静默忽略。

## 架构

代码按 Nginx 的“核心 + 模块”方式分层，新增模块不需要修改 HTTP 核心：

```text
src/
├── main.rs                 进程启动、Pingora 服务与上游后台任务
├── config.rs               把指令树编译为 HttpConfig + 各模块状态
├── core/                   与具体模块无关的基础设施
│   ├── syntax.rs           Nginx 配置词法/语法与 include
│   ├── value.rs            time/size/address 等共享值解析
│   ├── http.rs             RequestState：连接、请求事实与模块类型化槽位
│   ├── variables.rs        $var 模板求值与变量注册表
│   ├── state.rs            模块状态的类型化存储（StateAccess）
│   ├── http_core.rs        请求引擎：阶段顺序 + Pingora 适配
│   └── runner/             进程级服务/控制面
└── modules/                每个文件对应一个 Nginx 模块
    ├── registry.rs         指令归属表（ngx_command_t 等价物）
    ├── location.rs         每个 location/server 的模块配置（loc_conf）
    ├── http_core.rs         server/listen/server_name/location/types
    ├── realip.rs            ngx_http_realip_module
    ├── rewrite.rs           ngx_http_rewrite_module
    ├── proxy.rs             ngx_http_proxy_module
    ├── upstream.rs          ngx_http_upstream_module
    ├── balancer.rs          后端选择（Pingora LoadBalancer）
    ├── static_files/        ngx_http_static_module
    ├── headers.rs           ngx_http_headers_module
    ├── log.rs               ngx_http_log_module
    └── lua.rs               Lua 钩子
```

关键约定：

- **指令归属唯一**：每个指令只属于一个模块，注册表同时记录允许的上下文（`Main/Events/Http/Server/Location/Upstream`），未知指令与错误上下文都会在 `-t` 阶段报出文件与行号。
- **配置与字典分离**：模块把配置写进 `Location`（类型化 `loc_conf`），核心只按阶段顺序调用，不引用具体模块类型。
- **变量可扩展**：模块通过 `Module::variables()` 注册变量（如 `realip_remote_addr`），模板 `$var` 统一求值。
- **新增模块步骤**：实现 `core::Module` → 在 `modules/mod.rs` 增加一行 → 在 `Registry::default_modules()` 注册 → 若涉及请求处理，在 `core/http_core.rs` 对应阶段调用。详见 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)。

## 已实现

- **静态文件**：`root`、`index`、`try_files`、`autoindex`、`types`/`default_type`、GET/HEAD、ETag、Last-Modified、304、单区间 Range。
- **反向代理**（对齐 `ngx_http_proxy_module`）：HTTP/HTTPS 上游、直连 `proxy_pass http://IP:PORT` 与命名 upstream、
  请求体与响应体流式转发、超时、连接失败与幂等请求重试；请求构造 `proxy_set_header`/`proxy_method`/`proxy_set_body`/
  `proxy_pass_request_headers`/`proxy_pass_request_body`/`proxy_http_version`；响应处理 `proxy_hide_header`/`proxy_pass_header`/
  `proxy_ignore_headers`/`proxy_intercept_errors`；响应改写 `proxy_redirect`（含 `default` 语义）/
  `proxy_cookie_domain`/`proxy_cookie_path`/`proxy_cookie_flags`；缓冲与临时文件、`proxy_limit_rate`、`proxy_store` 参数；  `proxy_cache` 响应缓存（`proxy_cache_path`/`proxy_cache_valid`/`proxy_cache_key`/`proxy_cache_bypass` 与 `$upstream_cache_status`）。
- **URL 重写**：正则捕获组、变量、`last`、`break`、`redirect`、`permanent`（保留原始查询串）；`return` 在 content 阶段求值，可读取限流变量。
- **负载均衡**：加权 RoundRobin（默认）、`random`、`ip_hash`、`least_conn`，支持权重、禁用节点和 TCP 主动健康检查。
- **realip**（对齐 C 版）：`set_real_ip_from` 支持单 IP、CIDR、主机名（配置期解析）与 `unix:`；`real_ip_header` 支持 `X-Real-IP`、`X-Forwarded-For`、自定义头与 `proxy_protocol`；`real_ip_recursive` 按 `ngx_http_get_forwarded_addr` 逐跳信任链回溯；端口仅在头部显式携带时改写；重复 `real_ip_header` 报错。
- **访问控制**：`allow`/`deny`，支持 `all`、CIDR、单 IP、`unix:`，按声明顺序首个匹配，IPv4-mapped IPv6 对端按 IPv4 规则匹配。
- **限流**：`limit_req`（泄漏桶、`burst`、`delay`、`nodelay`、`dry_run`、自定义状态码）与 `limit_conn`（并发连接，请求结束才释放）；提供 `$limit_req_status`、`$limit_conn_status`。
- **可观测性**：`stub_status`（Nginx 原格式）与 `prometheus_metrics`（`nginxrs_*` 指标）。
- **配置重载**：`nginxrs -s reload` 原子替换路由表，校验失败则保留旧配置；Unix 支持 `SIGHUP`。
- **下游 TLS**：`listen ... ssl` + 完整 `ngx_http_ssl_module`（多证书 SNI、client 证书验证、
  会话缓存/票据、密码套件、`$ssl_*` 变量）；TLS 在 HTTP 解析前完成，与 Nginx 的握手回调一致。
- **反向代理 TLS**：`proxy_pass https://` 支持 `proxy_ssl_verify`、`proxy_ssl_trusted_certificate`、
  `proxy_ssl_name`/`proxy_ssl_server_name`、`proxy_ssl_protocols`/`proxy_ssl_ciphers`。
- **Lua**：`access_by_lua_*`、`rewrite_by_lua_*`、`content_by_lua_*`、`header_filter_by_lua_*`，见下文 API。
- **流媒体分发**：HLS (`.m3u8/.ts`)、DASH (`.mpd/.m4s`)、MP4 等文件的 MIME、流式分块与 Range；反代路径默认按
  `proxy_buffering` 走事件管道缓冲（内存 + `proxy_temp_path` 临时文件），可用 `proxy_buffering off` 改成逐块转发。
- **运维**：`-t` 配置检查、Nginx combined 风格访问日志、Rust/env_logger 运行日志。

## 构建与运行

需要 Rust **1.88+**。默认启用纯 Rust 的 `rustls` 上游 TLS 支持和内嵌 Lua，无需系统 Lua。

```powershell
cargo build --release

# 校验示例配置（也检查 Lua 语法和上游地址）
cargo run -- -c conf/nginxrs.conf -t

# 启动，默认监听 127.0.0.1:8080 或 0.0.0.0:8080，取决于 listen 配置
cargo run -- -c conf/nginxrs.conf

# 直接运行产物
.\target\release\nginxrs.exe -c conf\nginxrs.conf
```

Linux/macOS 使用相同 Cargo 命令，产物为 `target/release/nginxrs`。

示例站点：

- `http://localhost:8080/`：静态首页。
- `http://localhost:8080/health`：`return` 响应。
- `http://localhost:8080/lua`：Lua 内容处理器。
- `http://localhost:8080/api/`：转发到示例中的 `127.0.0.1:9001/9002`；需自行启动后端。
- `/legacy/...` 会 301 到 `/media/...`。

相对路径以**主配置文件所在目录**为基准。例如 `conf/nginxrs.conf` 中的 `root ../www` 指向项目根目录的 `www`。

## 示例配置

```nginx
worker_processes auto;
events { worker_connections 1024; }

http {
    include mime.types;
    access_log ../logs/access.log combined;

    upstream backend {
        least_conn;                 # 也可省略（round_robin）或使用 ip_hash/random
        server 127.0.0.1:9001 weight=2;
        server 127.0.0.1:9002 weight=1;
        server 127.0.0.1:9003 down;
        health_check interval=2s;  # nginxrs 扩展：Pingora TCP 健康检查
    }

    server {
        listen 8080 default_server;
        server_name localhost *.example.test;
        root ../www;
        index index.html;

        # 仅当直连对端属于下列受信代理时才信任转发头
        set_real_ip_from 127.0.0.1;
        set_real_ip_from 10.0.0.0/8;
        real_ip_header X-Forwarded-For;
        real_ip_recursive on;

        location = /health {
            return 200 "ok\n";
        }

        location = /client {
            content_by_lua_block "ngx.say(ngx.var.remote_addr .. ' ' .. ngx.var.realip_remote_addr)";
        }

        location /api/ {
            rewrite ^/api/(.*)$ /v1/$1 last;
            proxy_pass http://backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_connect_timeout 2s;
            proxy_read_timeout 60s;
            proxy_send_timeout 60s;
            proxy_next_upstream_tries 2;
            proxy_hide_header X-Powered-By;
        }

        location /media/ {
            add_header Cache-Control "public, max-age=60" always;
            try_files $uri =404;
        }

        location / {
            try_files $uri $uri/ =404;
        }
    }
}
```

`proxy_pass http://backend/base/` 会将匹配到的 location 前缀替换为 `/base/`；不带 URI 的 `proxy_pass http://backend` 保留重写后的路径。上游使用 HTTPS 时写 `proxy_pass https://backend`；`proxy_ssl_verify` 与 Nginx 一样默认 `off`，需要校验时显式开启并给出 `proxy_ssl_trusted_certificate`。

响应改写的语义与 C 版一致：

```nginx
location /app/ {
    proxy_pass http://backend/;

    # 默认规则：把上游自身的地址改写成客户端看到的地址（等价于 proxy_pass 的 URL 前缀）
    proxy_redirect default;

    # 显式规则：左侧可为字面前缀或 ~ 正则，右侧可含变量
    proxy_redirect http://backend.internal/ /app/;
    proxy_redirect ~^http://([^/]+)(/.*)$ http://$host$2;

    # Cookie 属性改写
    proxy_cookie_domain backend.local example.com;
    proxy_cookie_path /proxy/ /app/;
    proxy_cookie_flags sid secure samesite=strict;   # 也支持 nosecure/nohttponly/samesite=off

    # 上游响应头的取舍
    proxy_hide_header X-Powered-By;
    proxy_pass_header X-Accel-Expires;
}
```

## realip

行为与 `ngx_http_realip_module` 一致：

1. 只有当前 `$remote_addr`（即 TCP 对端）命中任一 `set_real_ip_from` 条目时，才会读取转发头；否则原始地址保持不变，避免客户端伪造。
2. `real_ip_header` 默认 `X-Real-IP`，也支持 `X-Forwarded-For` 或任意头部名；值可带端口，支持 `1.2.3.4:port`、`[::1]:port` 与裸 IPv6。
3. `real_ip_recursive off`（默认）取头部的第一个地址；`on` 时从最靠近代理的一端反向遍历，跳过受信地址，取第一个非受信地址作为客户端地址。
4. `$remote_addr`/`$remote_port` 被改写，原值始终保留在 `$realip_remote_addr`/`$realip_remote_port`；`proxy_set_header X-Real-IP $remote_addr` 与访问日志都会使用改写后的地址。

```nginx
server {
    set_real_ip_from 10.0.0.0/8;
    set_real_ip_from 2001:db8::/32;
    real_ip_header X-Forwarded-For;
    real_ip_recursive on;
    location / { proxy_pass http://backend; proxy_set_header X-Real-IP $remote_addr; }
}
```

## Lua

```nginx
location = /lua {
    access_by_lua_block "ngx.req.set_header('X-Checked', 'yes')";
    header_filter_by_lua_block "ngx.header['X-Lua'] = 'yes'";
    content_by_lua_block "ngx.status=200; ngx.say('hello ', ngx.var.uri)";
}
```

也支持对应的 `*_by_lua_file path.lua`。当前提供的兼容 API：

| API | 用途 |
|---|---|
| `ngx.var.uri/request_uri/host/remote_addr/args/scheme` | 请求变量 |
| `ngx.req.get_uri()` / `set_uri()` | 读取或内部重写 URI |
| `ngx.req.get_method()` / `get_headers()` | 读取方法和请求头 |
| `ngx.req.set_header()` / `clear_header()` | 修改发往上游的请求头 |
| `ngx.header[...]` | 读取/添加响应头 |
| `ngx.status` | 设置响应状态 |
| `ngx.say()` / `ngx.print()` | 生成内容响应 |
| `ngx.exit(status)` / `ngx.redirect(uri, status)` | 终止处理或重定向 |
| `ngx.log()` | 写运行日志 |

每次请求使用独立 Lua 状态，不开放 OS/process 库。Lua 配置属于受信任的服务端代码；当前没有执行指令数沙箱，请勿让脚本包含死循环。这与 OpenResty 的完整 API 并不等价，不支持 cosocket、共享字典或子请求。

## 限流、访问控制与指标

```nginx
http {
    limit_req_zone  $binary_remote_addr zone=req:10m rate=10r/s;
    limit_conn_zone $binary_remote_addr zone=conn:10m;

    server {
        listen 8080;
        limit_req_status 429;
        limit_conn_status 429;

        location = /status  { stub_status; }          # Nginx 三行格式
        location = /metrics { prometheus_metrics; }    # Prometheus 文本格式

        location = /admin/ {
            allow 10.0.0.0/8;
            deny all;
            proxy_pass http://backend;
        }

        location /api/ {
            limit_req zone=req burst=20 nodelay;   # 突发 20，只拒绝不延迟
            limit_conn conn 32;                    # 每客户端最多 32 个并发请求
            return 200 "status=$limit_req_status\n";
        }
    }
}
```

`limit_req` 采用与 Nginx 相同的泄漏桶：每次请求计入 1000 毫请求，按 `rate` 随时间线性排空；
超过 `burst` 返回 `limit_req_status`，超过 `delay` 则延迟 `(excess-delay)/rate` 毫秒，`nodelay` 永不延迟。

## TLS 与配置重载

```nginx
pid nginxrs.pid;          # -s reload / -s stop 使用该 pid 文件

http {
    server {
        listen 8443 ssl;
        ssl_certificate     certs/server.crt;
        ssl_certificate_key certs/server.key;
        ssl_protocols       TLSv1.2 TLSv1.3;
        location / { return 200 "secure\n"; }
    }
}
```

```powershell
nginxrs -c conf/nginxrs.conf -s reload   # 原子重载；配置有误会报错并保留旧配置
nginxrs -c conf/nginxrs.conf -s stop      # 真正退出进程并清理 pid/控制描述符
```

Unix 上 `kill -HUP <pid>` 触发同样的重载。

`ngx_http_ssl_module` 已按 C 版语义实现：`ssl_certificate` 支持 `name:path` 多证书并按 SNI 以
hash → 通配符 → 正则 → `default` 的顺序选择（`ngx_ssl_certificate_cb`）；`ssl_verify_client` 的
`off`/`on`/`optional`/`optional_no_ca`、`ssl_verify_depth` 链长与 `ssl_client_certificate`/`ssl_crl`；
`ssl_session_cache`（`builtin`/`shared:NAME:SIZE`）与 `ssl_session_tickets`；`ssl_protocols`、
`ssl_ciphers`（OpenSSL 密码串语法，如 `HIGH:!aNULL:!MD5`）与 `ssl_ecdh_curve`；以及 `$ssl_*` 变量族。
`ssl_reject_handshake on` 允许该 `server` 不配置证书并以 `unrecognized_name` 拒绝握手；
`ssl_stapling on` 从 `ssl_stapling_file`（DER/PEM）取值，或在只配置 `ssl_stapling_responder`
时于配置加载阶段向 responder 拉取 OCSP 响应，再 stapling 到叶子证书。
`ssl_stapling_verify on` 会校验 responder 返回的响应（状态、`CertID` 匹配、`thisUpdate`/`nextUpdate`、
撤销状态），不合法时配置加载失败。受 rustls 限制无法真正生效的部分（TLS 1.0/1.1、`ssl_dhparam`、
`ssl_password_file`）会在 `-t` 时明确报告。

```nginx
server {
    listen 443 ssl default_server;
    ssl_certificate     a.example.com:cert/a.pem;    # name:path，按 SNI 选择
    ssl_certificate_key a.example.com:cert/a.key;
    ssl_certificate     default:cert/default.pem;
    ssl_certificate_key default:cert/default.key;
    ssl_verify_client   optional_no_ca;
    ssl_session_cache   shared:SSL:10m;
    add_header X-Client-Verify $ssl_client_verify always;
}

# 到上游的 TLS
location /api/ {
    proxy_pass              https://backend;
    proxy_ssl_server_name   on;
    proxy_ssl_verify        on;
    proxy_ssl_trusted_certificate certs/upstream-ca.pem;
}
```


## 测试

```powershell
cargo test --all-targets -- --test-threads=1
cargo clippy --all-targets -- -D warnings
```

集成测试会真实启动 nginxrs 与 TCP/慢速后端，覆盖：

- 静态文件、HEAD、Range、HLS MIME、重写与重定向；
- Lua 内容与响应头过滤器、`add_header` 链路；
- 两个上游都收到请求（负载均衡）；
- realip 改写 `$remote_addr`、保留 `$realip_remote_addr`、`proxy_set_header` 透传真实客户端、未配置受信网段时不改写；
- `allow`/`deny` 的 CIDR 匹配与 403；
- `limit_req` 超限返回 429 与 `$limit_req_status`；
- `limit_conn` 在首个请求未完成时拒绝并发请求；
- `stub_status` 与 Prometheus 输出格式；
- `-s reload` 生效、坏配置被拒绝且服务不中断；
- 自签证书下的真实 HTTPS 握手（无 openssl 时自动跳过）；
- `$ssl_protocol`/`$ssl_cipher`/`$ssl_server_name`/`$ssl_client_verify`/`$https` 反映握手的真实结果；
- 同一监听上的两个 TLS `server {}` 由 SNI 分别选中各自的证书（`ngx_http_ssl_servername`）；
- `proxy_set_header` 中的变量（`$host`、`$request_uri`、`$request_method`）在发往上游前求值，
  `proxy_pass http://backend/v1/` 按 Nginx 规则替换匹配前缀；
- `proxy_redirect default`/显式规则/`off` 三种行为，以及 `proxy_cookie_domain`/`proxy_cookie_path`/
  `proxy_cookie_flags` 对 `Set-Cookie` 的改写结果；
- `proxy_method`、`proxy_pass_request_body`、`proxy_set_body` 对上游请求的影响；
- `proxy_cache`：第二个请求命中缓存且上游只被访问一次、不同 `proxy_cache_key` 分开存储、
  `proxy_cache_bypass` 直连上游、无 `proxy_cache_valid` 且无过期头时不缓存、未知缓存域在 `-t` 时报错、
  带 `Set-Cookie` 的响应默认不缓存（`proxy_ignore_headers Set-Cookie` 可放行）；
- `ssl_reject_handshake`：未匹配的 `server_name` 握手失败，且该 `server` 无需证书即可通过 `-t`；
- `ssl_session_cache shared:...`：客户端复用会话时 `$ssl_session_reused` 报 `r`；
- `ssl_verify_client on` + `ssl_verify_depth`：受信 CA 签发的客户端证书得到 `SUCCESS`，
  未知 CA 签发的被拒绝；
- `ssl_stapling_responder`：配置加载阶段确实向 responder 发出 OCSP 请求；
- `ssl_stapling_verify on`：伪造的 OCSP 响应会让 `-t` 失败；
- `listen ... http2`：客户端只提供 `h2` 时 ALPN 协商成功且服务端以 SETTINGS 帧应答；
- `-s stop`：进程真正退出并关闭监听端口；`listen`/`upstream server` 接受主机名；
- `proxy_http_version` 默认 1.1、`proxy_buffers` 默认 8×pagesize 且至少 2 个缓冲区；
- 发往上游时清除 `Connection`/`Keep-Alive`/`TE`/`Upgrade`/`Expect`，默认补 `Connection: close`；
- `ssl_early_data on`：TLS 1.3 下客户端可尝试 0-RTT，`$ssl_early_data` 反映实际结果。
- `proxy_next_upstream`：`http_503` 触发重试并最终由健康节点应答、默认 `error timeout` 不对状态码重试、
  连接失败默认重试、`off` 关闭重试、`proxy_next_upstream_tries 1` 限制尝试次数、
  非幂等请求（`POST`）需要 `non_idempotent` 才会重试；
- `proxy_buffering`：超大响应经 `proxy_temp_path` 转存后完整送达、`proxy_buffering off` 逐块转发、
  `proxy_max_temp_file_size 0` 关闭转存仍不丢数据。

## 与官方 C 源码的对照

模块实现前会先阅读 `c/nginx/src/http/modules` 下的对应 C 文件，核对指令表、合并规则与请求阶段。
已据此修正的差异包括：`$binary_remote_addr` 缺失、直连 `proxy_pass` 未注册上游、
`return` 过早求值、`limit_conn` 槽位生命周期、realip 的端口与主机名语义、
`ssl_session_cache` 的容量换算（`size / 128`）、`ssl_verify_depth` 的 `+1` 链长语义、
`ssl_certificate` 的 SNI 选择顺序、`proxy_ssl_verify` 默认 `off`、
`proxy_redirect default` 的模式（`proxy_pass` 的 URL 前缀而不是已解析的上游地址）、
`proxy_pass http://host/` 在前缀完全匹配时仍然发送 `/`、
`proxy_next_upstream` 只在确实还能换一个节点时才把状态码当作上游失败（否则把上游的 500 原样返回给客户端）。

## 已知的运行时限制

- Pingora 的 `HttpProxy` 只对 `ProxyHttp` 实现 `ServerApp`，因此下游由 `core::http_core::Bridge`
  负责 TLS 终止与会话循环，`HttpCoreApp::route_request` 提供全部阶段；`proxy_pass` 由
  `HttpCoreApp::proxy_pass` 直接驱动上游 HTTP/1 会话。
- `proxy_request_buffering` 恒为 `on`（请求体先读完再连上游），没有临时文件落盘。

## 边界与后续路线

当前版本尚未实现：

- `alias`、`if`、命名 location、多区间 Range、完整变量集合。
- FastCGI/uWSGI/SCGI、gRPC 专用配置、缓存（Pingora Cache）、认证（`auth_basic`、`auth_request`）、动态模块。
- `ssl_verify_client`、`ssl_ciphers`、`ssl_session_*`、OCSP。
- RTMP 推流/拉流、转码、DRM。当前“流媒体”是 HLS/DASH/VOD 分发与流式反代，不是媒体处理服务器。

建议下一阶段：Pingora Cache 集成、`auth_basic`/`auth_request`、`map`/`geo` 变量、
以及把限流状态迁到 Pingora 共享内存以支持多进程。不要在同一个 HTTP 进程中临时堆叠转码任务；转码应交给独立 worker。
