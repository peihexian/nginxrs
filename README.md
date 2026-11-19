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
- **反向代理**：HTTP/HTTPS 上游、直连 `proxy_pass http://IP:PORT` 与命名 upstream、请求体与响应体流式转发、超时、请求/响应头修改、连接失败与幂等请求重试。
- **URL 重写**：正则捕获组、变量、`last`、`break`、`redirect`、`permanent`（保留原始查询串）；`return` 在 content 阶段求值，可读取限流变量。
- **负载均衡**：加权 RoundRobin（默认）、`random`、`ip_hash`、`least_conn`，支持权重、禁用节点和 TCP 主动健康检查。
- **realip**（对齐 C 版）：`set_real_ip_from` 支持单 IP、CIDR、主机名（配置期解析）与 `unix:`；`real_ip_header` 支持 `X-Real-IP`、`X-Forwarded-For`、自定义头与 `proxy_protocol`；`real_ip_recursive` 按 `ngx_http_get_forwarded_addr` 逐跳信任链回溯；端口仅在头部显式携带时改写；重复 `real_ip_header` 报错。
- **访问控制**：`allow`/`deny`，支持 `all`、CIDR、单 IP、`unix:`，按声明顺序首个匹配，IPv4-mapped IPv6 对端按 IPv4 规则匹配。
- **限流**：`limit_req`（泄漏桶、`burst`、`delay`、`nodelay`、`dry_run`、自定义状态码）与 `limit_conn`（并发连接，请求结束才释放）；提供 `$limit_req_status`、`$limit_conn_status`。
- **可观测性**：`stub_status`（Nginx 原格式）与 `prometheus_metrics`（`nginxrs_*` 指标）。
- **配置重载**：`nginxrs -s reload` 原子替换路由表，校验失败则保留旧配置；Unix 支持 `SIGHUP`。
- **下游 TLS**：`listen ... ssl` + `ssl_certificate`/`ssl_certificate_key`/`ssl_protocols`，基于 Pingora 的 rustls 监听，自动启用 HTTP/2 ALPN。
- **Lua**：`access_by_lua_*`、`rewrite_by_lua_*`、`content_by_lua_*`、`header_filter_by_lua_*`，见下文 API。
- **流媒体分发**：HLS (`.m3u8/.ts`)、DASH (`.mpd/.m4s`)、MP4 等文件的 MIME、流式分块与 Range；反代路径不缓冲整个上游响应。
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

`proxy_pass http://backend/base/` 会将匹配到的 location 前缀替换为 `/base/`；不带 URI 的 `proxy_pass http://backend` 保留重写后的路径。上游使用 HTTPS 时写 `proxy_pass https://backend`，默认校验证书和主机名。

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
nginxrs -c conf/nginxrs.conf -s stop
```

Unix 上 `kill -HUP <pid>` 触发同样的重载。`ssl_verify_client`、`ssl_ciphers`、`ssl_session_*`
尚未实现，配置时会明确报错。

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
- 自签证书下的真实 HTTPS 握手（无 openssl 时自动跳过）。

## 与官方 C 源码的对照

模块实现前会先阅读 `c/nginx/src/http/modules` 下的对应 C 文件，核对指令表、合并规则与请求阶段。
已据此修正的差异包括：`$binary_remote_addr` 缺失、直连 `proxy_pass` 未注册上游、
`return` 过早求值、`limit_conn` 槽位生命周期、realip 的端口与主机名语义。

## 边界与后续路线

当前版本尚未实现：

- `alias`、`if`、命名 location、多区间 Range、完整变量集合。
- FastCGI/uWSGI/SCGI、gRPC 专用配置、缓存（Pingora Cache）、认证（`auth_basic`、`auth_request`）、动态模块。
- `ssl_verify_client`、`ssl_ciphers`、`ssl_session_*`、OCSP。
- RTMP 推流/拉流、转码、DRM。当前“流媒体”是 HLS/DASH/VOD 分发与流式反代，不是媒体处理服务器。

建议下一阶段：Pingora Cache 集成、`auth_basic`/`auth_request`、`map`/`geo` 变量、
以及把限流状态迁到 Pingora 共享内存以支持多进程。不要在同一个 HTTP 进程中临时堆叠转码任务；转码应交给独立 worker。
