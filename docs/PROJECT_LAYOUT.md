# 目录规划

项目根目录按「运行时资产 / 开发资产 / 测试资产」三类划分，仓库中只保留可复现的部分，
生产与本地实验数据一律不入库。

## 目录一览

| 目录 | 用途 | 是否入库 |
| --- | --- | --- |
| `src/` | 服务器实现（`core` 基础设施 + `modules` 各 Nginx 模块） | 是 |
| `conf/` | 开发用的示例配置：`nginxrs.conf`、`mime.types`、`lua/content.lua` | 是 |
| `www/` | 示例站点静态文件，配合 `conf/nginxrs.conf` 的 `root ../www` | 是 |
| `docs/` | 架构、指令、目录规划等文档 | 是 |
| `tests/` | 端到端测试，按领域分子目录，见下节 | 是 |
| `c/` | 官方 Nginx C 源码，仅作对照阅读 | 否（`.gitignore`） |
| `test_conf/` | **生产环境配置**，不要改动、不要入库 | 否 |
| `tmp_v/` | 临时验证用的配置副本 | 否（`.gitignore`） |
| `logs/` | 运行期日志 | 否（`.gitignore`） |
| `target/` | 构建产物 | 否（`.gitignore`） |

`pre_refactor/` 为空的归档目录，可随时删除或用于存放重构前的快照。

## tests/ 组织方式

集成测试从单个 3000 行的 `tests/end_to_end.rs` 拆成「按领域分目录 + 共享 support」：

```
tests/
├── support/                     共享测试基础设施（每个测试 crate 各自 include）
│   ├── mod.rs                   Env（临时目录 + 端口）、统一导出
│   ├── server.rs                启动/停止 nginxrs、等待就绪、free_port、run()
│   ├── http.rs                  原始 HTTP/1.1 请求与断言
│   ├── backend.rs               各类测试后端（echo / raw / sized / slow / counting）
│   ├── cert.rs                  openssl 生成自签证书与 CA 链
│   ├── client.rs                TLS 客户端（https_get、会话复用、客户端证书、h2）
│   └── tlsc.rs                  测试用「接受任意证书」校验器
├── core/                        服务器核心行为
│   ├── static_and_lua.rs        静态文件、Range、MIME、rewrite、Lua、负载均衡
│   ├── realip.rs                realip 地址改写
│   ├── access_and_limits.rs     allow/deny、limit_req、limit_conn、stub_status
│   ├── directives.rs            server_tokens、expires、alias、max_ranges、access_log 作用域
│   ├── rewrite_conditions.rs    if/set/break 条件与 file 测试
│   ├── geo.rs                  geo 块、地址映射、转发链
│   ├── geoip.rs                geoip 变量（国家/城市/坐标，测试内生成 .mmdb）
│   └── lifecycle.rs             -s reload / -s stop
├── filters/                     响应过滤器
│   ├── gzip.rs                  gzip/gunzip 协商、压缩、`Vary`、HEAD
│   ├── gzip_static.rs           `.gz` 兄弟文件（on/always/off）
│   └── ssi.rs                   SSI 渲染、包含、errmsg/silent_errors
│   └── ssi.rs                   SSI 渲染、包含、errmsg/silent_errors
├── auth/                        认证
│   └── basic.rs                 auth_basic 挑战、正确/错误口令、user file 缺失
├── config/                      配置加载
│   └── production_shape.rs      生产形态配置（占位值）整树 -t 与实跑
├── proxy/                       反向代理语义
│   ├── grpc.rs                  grpc_pass：伪首部、trailers、upstream 组、失败 502
│   ├── request_shaping.rs       proxy_set_header、URI 替换、未知指令校验
│   ├── response_rewriting.rs    proxy_redirect、proxy_cookie_*、method/body
│   ├── next_upstream.rs         重试策略（状态码、连接错误、次数、非幂等）
│   ├── buffering.rs             缓冲与临时文件转存
│   ├── cache.rs                 proxy_cache 命中/miss/key/bypass/validity
│   ├── error_pages.rs           error_page 与 proxy_intercept_errors
│   └── headers.rs               头部的隐藏、透传与 hop-by-hop 清理
└── tls/                         TLS 相关
    ├── handshake.rs             握手、$ssl_* 变量、SNI 选证
    ├── reject_handshake.rs      ssl_reject_handshake、客户端证书校验
    ├── sessions_and_stapling.rs 会话复用、OCSP stapling
    └── early_data_and_http2.rs  0-RTT、ALPN h2 协商
```

### 为什么要在 `Cargo.toml` 里声明 `[[test]]`

Cargo 只自动发现 `tests/*.rs`，子目录里的文件需要显式声明，因此每个测试文件在
`Cargo.toml` 末尾都有一对：

```toml
[[test]]
name = "cache"
path = "tests/proxy/cache.rs"
```

`support/` 不声明为测试目标，只被 `#[path]` 引入。

### 新增测试的步骤

1. 选定领域目录；新领域先在 `tests/` 下建目录，并在 `Cargo.toml` 加 `[[test]]`。
2. 文件头写：

   ```rust
   #[path = "../support/mod.rs"]
   mod support;

   use support::{Env, config_path};
   ```

3. 用 `Env::new()` 拿临时目录与空闲端口，`env.start(&config)` 起服务，测试结束自动
   结束进程（`ChildGuard` 的 `Drop`）。
4. 需要的后端从 `support::backend` 取；缺什么就在那里加，不要在各测试文件里重复实现。
5. 依赖 `openssl` 的用例用 `Certificates::self_signed_or_skip`，缺失时打印 skip 并返回。

### 运行方式

```powershell
cargo test                                  # 全部（含单元测试）
cargo test --test cache                     # 单个领域
cargo test --test cache proxy_cache_key     # 单个用例
cargo test -- --test-threads=1              # 串行，端口更稳定
```

每个测试文件是独立的 crate 并行构建，单文件编译失败不会阻塞其他领域。

## 配置目录的使用约定

- `conf/` 只放开发示例，可随意改；`cargo run -- -c conf/nginxrs.conf` 直接可用。
- `test_conf/` 是生产配置，`-b` / `-r` 等命令对它操作前请先备份；它不在版本控制内。
- 需要实验时用 `tmp_v/`：复制 `conf/` 过去改，验证完直接删除，不会污染仓库。
