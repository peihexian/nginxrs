//! `proxy_cache`: hit/miss behaviour, keys, bypass, validity and zone validation.

#[path = "../support/mod.rs"]
mod support;

use std::sync::atomic::Ordering;

use support::backend::spawn_counting_backend;
use support::http::{body, request, status};
use support::server::run;
use support::{Env, config_path};

/// A `proxy_cache_path` plus the counting upstream every cache test shares.
fn cached_server(env: &Env, location: &str) -> (support::ChildGuard, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    let cache_dir = env.path().join("cache");
    std::fs::create_dir_all(&cache_dir).unwrap();
    let (backend, counter) = spawn_counting_backend();
    let port = env.port;
    let config = format!(
        r#"
        http {{
            access_log off;
            proxy_cache_path {cache_dir} levels=1:2 keys_zone=z:10m inactive=1h max_size=10m;
            upstream backend {{ server 127.0.0.1:{backend}; }}
            server {{
                listen 127.0.0.1:{port};
                location / {{
                    proxy_pass http://backend;
                    {location}
                }}
            }}
        }}
        "#,
        cache_dir = config_path(&cache_dir),
    );
    (env.start(&config), counter)
}

fn get(port: u16, path: &str) -> String {
    request(
        port,
        &format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
    )
}

/// A cached response is served without contacting the upstream on the second request.
#[test]
fn proxy_cache_serves_the_second_request_from_the_cache() {
    let env = Env::new();
    let (_server, counter) = cached_server(
        &env,
        "proxy_cache z;\n                    proxy_cache_valid 200 10m;",
    );
    let port = env.port;

    let first = get(port, "/item");
    assert_eq!(status(&first), 200, "{first}");
    assert_eq!(body(&first), "hit-1");

    let second = get(port, "/item");
    assert_eq!(status(&second), 200, "{second}");
    assert_eq!(body(&second), "hit-1", "the cached body must be replayed");
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "the upstream must only be contacted once"
    );
}

/// Different cache keys are stored separately.
#[test]
fn proxy_cache_key_separates_requests() {
    let env = Env::new();
    let (_server, counter) = cached_server(
        &env,
        "proxy_cache z;\n                    proxy_cache_key $request_uri;\n                    proxy_cache_valid 200 10m;",
    );
    let port = env.port;

    let a = get(port, "/a");
    let b = get(port, "/b");
    assert_eq!(body(&a), "hit-1", "{a}");
    assert_eq!(body(&b), "hit-2", "{b}");
    assert_eq!(counter.load(Ordering::SeqCst), 2);

    // Both keys now hit.
    let a2 = get(port, "/a");
    assert_eq!(body(&a2), "hit-1");
}

/// `proxy_cache_bypass` skips the cache and reaches the upstream.
#[test]
fn proxy_cache_bypass_skips_the_lookup() {
    let env = Env::new();
    let (_server, counter) = cached_server(
        &env,
        "proxy_cache z;\n                    proxy_cache_valid 200 10m;\n                    proxy_cache_bypass $arg_nocache;",
    );
    let port = env.port;

    let first = get(port, "/item");
    assert_eq!(body(&first), "hit-1", "{first}");
    let bypass = get(port, "/item?nocache=1");
    assert_eq!(body(&bypass), "hit-2", "a bypass must reach the upstream");
    assert_eq!(counter.load(Ordering::SeqCst), 2);
}

/// Without `proxy_cache_valid` and without expiry headers the response is not cached.
#[test]
fn proxy_cache_without_validity_is_not_cached() {
    let env = Env::new();
    let (_server, counter) = cached_server(&env, "proxy_cache z;");
    let port = env.port;

    let first = get(port, "/item");
    assert_eq!(body(&first), "hit-1", "{first}");
    let second = get(port, "/item");
    assert_eq!(body(&second), "hit-2", "{second}");
    assert_eq!(counter.load(Ordering::SeqCst), 2);
}

/// An unknown `proxy_cache` zone is a configuration error, as in Nginx.
#[test]
fn proxy_cache_unknown_zone_is_rejected() {
    let env = Env::new();
    let path = env.path().join("nginx.conf");
    std::fs::write(
        &path,
        r#"
        http {
            server {
                listen 127.0.0.1:18098;
                location / { proxy_pass http://127.0.0.1:9000; proxy_cache missing; }
            }
        }
        "#,
    )
    .unwrap();
    let output = run(["-c", path.to_str().unwrap(), "-t"]);
    assert!(!output.status.success(), "{output:?}");
    let message = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(message.contains("unknown"), "{message}");
}
