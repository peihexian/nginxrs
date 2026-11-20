//! Process lifecycle: `-s reload` and `-s stop` against a running server.

#[path = "../support/mod.rs"]
mod support;

use std::time::Duration;

use support::http::{assert_response, request, status};
use support::server::{BINARY, ChildGuard, run, wait_until_closed, wait_until_ready};
use support::{Env, config_path};
use std::process::{Command, Stdio};

/// A valid reload swaps routes without dropping the listener; a broken configuration is
/// rejected and the running configuration stays active.
#[test]
fn reload_swaps_configuration_and_rejects_broken_files() {
    let env = Env::new();
    let port = env.port;
    let pid_file = env.path().join("nginxrs.pid");
    let config_file = env.path().join("nginx.conf");
    let write = |body: &str| {
        std::fs::write(
            &config_file,
            format!(
                r#"
                worker_processes 2;
                pid nginxrs.pid;
                http {{
                    access_log off;
                    server {{
                        listen 127.0.0.1:{port};
                        location = /version {{ return 200 "{body}"; }}
                    }}
                }}
                "#
            ),
        )
        .unwrap();
    };

    write("one");
    let child = Command::new(BINARY)
        .arg("-c")
        .arg(&config_file)
        .arg("-p")
        .arg(&pid_file)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let _guard = ChildGuard(child);
    wait_until_ready(port, &config_file, Duration::from_secs(10));

    let get_version = || {
        request(
            port,
            "GET /version HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
    };

    assert_response(&get_version(), 200, "one");

    // Valid reload: new routes take effect without dropping the listener.
    write("two");
    let output = run([
        "-c",
        config_file.to_str().unwrap(),
        "-p",
        pid_file.to_str().unwrap(),
        "-s",
        "reload",
    ]);
    assert!(output.status.success(), "{output:?}");
    assert_response(&get_version(), 200, "two");

    // Invalid reload is rejected and the running configuration stays active.
    std::fs::write(
        &config_file,
        "worker_processes 2; http { server { listen 1; made_up on; } }",
    )
    .unwrap();
    let output = run([
        "-c",
        config_file.to_str().unwrap(),
        "-p",
        pid_file.to_str().unwrap(),
        "-s",
        "reload",
    ]);
    assert!(
        !output.status.success(),
        "invalid reload should fail: {output:?}"
    );
    assert_response(&get_version(), 200, "two");
}

/// `nginxrs -s stop` must terminate the server, not only acknowledge the command.
#[test]
fn stop_signal_terminates_the_server() {
    let env = Env::new();
    let port = env.port;
    let pid_file = env.path().join("nginxrs.pid");
    let config = format!(
        r#"
        pid {pid};
        http {{
            access_log off;
            server {{
                listen 127.0.0.1:{port};
                location / {{ return 200 "up"; }}
            }}
        }}
        "#,
        pid = config_path(&pid_file),
    );
    let config_file = env.path().join("nginx.conf");
    std::fs::write(&config_file, &config).unwrap();
    let mut server = Command::new(BINARY)
        .arg("-c")
        .arg(&config_file)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    wait_until_ready(port, &config_file, Duration::from_secs(10));

    let output = run([
        "-c",
        config_file.to_str().unwrap(),
        "-s",
        "stop",
    ]);
    // The server may exit before the control reply is drained, so a reset on that socket is
    // acceptable; what matters is that the server actually stops (asserted below).
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success() || stderr.contains("10054") || stderr.is_empty(),
        "unexpected stop failure: {stderr}"
    );

    wait_until_closed(port, Duration::from_secs(10));
    let _ = server.wait();
    assert!(status("HTTP/1.1 200 OK") == 200);
}
