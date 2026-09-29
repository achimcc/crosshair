//! HOW CROSSHAIR PROVES WHO IT IS TO GRAFANA — measured on the wire, against
//! the built binary and the real `curl`, not against a `Canned` double that
//! never sees a header.
//!
//! Audit B138 / CD-10: until 0.2.0 crosshair logged in with the Grafana ADMIN
//! password through `/login` and kept a session cookie, although it only
//! reads — a dashboard search and `/api/ds/query`. Now it sends a
//! service-account token as `Authorization: Bearer`, to Grafana and to
//! nothing else, and never calls `/login`.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};

/// A token that looks like Grafana's, and is recognisable in any output.
const TOKEN: &str = "glsa_crosshairTestToken0123456789_abcdef01";

#[derive(Debug, Clone)]
struct Seen {
    path: String,
    authorization: Option<String>,
}

fn is_grafana(path: &str) -> bool {
    path.starts_with("/api/search")
        || path.starts_with("/api/dashboards/")
        || path.starts_with("/api/ds/query")
        || path.starts_with("/login")
}

/// One request per connection: curl is spawned once per call, and the
/// answer closes the connection.
fn serve(mut stream: TcpStream, seen: &Mutex<Vec<Seen>>) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    if reader.read_line(&mut line).unwrap_or(0) == 0 {
        return;
    }
    let path = line.split_whitespace().nth(1).unwrap_or("").to_string();
    let mut authorization = None;
    let mut length = 0usize;
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h).unwrap_or(0) == 0 || h == "\r\n" {
            break;
        }
        let (name, value) = h.split_once(':').unwrap_or((&h, ""));
        let value = value.trim().to_string();
        match name.to_ascii_lowercase().as_str() {
            "authorization" => authorization = Some(value),
            "content-length" => length = value.parse().unwrap_or(0),
            _ => {}
        }
    }
    let mut body = vec![0u8; length];
    let _ = reader.read_exact(&mut body);
    seen.lock().unwrap().push(Seen {
        path: path.clone(),
        authorization: authorization.clone(),
    });

    let bearer_ok = authorization.as_deref() == Some(&format!("Bearer {TOKEN}"));
    let (status, answer) = if is_grafana(&path) && !bearer_ok {
        (
            "401 Unauthorized",
            r#"{"message":"Unauthorized"}"#.to_string(),
        )
    } else if path.starts_with("/login") {
        ("200 OK", r#"{"message":"Logged in"}"#.to_string())
    } else if path.starts_with("/api/v1/series") {
        if path.contains("crosshair-control-no-such-job") {
            ("200 OK", r#"{"status":"success","data":[]}"#.to_string())
        } else {
            (
                "200 OK",
                r#"{"status":"success","data":[{"__name__":"up"}]}"#.to_string(),
            )
        }
    } else if path.starts_with("/api/search") {
        (
            "200 OK",
            r#"[{"uid":"abc","folderTitle":"Observability","title":"Self"}]"#.to_string(),
        )
    } else if path.starts_with("/api/dashboards/uid/abc") {
        (
            "200 OK",
            r#"{"dashboard":{"panels":[{"type":"timeseries","title":"P",
            "datasource":{"uid":"prometheus"},"targets":[{"refId":"A","expr":"up"}]}]}}"#
                .to_string(),
        )
    } else if path.starts_with("/api/ds/query") {
        (
            "200 OK",
            r#"{"results":{"Q0":{"frames":[{"data":{"values":[[1]]}}]},"Q1":{"frames":[]}}}"#
                .to_string(),
        )
    } else {
        ("404 Not Found", r#"{"message":"not found"}"#.to_string())
    };
    let _ = write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{answer}",
        answer.len()
    );
}

fn start_server() -> (String, Arc<Mutex<Vec<Seen>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let s = Arc::clone(&seen);
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            serve(stream, &s);
        }
    });
    (base, seen)
}

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("crosshair-auth-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn grafana_gets_the_bearer_token_and_no_login_is_ever_called() {
    let (base, seen) = start_server();
    let dir = scratch("bearer");
    let token_file = dir.join("token");
    // With the trailing newline `echo` would write.
    std::fs::write(&token_file, format!("{TOKEN}\n")).unwrap();
    let tmp = dir.join("tmp");
    std::fs::create_dir_all(&tmp).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_crosshair"))
        .args(["check", "--source", "grafana", "--prometheus", &base])
        .args(["--grafana", &base, "--grafana-token-file"])
        .arg(&token_file)
        .env("TMPDIR", &tmp)
        .output()
        .expect("running crosshair");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let seen = seen.lock().unwrap().clone();
    let leftovers: Vec<_> = std::fs::read_dir(&tmp)
        .unwrap()
        .flatten()
        .map(|e| e.file_name())
        .collect();
    let _ = std::fs::remove_dir_all(&dir);

    // The token never shows up in what the run prints.
    assert!(
        !stdout.contains(TOKEN) && !stderr.contains(TOKEN),
        "the token is in the output"
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "the run against a Grafana that wants the token must succeed\nstdout: {stdout}\nstderr: {stderr}\nrequests: {seen:?}"
    );

    let grafana: Vec<&Seen> = seen.iter().filter(|s| is_grafana(&s.path)).collect();
    assert!(
        grafana.iter().any(|s| s.path.starts_with("/api/ds/query"))
            && grafana.iter().any(|s| s.path.starts_with("/api/search")),
        "the run did not reach Grafana at all: {seen:?}"
    );
    assert!(
        !seen.iter().any(|s| s.path.starts_with("/login")),
        "crosshair must not log in any more: {seen:?}"
    );
    for s in &grafana {
        assert_eq!(
            s.authorization.as_deref(),
            Some(format!("Bearer {TOKEN}").as_str()),
            "a Grafana request without the bearer token: {}",
            s.path
        );
    }
    // The token belongs to Grafana; Prometheus never sees it.
    for s in seen.iter().filter(|s| s.path.starts_with("/api/v1/")) {
        assert_eq!(
            s.authorization, None,
            "Prometheus got an Authorization header: {}",
            s.path
        );
    }
    // And the header file that carried it is gone again.
    assert!(
        leftovers.is_empty(),
        "the run left files in its temp dir: {leftovers:?}"
    );
}

/// THE OLD OPTION IS GONE, NOT KEPT BESIDE THE NEW ONE: a caller still passing
/// the admin password must fail loudly, never fall back to a login.
#[test]
fn the_password_option_is_refused() {
    let (base, seen) = start_server();
    let dir = scratch("password");
    let pw = dir.join("pw");
    std::fs::write(&pw, "admin-password\n").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_crosshair"))
        .args(["check", "--source", "grafana", "--prometheus", &base])
        .args(["--grafana", &base, "--grafana-password-file"])
        .arg(&pw)
        .output()
        .expect("running crosshair");
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        seen.lock().unwrap().is_empty(),
        "a refused option must not reach any server: {:?}",
        seen.lock().unwrap()
    );
}
