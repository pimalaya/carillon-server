//! A tiny local webhook sink for verifying Carillon deliveries.
//!
//! Listens on `127.0.0.1:9099` (override with `CARILLON_SINK_ADDR`),
//! and for every `POST` it verifies the Stripe-style signature header
//! `X-Carillon-Signature: t=<ts>,v1=<hex>[,v1=<hex>]` by recomputing
//! `HMAC-SHA256(secret, "<t>.<raw body>")` with the shared secret in
//! `CARILLON_SINK_SECRET` and checking it against every `v1` (so a
//! rotation overlap validates). It also reports replay freshness
//! (`|now - t|` within the tolerance) and dedupes by `X-Carillon-Id`.
//! The payload is content-free, so it prints the body verbatim.
//!
//! ```sh
//! CARILLON_SINK_SECRET=test-secret cargo run --example webhook_sink
//! ```

use std::collections::HashSet;
use std::env;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Reject a timestamp more than this many seconds from now as a replay.
const TOLERANCE_SECS: i64 = 300;

fn main() {
    let addr = env::var("CARILLON_SINK_ADDR").unwrap_or_else(|_| "127.0.0.1:9099".into());
    let secret = env::var("CARILLON_SINK_SECRET").unwrap_or_else(|_| "test-secret".into());

    let listener = TcpListener::bind(&addr).expect("cannot bind sink");
    println!(
        "webhook sink listening on http://{addr} (secret len {})",
        secret.len()
    );

    // Idempotency: remember seen event ids so retries are visible.
    let mut seen: HashSet<String> = HashSet::new();

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(err) = handle(stream, &secret, &mut seen) {
                    eprintln!("connection error: {err}");
                }
            }
            Err(err) => eprintln!("accept error: {err}"),
        }
    }
}

fn handle(mut stream: TcpStream, secret: &str, seen: &mut HashSet<String>) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);

    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;

    let mut content_length = 0usize;
    let mut signature = String::new();
    let mut event = String::new();
    let mut id = String::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            break;
        }
        let Some((name, value)) = trimmed.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "content-length" => content_length = value.parse().unwrap_or(0),
            "x-carillon-signature" => signature = value.to_string(),
            "x-carillon-event" => event = value.to_string(),
            "x-carillon-id" => id = value.to_string(),
            _ => {}
        }
    }

    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body)?;

    let sig = verify(secret, &signature, &body);
    let freshness = match sig.age {
        Some(age) if age.abs() <= TOLERANCE_SECS => format!("fresh({age}s)"),
        Some(age) => format!("STALE({age}s)"),
        None => "no-timestamp".to_string(),
    };
    let dedupe = if id.is_empty() {
        "no-id"
    } else if seen.insert(id.clone()) {
        "new"
    } else {
        "DUPLICATE"
    };

    println!(
        "--> {request}  sig={verdict}  {freshness}  id={dedupe}  event={event}\n    body={}",
        String::from_utf8_lossy(&body),
        request = request_line.trim_end(),
        verdict = if sig.valid { "VALID  " } else { "INVALID" },
    );

    let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
    stream.write_all(response.as_bytes())?;
    stream.flush()
}

/// The outcome of verifying a signature header.
struct SigCheck {
    valid: bool,
    age: Option<i64>,
}

/// Verifies `t=<ts>,v1=<hex>[,v1=...]` over `"<t>.<body>"`.
fn verify(secret: &str, header: &str, body: &[u8]) -> SigCheck {
    let mut ts: Option<i64> = None;
    let mut v1s: Vec<&str> = Vec::new();
    for part in header.split(',') {
        match part.split_once('=') {
            Some(("t", value)) => ts = value.parse().ok(),
            Some(("v1", value)) => v1s.push(value),
            _ => {}
        }
    }

    let Some(ts) = ts else {
        return SigCheck {
            valid: false,
            age: None,
        };
    };

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("any key length");
    mac.update(format!("{ts}.").as_bytes());
    mac.update(body);
    let expected = hex::encode(mac.finalize().into_bytes());

    let valid = v1s
        .iter()
        .any(|v1| constant_time_eq(v1.as_bytes(), expected.as_bytes()));
    let age = now_secs() - ts;

    SigCheck {
        valid,
        age: Some(age),
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
