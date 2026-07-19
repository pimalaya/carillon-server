//! A tiny local webhook sink for verifying Carillon deliveries.
//!
//! Listens on `127.0.0.1:9099` (override with `CARILLON_SINK_ADDR`),
//! and for every `POST` it recomputes the HMAC-SHA256 signature over
//! the raw body with the shared secret in `CARILLON_SINK_SECRET` and
//! reports whether it matches the `X-Carillon-Signature` header. The
//! payload is content-free, so it prints the body verbatim. Used to
//! confirm the end-to-end IDLE → signed webhook path against a real
//! mailbox.
//!
//! ```sh
//! CARILLON_SINK_SECRET=test-secret cargo run --example webhook_sink
//! ```

use std::env;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

fn main() {
    let addr = env::var("CARILLON_SINK_ADDR").unwrap_or_else(|_| "127.0.0.1:9099".into());
    let secret = env::var("CARILLON_SINK_SECRET").unwrap_or_else(|_| "test-secret".into());

    let listener = TcpListener::bind(&addr).expect("cannot bind sink");
    println!(
        "webhook sink listening on http://{addr} (secret len {})",
        secret.len()
    );

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(err) = handle(stream, &secret) {
                    eprintln!("connection error: {err}");
                }
            }
            Err(err) => eprintln!("accept error: {err}"),
        }
    }
}

fn handle(mut stream: TcpStream, secret: &str) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);

    // Request line.
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;

    // Headers.
    let mut content_length = 0usize;
    let mut signature = String::new();
    let mut event = String::new();
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
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        match name.as_str() {
            "content-length" => content_length = value.parse().unwrap_or(0),
            "x-carillon-signature" => signature = value.to_string(),
            "x-carillon-event" => event = value.to_string(),
            _ => {}
        }
    }

    // Body.
    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body)?;

    let expected = sign(secret, &body);
    let verdict = if constant_time_eq(expected.as_bytes(), signature.as_bytes()) {
        "VALID  "
    } else {
        "INVALID"
    };

    println!(
        "--> {request}  sig={verdict}  event={event}\n    body={}",
        String::from_utf8_lossy(&body),
        request = request_line.trim_end(),
    );

    let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
    stream.write_all(response.as_bytes())?;
    stream.flush()
}

fn sign(secret: &str, body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("any key length");
    mac.update(body);
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
