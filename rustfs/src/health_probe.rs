// Copyright 2024 RustFS Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Built-in HTTP/HTTPS/mTLS health and readiness probe (`rustfs health`).

use crate::config::HealthProbeOpts;
use rustfs_config::{RUSTFS_CLIENT_CERT_FILENAME, RUSTFS_CLIENT_KEY_FILENAME};
use rustfs_tls_runtime::{TlsMaterialSnapshot, TlsSource, ensure_crypto_provider};
use rustls::pki_types::{CertificateDer, pem::PemObject};
use std::io::{Cursor, Error, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

const HEALTH_LIVENESS_PATH: &str = "/health";
const HEALTH_READINESS_PATH: &str = "/health/ready";
const MAX_BODY_SNIPPET_CHARS: usize = 256;

/// Run the health probe on a lightweight single-threaded Tokio runtime.
pub fn run_health_probe_cli(opts: &HealthProbeOpts) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(execute_health_probe(opts))
}

/// Execute a single liveness (`/health`) or readiness (`/health/ready`) probe.
pub async fn execute_health_probe(opts: &HealthProbeOpts) -> Result<()> {
    let tls_dir = opts.tls_path.as_deref().map(str::trim).filter(|path| !path.is_empty());

    let snapshot = match tls_dir {
        Some(path) => Some(
            TlsMaterialSnapshot::load(&TlsSource::from_directory(path))
                .await
                .map_err(|err| Error::other(format!("load TLS material from `{path}`: {err}")))?,
        ),
        None => None,
    };

    let (host, port) = resolve_local_listen_address(&opts.address)?;
    let use_tls = snapshot.as_ref().is_some_and(|snap| snap.server.is_some())
        || opts.client_cert.is_some()
        || opts.client_key.is_some()
        || opts.insecure;

    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(opts.timeout));

    if use_tls {
        ensure_crypto_provider().map_err(Error::other)?;
        if opts.insecure {
            builder = builder.danger_accept_invalid_certs(true);
        } else if let Some(snap) = &snapshot {
            for pem in [
                Some(snap.outbound.root_ca_pem.as_slice()),
                snap.server_client_ca_pem.as_deref(),
            ]
            .into_iter()
            .flatten()
            {
                let mut reader = Cursor::new(pem);
                for cert_der in CertificateDer::pem_reader_iter(&mut reader).flatten() {
                    let cert = reqwest::Certificate::from_der(cert_der.as_ref())
                        .map_err(|err| Error::other(format!("load CA certificate: {err}")))?;
                    builder = builder.add_root_certificate(cert);
                }
            }
        }

        if let Some(identity) = load_client_identity(opts, snapshot.as_ref()).await? {
            builder = builder.identity(identity);
        }
    }

    let client = builder
        .build()
        .map_err(|err| Error::other(format!("build HTTP probe client: {err}")))?;

    let scheme = if use_tls { "https" } else { "http" };
    let url_host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host
    };
    let path = if opts.ready {
        HEALTH_READINESS_PATH
    } else {
        HEALTH_LIVENESS_PATH
    };
    let url = format!("{scheme}://{url_host}:{port}{path}");

    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|err| Error::other(format!("probe {url} failed: {err}")))?;

    let status = response.status();
    if status.is_success() {
        return Ok(());
    }

    let body = response.text().await.unwrap_or_default();
    let snippet: String = body
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(MAX_BODY_SNIPPET_CHARS)
        .collect();
    if snippet.is_empty() {
        Err(Error::other(format!("probe {url} returned HTTP {}", status.as_u16())))
    } else {
        Err(Error::other(format!("probe {url} returned HTTP {}: {snippet}", status.as_u16())))
    }
}

async fn load_client_identity(
    opts: &HealthProbeOpts,
    snapshot: Option<&TlsMaterialSnapshot>,
) -> Result<Option<reqwest::Identity>> {
    let (cert_pem, key_pem) = if opts.client_cert.is_some() || opts.client_key.is_some() {
        let base_dir = snapshot.map(|snap| snap.source.base_dir.as_path());
        let cert_path = opts
            .client_cert
            .clone()
            .or_else(|| base_dir.map(|dir| dir.join(RUSTFS_CLIENT_CERT_FILENAME)))
            .ok_or_else(|| Error::other("--key specified without --cert or --tls-path"))?;
        let key_path = opts
            .client_key
            .clone()
            .or_else(|| base_dir.map(|dir| dir.join(RUSTFS_CLIENT_KEY_FILENAME)))
            .ok_or_else(|| Error::other("--cert specified without --key or --tls-path"))?;
        let cert = tokio::fs::read(&cert_path)
            .await
            .map_err(|err| Error::other(format!("read client cert `{}`: {err}", cert_path.display())))?;
        let key = tokio::fs::read(&key_path)
            .await
            .map_err(|err| Error::other(format!("read client key `{}`: {err}", key_path.display())))?;
        (cert, key)
    } else if let Some(id) = snapshot.and_then(|snap| snap.outbound.mtls_identity.as_ref()) {
        (id.cert_pem.clone(), id.key_pem.clone())
    } else {
        return Ok(None);
    };

    let mut combined = Vec::with_capacity(cert_pem.len() + key_pem.len() + 1);
    combined.extend_from_slice(&cert_pem);
    if !combined.ends_with(b"\n") {
        combined.push(b'\n');
    }
    combined.extend_from_slice(&key_pem);

    reqwest::Identity::from_pem(&combined)
        .map(Some)
        .map_err(|err| Error::other(format!("parse mTLS client identity: {err}")))
}

fn resolve_local_listen_address(address: &str) -> Result<(String, u16)> {
    let trimmed = address.trim();
    if let Some(port_str) = trimmed.strip_prefix(':') {
        let port = parse_non_zero_port(port_str, address)?;
        return Ok((Ipv4Addr::LOCALHOST.to_string(), port));
    }

    if let Ok(sock_addr) = trimmed.parse::<SocketAddr>() {
        if sock_addr.port() == 0 {
            return Err(Error::other(format!("invalid listen address `{address}`: port must be non-zero")));
        }
        let ip = match sock_addr.ip() {
            IpAddr::V4(v4) if v4.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(v6) if v6.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
            concrete => concrete,
        };
        return Ok((ip.to_string(), sock_addr.port()));
    }

    let (host, port_str) = trimmed
        .rsplit_once(':')
        .ok_or_else(|| Error::other(format!("invalid listen address `{address}`: expected HOST:PORT or :PORT")))?;
    let host = host.trim();
    if host.is_empty() {
        return Err(Error::other(format!("invalid listen address `{address}`: empty host")));
    }
    Ok((host.to_string(), parse_non_zero_port(port_str, address)?))
}

fn parse_non_zero_port(port_str: &str, raw_address: &str) -> Result<u16> {
    let port = port_str
        .parse::<u16>()
        .map_err(|err| Error::other(format!("invalid listen address `{raw_address}`: {err}")))?;
    if port == 0 {
        return Err(Error::other(format!("invalid listen address `{raw_address}`: port must be non-zero")));
    }
    Ok(port)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, SanType,
    };
    use rustfs_config::{RUSTFS_CA_CERT, RUSTFS_CLIENT_CA_CERT_FILENAME, RUSTFS_TLS_CERT, RUSTFS_TLS_KEY};
    use rustfs_tls_runtime::default_crypto_provider;
    use rustls::RootCertStore;
    use rustls::pki_types::PrivateKeyDer;
    use rustls::server::WebPkiClientVerifier;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    fn default_opts() -> HealthProbeOpts {
        HealthProbeOpts {
            ready: false,
            address: ":9000".to_string(),
            tls_path: None,
            client_cert: None,
            client_key: None,
            insecure: false,
            timeout: 3,
        }
    }

    struct MtlsTestPki {
        ca_pem: String,
        ca_der: CertificateDer<'static>,
        server_cert_pem: String,
        server_key_pem: String,
        server_certs: Vec<CertificateDer<'static>>,
        server_key: PrivateKeyDer<'static>,
        client_cert_pem: String,
        client_key_pem: String,
    }

    fn build_mtls_test_pki(server_sans: Vec<SanType>) -> MtlsTestPki {
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.distinguished_name = DistinguishedName::new();
        let ca_key = KeyPair::generate().expect("generate CA key");
        let ca_cert = ca_params.self_signed(&ca_key).expect("self-sign CA");
        let ca_issuer = Issuer::new(ca_params, ca_key);

        let mut server_params = CertificateParams::default();
        server_params.subject_alt_names = server_sans;
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_key = KeyPair::generate().expect("generate server key");
        let server_cert = server_params.signed_by(&server_key, &ca_issuer).expect("sign server cert");

        let mut client_params = CertificateParams::default();
        client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let client_key = KeyPair::generate().expect("generate client key");
        let client_cert = client_params.signed_by(&client_key, &ca_issuer).expect("sign client cert");

        MtlsTestPki {
            ca_pem: ca_cert.pem(),
            ca_der: ca_cert.der().clone(),
            server_cert_pem: server_cert.pem(),
            server_key_pem: server_key.serialize_pem(),
            server_certs: vec![server_cert.der().clone()],
            server_key: PrivateKeyDer::try_from(server_key.serialize_der()).expect("server key DER"),
            client_cert_pem: client_cert.pem(),
            client_key_pem: client_key.serialize_pem(),
        }
    }

    async fn spawn_http_server(expected_path: &'static str, status: &'static str, body: &'static str) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind HTTP");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut buf = [0_u8; 1024];
            let n = stream.read(&mut buf).await.unwrap_or(0);
            let ok = String::from_utf8_lossy(&buf[..n]).starts_with(&format!("GET {expected_path} "));
            let reply = if ok {
                format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
            } else {
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
            };
            let _ = stream.write_all(reply.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
        addr
    }

    async fn spawn_strict_mtls_server(pki: &MtlsTestPki, expected_path: &'static str) -> SocketAddr {
        ensure_crypto_provider().expect("crypto provider");
        let provider = Arc::new(default_crypto_provider());
        let mut roots = RootCertStore::empty();
        roots.add(pki.ca_der.clone()).expect("add client CA");
        let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&provider))
            .build()
            .expect("strict verifier");
        let server_cfg = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_client_cert_verifier(verifier)
            .with_single_cert(pki.server_certs.clone(), pki.server_key.clone_key())
            .expect("server cert");
        let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mTLS");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let Ok(mut tls) = acceptor.accept(tcp).await else {
                return;
            };
            let mut buf = [0_u8; 1024];
            let n = tls.read(&mut buf).await.unwrap_or(0);
            let ok = String::from_utf8_lossy(&buf[..n]).starts_with(&format!("GET {expected_path} "));
            let reply = if ok {
                "HTTP/1.1 200 OK\r\nContent-Length: 14\r\nConnection: close\r\n\r\n{\"ready\":true}"
            } else {
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            };
            let _ = tls.write_all(reply.as_bytes()).await;
            let _ = tls.shutdown().await;
        });
        addr
    }

    #[test]
    fn resolve_local_listen_address_maps_unspecified_to_loopback() {
        assert_eq!(resolve_local_listen_address(":9000").unwrap(), ("127.0.0.1".to_string(), 9000));
        assert_eq!(resolve_local_listen_address("0.0.0.0:9443").unwrap(), ("127.0.0.1".to_string(), 9443));
        assert_eq!(resolve_local_listen_address("[::]:9000").unwrap(), ("::1".to_string(), 9000));
    }

    #[tokio::test]
    async fn plain_http_readiness_probe_succeeds_on_200_and_fails_on_503() {
        let ok_addr = spawn_http_server("/health/ready", "200 OK", r#"{"ready":true}"#).await;
        let mut opts = default_opts();
        opts.ready = true;
        opts.address = format!(":{}", ok_addr.port());
        execute_health_probe(&opts).await.expect("200 OK must succeed");

        let bad_addr = spawn_http_server(
            "/health/ready",
            "503 Service Unavailable",
            r#"{"ready":false,"degradedReasons":["read_quorum_unavailable"]}"#,
        )
        .await;
        opts.address = format!(":{}", bad_addr.port());
        let err = execute_health_probe(&opts).await.expect_err("503 must fail").to_string();
        assert!(err.contains("503") && err.contains("read_quorum_unavailable"), "got: {err}");
    }

    #[tokio::test]
    async fn strict_mtls_probe_verifies_tls_path_and_rejects_missing_client_cert() {
        let pki = build_mtls_test_pki(vec![SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST))]);
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(RUSTFS_TLS_CERT), &pki.server_cert_pem).unwrap();
        std::fs::write(dir.path().join(RUSTFS_TLS_KEY), &pki.server_key_pem).unwrap();
        std::fs::write(dir.path().join(RUSTFS_CA_CERT), &pki.ca_pem).unwrap();
        std::fs::write(dir.path().join(RUSTFS_CLIENT_CA_CERT_FILENAME), &pki.ca_pem).unwrap();

        let unauth_addr = spawn_strict_mtls_server(&pki, "/health/ready").await;
        let mut opts = default_opts();
        opts.ready = true;
        opts.address = format!(":{}", unauth_addr.port());
        opts.tls_path = Some(dir.path().display().to_string());
        assert!(execute_health_probe(&opts).await.is_err());

        std::fs::write(dir.path().join(RUSTFS_CLIENT_CERT_FILENAME), &pki.client_cert_pem).unwrap();
        std::fs::write(dir.path().join(RUSTFS_CLIENT_KEY_FILENAME), &pki.client_key_pem).unwrap();
        let auth_addr = spawn_strict_mtls_server(&pki, "/health/ready").await;
        opts.address = format!(":{}", auth_addr.port());
        execute_health_probe(&opts).await.expect("verified mTLS probe must succeed");
    }

    #[tokio::test]
    async fn strict_mtls_probe_supports_insecure_loopback_for_dns_only_san() {
        let pki = build_mtls_test_pki(vec![SanType::DnsName("*.rustfs-hl.default.svc.cluster.local".try_into().unwrap())]);
        let dir = tempfile::tempdir().expect("tempdir");
        let cert_path = dir.path().join("client.crt");
        let key_path = dir.path().join("client.key");
        std::fs::write(&cert_path, &pki.client_cert_pem).unwrap();
        std::fs::write(&key_path, &pki.client_key_pem).unwrap();

        let addr = spawn_strict_mtls_server(&pki, "/health/ready").await;
        let mut opts = default_opts();
        opts.ready = true;
        opts.address = format!("127.0.0.1:{}", addr.port());
        opts.client_cert = Some(cert_path);
        opts.client_key = Some(key_path);
        opts.insecure = true;
        execute_health_probe(&opts)
            .await
            .expect("insecure loopback mTLS probe must succeed");
    }
}
