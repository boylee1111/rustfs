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

//! End-to-end binary integration tests for `rustfs health` against a live
//! `rustfs` server process with strict handshake-level mTLS enabled.

use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, SanType};
use rustfs_config::{
    RUSTFS_CA_CERT, RUSTFS_CLIENT_CA_CERT_FILENAME, RUSTFS_CLIENT_CERT_FILENAME, RUSTFS_CLIENT_KEY_FILENAME, RUSTFS_TLS_CERT,
    RUSTFS_TLS_KEY,
};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn reserve_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local addr").port()
}

fn write_mtls_bundle(full_dir: &Path, server_only_dir: &Path) {
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.distinguished_name = DistinguishedName::new();
    let ca_key = KeyPair::generate().expect("generate CA key");
    let ca_cert = ca_params.self_signed(&ca_key).expect("self-sign CA");
    let ca_issuer = Issuer::new(ca_params, ca_key);

    // Cert-manager style wildcard DNS SAN (no 127.0.0.1 IP SAN).
    let mut server_params = CertificateParams::default();
    server_params.subject_alt_names = vec![SanType::DnsName(
        "*.rustfs-hl.default.svc.cluster.local".try_into().expect("valid DNS SAN"),
    )];
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_key = KeyPair::generate().expect("generate server key");
    let server_cert = server_params.signed_by(&server_key, &ca_issuer).expect("sign server cert");

    let mut client_params = CertificateParams::default();
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_key = KeyPair::generate().expect("generate client key");
    let client_cert = client_params.signed_by(&client_key, &ca_issuer).expect("sign client cert");

    for dir in [full_dir, server_only_dir] {
        std::fs::write(dir.join(RUSTFS_TLS_CERT), server_cert.pem()).expect("write server cert");
        std::fs::write(dir.join(RUSTFS_TLS_KEY), server_key.serialize_pem()).expect("write server key");
        std::fs::write(dir.join(RUSTFS_CA_CERT), ca_cert.pem()).expect("write ca.crt");
        std::fs::write(dir.join(RUSTFS_CLIENT_CA_CERT_FILENAME), ca_cert.pem()).expect("write client_ca.crt");
    }

    std::fs::write(full_dir.join(RUSTFS_CLIENT_CERT_FILENAME), client_cert.pem()).expect("write client cert");
    std::fs::write(full_dir.join(RUSTFS_CLIENT_KEY_FILENAME), client_key.serialize_pem()).expect("write client key");
}

#[tokio::test]
async fn rustfs_health_binary_probes_live_mtls_server_end_to_end() {
    let data_dir = tempfile::tempdir().expect("data tempdir");
    let full_tls_dir = tempfile::tempdir().expect("full tls tempdir");
    let no_client_tls_dir = tempfile::tempdir().expect("no-client tls tempdir");
    write_mtls_bundle(full_tls_dir.path(), no_client_tls_dir.path());

    let port = reserve_free_port();
    let listen_addr = format!("127.0.0.1:{port}");
    let bin = env!("CARGO_BIN_EXE_rustfs");

    let child = Command::new(bin)
        .args(["server", data_dir.path().to_str().expect("utf8 data path")])
        .env("RUSTFS_ADDRESS", &listen_addr)
        .env("RUSTFS_CONSOLE_ENABLE", "false")
        .env("RUSTFS_TLS_PATH", full_tls_dir.path())
        .env("RUSTFS_SERVER_MTLS_ENABLE", "true")
        .env("RUSTFS_ACCESS_KEY", "rustfsadmin")
        .env("RUSTFS_SECRET_KEY", "rustfsadmin123")
        .env_remove("HTTP_PROXY")
        .env_remove("HTTPS_PROXY")
        .env_remove("http_proxy")
        .env_remove("https_proxy")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn rustfs mTLS server");
    let mut server_guard = ChildGuard(child);

    // Poll with the real `rustfs health --ready --insecure` binary until readiness quorum comes up.
    let deadline = Instant::now() + Duration::from_secs(45);
    let mut ready = false;
    let mut last_stderr = String::new();
    while Instant::now() < deadline {
        if let Some(status) = server_guard.0.try_wait().expect("poll child") {
            panic!("rustfs server exited prematurely with {status}");
        }
        let output = Command::new(bin)
            .args(["health", "--ready", "--insecure", "--timeout", "2"])
            .env("RUSTFS_ADDRESS", format!(":{port}"))
            .env("RUSTFS_TLS_PATH", full_tls_dir.path())
            .env_remove("HTTP_PROXY")
            .env_remove("HTTPS_PROXY")
            .output()
            .expect("run rustfs health --ready");
        if output.status.success() {
            ready = true;
            break;
        }
        last_stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(ready, "rustfs health --ready did not succeed within 45s; last stderr: {last_stderr}");

    // Liveness probe (`rustfs health`) must also exit 0.
    let live_out = Command::new(bin)
        .args(["health", "--insecure", "--timeout", "2"])
        .env("RUSTFS_ADDRESS", format!(":{port}"))
        .env("RUSTFS_TLS_PATH", full_tls_dir.path())
        .output()
        .expect("run rustfs health");
    assert!(
        live_out.status.success(),
        "liveness probe failed: {}",
        String::from_utf8_lossy(&live_out.stderr)
    );

    // Unauthenticated HTTPS client (no client cert) must be rejected by strict handshake mTLS.
    let unauth_client = reqwest::Client::builder()
        .no_proxy()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(3))
        .build()
        .expect("build unauth reqwest client");
    assert!(
        unauth_client
            .get(format!("https://127.0.0.1:{port}/health/ready"))
            .send()
            .await
            .is_err(),
        "strict server mTLS must reject HTTPS health probes without a client certificate"
    );

    // `rustfs health --ready` without client_cert.pem/client_key.pem must exit non-zero.
    let unauth_cli_out = Command::new(bin)
        .args(["health", "--ready", "--insecure", "--timeout", "2"])
        .env("RUSTFS_ADDRESS", format!(":{port}"))
        .env("RUSTFS_TLS_PATH", no_client_tls_dir.path())
        .output()
        .expect("run unauthenticated rustfs health --ready");
    assert!(!unauth_cli_out.status.success(), "unauthenticated CLI probe must fail");
    let unauth_stderr = String::from_utf8_lossy(&unauth_cli_out.stderr);
    assert!(
        unauth_stderr.contains("Health probe failed"),
        "expected fatal health probe message on stderr, got: {unauth_stderr}"
    );
}
