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

use hex_simd::{AsOut, AsciiCase};
use hyper::body::Bytes;
use std::mem::MaybeUninit;

#[cfg(feature = "fips")]
#[path = "crypto/fips.rs"]
mod backend;
#[cfg(not(feature = "fips"))]
#[path = "crypto/standard.rs"]
mod backend;

pub use backend::{HmacSha256, Sha256, hmac_sha1};

/// Error returned when an HMAC key is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidKeyLength;

impl std::fmt::Display for InvalidKeyLength {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid HMAC key length")
    }
}

impl std::error::Error for InvalidKeyLength {}

/// Error returned when MAC verification fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacError;

impl std::fmt::Display for MacError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MAC verification failed")
    }
}

impl std::error::Error for MacError {}

/// 32-byte HMAC-SHA256 output tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HmacOutput(pub(super) [u8; 32]);

impl HmacOutput {
    /// Returns the raw 32-byte HMAC tag.
    #[must_use]
    pub fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl AsRef<[u8]> for HmacOutput {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<HmacOutput> for [u8; 32] {
    fn from(output: HmacOutput) -> Self {
        output.0
    }
}

/// Base64 URL safe encoding without padding
/// `base64_encode_url_safe_no_pad(input)`
///
/// # Arguments
/// * `input` - A byte slice to be encoded
///
/// # Returns
/// A `String` containing the Base64 URL safe encoded representation of the input data
pub fn base64_encode_url_safe_no_pad(input: &[u8]) -> String {
    base64_simd::URL_SAFE_NO_PAD.encode_to_string(input)
}

/// Base64 URL safe decoding without padding
/// `base64_decode_url_safe_no_pad(input)`
///
/// # Arguments
/// * `input` - A byte slice containing the Base64 URL safe encoded data
///
/// # Returns
/// A `Result` containing a `Vec<u8>` with the decoded data or a `base64_simd::Error` if decoding fails
///
/// # Errors
/// This function will return an error if the input data is not valid Base64 URL safe encoded data
///
pub fn base64_decode_url_safe_no_pad(input: &[u8]) -> Result<Vec<u8>, base64_simd::Error> {
    base64_simd::URL_SAFE_NO_PAD.decode_to_vec(input)
}

/// encode to hex string (lowercase)
/// `hex(data)`
///
/// # Arguments
/// * `data` - A byte slice to be encoded
///
/// # Returns
/// A `String` containing the hexadecimal representation of the input data in lowercase
///
pub fn hex(data: impl AsRef<[u8]>) -> String {
    hex_simd::encode_to_string(data, hex_simd::AsciiCase::Lower)
}

/// verify sha256 checksum string
///
/// # Arguments
/// * `s` - A string slice to be verified
///
/// # Returns
/// A `bool` indicating whether the input string is exactly 64 lowercase hexadecimal characters.
/// Uppercase hexadecimal characters are not accepted.
pub fn is_sha256_checksum(s: &str) -> bool {
    let is_lowercase_hex = |c: u8| matches!(c, b'0'..=b'9' | b'a'..=b'f');
    s.len() == 64 && s.as_bytes().iter().copied().all(is_lowercase_hex)
}

/// HMAC-SHA256 hashing
/// `hmac_sha256(key, data)`
///
/// # Arguments
/// * `key` - A byte slice representing the HMAC key
/// * `data` - A byte slice representing the data to be hashed
///
/// # Returns
/// A 32-byte array containing the HMAC-SHA256 hash of the input data using the provided key
///
pub fn hmac_sha256(key: impl AsRef<[u8]>, data: impl AsRef<[u8]>) -> [u8; 32] {
    let mut m = HmacSha256::new_from_slice(key.as_ref()).expect("operation should succeed");
    m.update(data.as_ref());
    m.finalize().into_bytes()
}

/// `f(hex(src))`
fn hex_bytes32<R>(src: impl AsRef<[u8]>, f: impl FnOnce(&str) -> R) -> R {
    let buf: &mut [_] = &mut [MaybeUninit::uninit(); 64];
    let ans = hex_simd::encode_as_str(src.as_ref(), buf.as_out(), AsciiCase::Lower);
    f(ans)
}

/// Computes the one-shot SHA-256 digest of `data`.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data)
}

fn sha256_chunk(chunk: &[Bytes]) -> [u8; 32] {
    let mut h = Sha256::new();
    chunk.iter().for_each(|data| h.update(data));
    h.finalize()
}

/// hex of sha256 `f(hex(sha256(data)))`
///
/// # Arguments
/// * `data` - A byte slice representing the data to be hashed
/// * `f` - A closure that takes a string slice and returns a value of type `R`
///
/// # Returns
/// A value of type `R` returned by the closure `f` after processing the hexadecimal
/// representation of the SHA-256 hash of the input data
///
pub fn hex_sha256<R>(data: &[u8], f: impl FnOnce(&str) -> R) -> R {
    hex_bytes32(sha256(data), f)
}

/// `f(hex(sha256(chunk)))`
pub fn hex_sha256_chunk<R>(chunk: &[Bytes], f: impl FnOnce(&str) -> R) -> R {
    hex_bytes32(sha256_chunk(chunk), f)
}

#[test]
fn test_sha256_and_hmac_sha256_rfc4231() {
    let digest = hex_sha256(b"abc", str::to_owned);
    assert_eq!(digest, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    let key = [0x0b_u8; 20];
    let data = b"Hi There";
    let expected_hex = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";
    let mac = hmac_sha256(key, data);
    assert_eq!(hex(mac), expected_hex);

    let mut verifier = HmacSha256::new_from_slice(&key).expect("valid key");
    verifier.update(data);
    assert!(verifier.verify_slice(&mac).is_ok());

    let mut bad_mac = mac;
    bad_mac[0] ^= 0x01;
    let mut verifier_bad = HmacSha256::new_from_slice(&key).expect("valid key");
    verifier_bad.update(data);
    assert!(verifier_bad.verify_slice(&bad_mac).is_err());
}

#[test]
fn test_base64_encoding_decoding() {
    let original_uuid_timestamp = "c0194290-d911-45cb-8e12-79ec563f46a8x1735460504394878000";

    let encoded_string = base64_encode_url_safe_no_pad(original_uuid_timestamp.as_bytes());

    println!("Encoded: {}", encoded_string);

    let decoded_bytes = base64_decode_url_safe_no_pad(encoded_string.as_bytes()).expect("operation should succeed");
    let decoded_string = String::from_utf8(decoded_bytes).expect("operation should succeed");

    assert_eq!(decoded_string, original_uuid_timestamp)
}

#[test]
fn sha256_checksum_accepts_exact_lowercase_hex() {
    assert!(is_sha256_checksum("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
}

#[test]
fn sha256_checksum_rejects_wrong_length_or_non_lowercase_hex() {
    assert!(!is_sha256_checksum("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde"));
    assert!(!is_sha256_checksum("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0"));
    assert!(!is_sha256_checksum("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg"));
    assert!(!is_sha256_checksum("0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef"));
}
