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
#[cfg(not(feature = "aws-lc-rs"))]
use hmac::{Hmac, KeyInit, Mac};
use hyper::body::Bytes;
#[cfg(not(feature = "aws-lc-rs"))]
use sha1::Sha1;
#[cfg(not(feature = "aws-lc-rs"))]
use sha2::Digest;
use std::mem::MaybeUninit;

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
pub struct HmacOutput([u8; 32]);

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

/// Incremental SHA-256 hasher and one-shot digest helper.
#[cfg(feature = "aws-lc-rs")]
#[derive(Clone)]
pub struct Sha256(aws_lc_rs::digest::Context);

#[cfg(feature = "aws-lc-rs")]
impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

/// Incremental SHA-256 hasher and one-shot digest helper.
#[cfg(not(feature = "aws-lc-rs"))]
#[derive(Clone, Default)]
pub struct Sha256(sha2::Sha256);

impl std::fmt::Debug for Sha256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sha256").finish_non_exhaustive()
    }
}

impl Sha256 {
    /// Size of a SHA-256 digest in bytes.
    pub const OUTPUT_SIZE: usize = 32;

    /// Creates a new incremental SHA-256 hasher.
    #[must_use]
    pub fn new() -> Self {
        #[cfg(feature = "aws-lc-rs")]
        {
            Self(aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256))
        }
        #[cfg(not(feature = "aws-lc-rs"))]
        {
            Self(<sha2::Sha256 as Digest>::new())
        }
    }

    /// Feeds `data` into the hasher.
    pub fn update(&mut self, data: impl AsRef<[u8]>) {
        self.0.update(data.as_ref());
    }

    /// Finalizes the hasher and returns the 32-byte SHA-256 digest.
    #[must_use]
    pub fn finalize(self) -> [u8; 32] {
        #[cfg(feature = "aws-lc-rs")]
        {
            self.0
                .finish()
                .as_ref()
                .try_into()
                .expect("SHA-256 digest is always 32 bytes")
        }
        #[cfg(not(feature = "aws-lc-rs"))]
        {
            self.0.finalize().into()
        }
    }

    /// Resets the hasher to its initial state.
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Computes the SHA-256 digest of `data` in one shot.
    #[must_use]
    pub fn digest(data: impl AsRef<[u8]>) -> [u8; 32] {
        #[cfg(feature = "aws-lc-rs")]
        {
            aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, data.as_ref())
                .as_ref()
                .try_into()
                .expect("SHA-256 digest is always 32 bytes")
        }
        #[cfg(not(feature = "aws-lc-rs"))]
        {
            <sha2::Sha256 as Digest>::digest(data.as_ref()).into()
        }
    }

    /// Returns the SHA-256 output size in bytes (32).
    #[must_use]
    pub const fn output_size() -> usize {
        Self::OUTPUT_SIZE
    }
}

/// Incremental HMAC-SHA256 signer and verifier.
#[cfg(feature = "aws-lc-rs")]
#[derive(Clone)]
pub struct HmacSha256(aws_lc_rs::hmac::Context);

/// Incremental HMAC-SHA256 signer and verifier.
#[cfg(not(feature = "aws-lc-rs"))]
#[derive(Clone)]
pub struct HmacSha256(Hmac<sha2::Sha256>);

impl std::fmt::Debug for HmacSha256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HmacSha256").finish_non_exhaustive()
    }
}

impl HmacSha256 {
    /// Creates a new HMAC-SHA256 instance from `key`.
    #[must_use]
    pub fn new(key: impl AsRef<[u8]>) -> Self {
        Self::new_from_slice(key.as_ref()).expect("HMAC accepts keys of any length")
    }

    /// Creates a new HMAC-SHA256 instance from `key`.
    pub fn new_from_slice(key: &[u8]) -> Result<Self, InvalidKeyLength> {
        #[cfg(feature = "aws-lc-rs")]
        {
            let signing_key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, key);
            Ok(Self(aws_lc_rs::hmac::Context::with_key(&signing_key)))
        }
        #[cfg(not(feature = "aws-lc-rs"))]
        {
            <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(key)
                .map(Self)
                .map_err(|_| InvalidKeyLength)
        }
    }

    /// Feeds `data` into the MAC state.
    pub fn update(&mut self, data: impl AsRef<[u8]>) {
        self.0.update(data.as_ref());
    }

    /// Finalizes the MAC and returns the 32-byte output tag.
    #[must_use]
    pub fn finalize(self) -> HmacOutput {
        #[cfg(feature = "aws-lc-rs")]
        {
            let tag = self.0.sign();
            HmacOutput(tag.as_ref().try_into().expect("HMAC-SHA256 tag is always 32 bytes"))
        }
        #[cfg(not(feature = "aws-lc-rs"))]
        {
            HmacOutput(self.0.finalize().into_bytes().into())
        }
    }

    /// Verifies that the computed MAC equals `tag` in constant time.
    pub fn verify_slice(self, tag: &[u8]) -> Result<(), MacError> {
        #[cfg(feature = "aws-lc-rs")]
        {
            let computed = self.0.sign();
            aws_lc_rs::constant_time::verify_slices_are_equal(computed.as_ref(), tag).map_err(|_| MacError)
        }
        #[cfg(not(feature = "aws-lc-rs"))]
        {
            self.0.verify_slice(tag).map_err(|_| MacError)
        }
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

/// HMAC-SHA1 hashing
/// `hmac_sha1(key, data)`
///
/// # Arguments
/// * `key` - A byte slice representing the HMAC key
/// * `data` - A byte slice representing the data to be hashed
///
/// # Returns
/// A 20-byte array containing the HMAC-SHA1 hash of the input data using the provided key
///
pub fn hmac_sha1(key: impl AsRef<[u8]>, data: impl AsRef<[u8]>) -> [u8; 20] {
    #[cfg(feature = "aws-lc-rs")]
    {
        let signing_key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key.as_ref());
        let tag = aws_lc_rs::hmac::sign(&signing_key, data.as_ref());
        tag.as_ref().try_into().expect("HMAC-SHA1 tag is always 20 bytes")
    }
    #[cfg(not(feature = "aws-lc-rs"))]
    {
        let mut m = <Hmac<Sha1>>::new_from_slice(key.as_ref()).expect("operation should succeed");
        m.update(data.as_ref());
        m.finalize().into_bytes().into()
    }
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
