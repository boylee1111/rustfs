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

//! Default RustCrypto (`sha2`, `hmac`, `sha1`) backend for `rustfs_utils::crypto`.

use super::{HmacOutput, InvalidKeyLength, MacError};
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::Digest;

/// Incremental SHA-256 hasher and one-shot digest helper.
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
        Self(<sha2::Sha256 as Digest>::new())
    }

    /// Feeds `data` into the hasher.
    pub fn update(&mut self, data: impl AsRef<[u8]>) {
        self.0.update(data.as_ref());
    }

    /// Finalizes the hasher and returns the 32-byte SHA-256 digest.
    #[must_use]
    pub fn finalize(self) -> [u8; 32] {
        self.0.finalize().into()
    }

    /// Resets the hasher to its initial state.
    pub fn reset(&mut self) {
        Digest::reset(&mut self.0);
    }

    /// Computes the SHA-256 digest of `data` in one shot.
    #[must_use]
    pub fn digest(data: impl AsRef<[u8]>) -> [u8; 32] {
        <sha2::Sha256 as Digest>::digest(data.as_ref()).into()
    }

    /// Returns the SHA-256 output size in bytes (32).
    #[must_use]
    pub const fn output_size() -> usize {
        Self::OUTPUT_SIZE
    }
}

/// Incremental HMAC-SHA256 signer and verifier.
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
        <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(key)
            .map(Self)
            .map_err(|_| InvalidKeyLength)
    }

    /// Feeds `data` into the MAC state.
    pub fn update(&mut self, data: impl AsRef<[u8]>) {
        self.0.update(data.as_ref());
    }

    /// Finalizes the MAC and returns the 32-byte output tag.
    #[must_use]
    pub fn finalize(self) -> HmacOutput {
        HmacOutput(self.0.finalize().into_bytes().into())
    }

    /// Verifies that the computed MAC equals `tag` in constant time.
    pub fn verify_slice(self, tag: &[u8]) -> Result<(), MacError> {
        self.0.verify_slice(tag).map_err(|_| MacError)
    }
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
pub fn hmac_sha1(key: impl AsRef<[u8]>, data: impl AsRef<[u8]>) -> [u8; 20] {
    let mut m = <Hmac<Sha1>>::new_from_slice(key.as_ref()).expect("operation should succeed");
    m.update(data.as_ref());
    m.finalize().into_bytes().into()
}
