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

//! FIPS-validated `aws-lc-rs` backend for `rustfs_utils::crypto`.

use super::{HmacOutput, InvalidKeyLength, MacError};
use aws_lc_rs::{
    constant_time,
    digest::{self, Context as DigestContext, SHA1_FOR_LEGACY_USE_ONLY, SHA256},
    hmac::{self, Context as HmacContext, HMAC_SHA1_FOR_LEGACY_USE_ONLY, HMAC_SHA256, Key},
};

/// Incremental SHA-256 hasher and one-shot digest helper backed by `aws-lc-rs`.
#[derive(Clone)]
pub struct Sha256(DigestContext);

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

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
        Self(DigestContext::new(&SHA256))
    }

    /// Feeds `data` into the hasher.
    pub fn update(&mut self, data: impl AsRef<[u8]>) {
        self.0.update(data.as_ref());
    }

    /// Finalizes the hasher and returns the 32-byte SHA-256 digest.
    #[must_use]
    pub fn finalize(self) -> [u8; 32] {
        self.0
            .finish()
            .as_ref()
            .try_into()
            .expect("SHA-256 digest is always 32 bytes")
    }

    /// Resets the hasher to its initial state.
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Computes the SHA-256 digest of `data` in one shot.
    #[must_use]
    pub fn digest(data: impl AsRef<[u8]>) -> [u8; 32] {
        digest::digest(&SHA256, data.as_ref())
            .as_ref()
            .try_into()
            .expect("SHA-256 digest is always 32 bytes")
    }

    /// Returns the SHA-256 output size in bytes (32).
    #[must_use]
    pub const fn output_size() -> usize {
        Self::OUTPUT_SIZE
    }
}

/// Incremental HMAC-SHA256 signer and verifier backed by `aws-lc-rs`.
#[derive(Clone)]
pub struct HmacSha256(HmacContext);

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
        let signing_key = Key::new(HMAC_SHA256, key);
        Ok(Self(HmacContext::with_key(&signing_key)))
    }

    /// Feeds `data` into the MAC state.
    pub fn update(&mut self, data: impl AsRef<[u8]>) {
        self.0.update(data.as_ref());
    }

    /// Finalizes the MAC and returns the 32-byte output tag.
    #[must_use]
    pub fn finalize(self) -> HmacOutput {
        let tag = self.0.sign();
        HmacOutput(tag.as_ref().try_into().expect("HMAC-SHA256 tag is always 32 bytes"))
    }

    /// Verifies that the computed MAC equals `tag` in constant time.
    pub fn verify_slice(self, tag: &[u8]) -> Result<(), MacError> {
        let computed = self.0.sign();
        constant_time::verify_slices_are_equal(computed.as_ref(), tag).map_err(|_| MacError)
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
    let _ = &SHA1_FOR_LEGACY_USE_ONLY;
    let signing_key = Key::new(HMAC_SHA1_FOR_LEGACY_USE_ONLY, key.as_ref());
    let tag = hmac::sign(&signing_key, data.as_ref());
    tag.as_ref().try_into().expect("HMAC-SHA1 tag is always 20 bytes")
}

#[cfg(test)]
mod tests {
    #[test]
    fn fips_backend_runs_in_aws_lc_fips_mode() {
        aws_lc_rs::try_fips_mode().expect("aws-lc-rs FIPS mode must be active when `rustfs-utils/fips` is enabled");
    }
}
