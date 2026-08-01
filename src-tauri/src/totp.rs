//! Steam Guard TOTP: auth codes, confirmation keys, device IDs.
//!
//! Steam uses a variant of RFC 6238: the same HMAC-SHA1 dynamic truncation,
//! but the truncated value is rendered in base-26 over an alphabet that drops
//! visually ambiguous characters, five characters per code, on a 30s step.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use hmac::{Hmac, Mac};
use sha1::{Digest, Sha1};

type HmacSha1 = Hmac<Sha1>;

pub const CODE_ALPHABET: &[u8] = b"23456789BCDFGHJKMNPQRTVWXY";
pub const CODE_LENGTH: usize = 5;
pub const STEP_SECONDS: i64 = 30;

#[derive(Debug, PartialEq, Eq)]
pub enum SecretError {
    Empty,
    Malformed,
}

impl std::fmt::Display for SecretError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecretError::Empty => write!(f, "secret is empty"),
            SecretError::Malformed => write!(f, "secret is not valid base64 or hex"),
        }
    }
}

/// Accept a shared/identity secret as base64 or hex.
pub fn decode_secret(secret: &str) -> Result<Vec<u8>, SecretError> {
    let text = secret.trim();
    if text.is_empty() {
        return Err(SecretError::Empty);
    }

    // A 20-byte secret is 28 base64 chars or 40 hex chars; hex is unambiguous.
    if text.len() == 40 {
        if let Ok(raw) = hex::decode(text) {
            return Ok(raw);
        }
    }

    match BASE64.decode(text) {
        Ok(raw) if !raw.is_empty() => Ok(raw),
        _ => Err(SecretError::Malformed),
    }
}

/// The 5-character Steam Guard code for a given unix timestamp.
pub fn generate_auth_code(shared_secret: &str, timestamp: i64) -> Result<String, SecretError> {
    let key = decode_secret(shared_secret)?;
    let counter = timestamp.div_euclid(STEP_SECONDS) as u64;

    let mut mac = HmacSha1::new_from_slice(&key).map_err(|_| SecretError::Malformed)?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();

    let start = (digest[digest.len() - 1] & 0x0F) as usize;
    let mut value = u32::from_be_bytes([
        digest[start],
        digest[start + 1],
        digest[start + 2],
        digest[start + 3],
    ]) & 0x7FFF_FFFF;

    let mut code = String::with_capacity(CODE_LENGTH);
    for _ in 0..CODE_LENGTH {
        code.push(CODE_ALPHABET[(value % CODE_ALPHABET.len() as u32) as usize] as char);
        value /= CODE_ALPHABET.len() as u32;
    }
    Ok(code)
}

/// Seconds left before the current code rolls over.
pub fn seconds_remaining(timestamp: i64) -> i64 {
    STEP_SECONDS - timestamp.rem_euclid(STEP_SECONDS)
}

/// Base64 key for the mobile confirmation endpoints (conf, details, allow, cancel).
pub fn generate_confirmation_key(
    identity_secret: &str,
    tag: &str,
    timestamp: i64,
) -> Result<String, SecretError> {
    let key = decode_secret(identity_secret)?;
    let mut mac = HmacSha1::new_from_slice(&key).map_err(|_| SecretError::Malformed)?;

    mac.update(&(timestamp as u64).to_be_bytes());
    if !tag.is_empty() {
        let bytes = tag.as_bytes();
        mac.update(&bytes[..bytes.len().min(32)]);
    }
    Ok(BASE64.encode(mac.finalize().into_bytes()))
}

/// The Android device ID Steam expects alongside confirmation requests.
pub fn device_id(steamid: &str) -> String {
    let digest = Sha1::digest(steamid.as_bytes());
    let hex = hex::encode(digest);
    format!(
        "android:{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // The same throwaway secret and expected codes the Python implementation
    // was pinned to, which were cross-checked against an independent .NET
    // HMACSHA1. Matching them proves this port is bit-for-bit equivalent.
    const SECRET: &str = "cnOgv/KdpLoP6Nbh0GMkXkPXALQ=";
    const KNOWN: [(i64, &str); 4] = [
        (0, "W3J46"),
        (1_600_000_000, "H6G3P"),
        (1_616_374_841, "FCCHM"),
        (2_000_000_000, "68J6V"),
    ];

    #[test]
    fn matches_the_python_and_dotnet_vectors() {
        for (timestamp, expected) in KNOWN {
            assert_eq!(generate_auth_code(SECRET, timestamp).unwrap(), expected);
        }
    }

    #[test]
    fn code_shape_is_five_chars_from_the_alphabet() {
        let code = generate_auth_code(SECRET, 1_600_000_000).unwrap();
        assert_eq!(code.len(), CODE_LENGTH);
        assert!(code.bytes().all(|b| CODE_ALPHABET.contains(&b)));
    }

    #[test]
    fn alphabet_excludes_ambiguous_characters() {
        assert_eq!(CODE_ALPHABET.len(), 26);
        for c in b"01AEILOSUZ" {
            assert!(!CODE_ALPHABET.contains(c));
        }
    }

    #[test]
    fn code_is_stable_within_a_step_and_changes_after() {
        let base = 1_600_000_020; // divisible by 30
        assert_eq!(
            generate_auth_code(SECRET, base).unwrap(),
            generate_auth_code(SECRET, base + 29).unwrap()
        );
        assert_ne!(
            generate_auth_code(SECRET, base).unwrap(),
            generate_auth_code(SECRET, base + 30).unwrap()
        );
    }

    #[test]
    fn hex_and_base64_secrets_agree() {
        let raw = BASE64.decode(SECRET).unwrap();
        assert_eq!(
            generate_auth_code(&hex::encode(&raw), 1_600_000_000).unwrap(),
            "H6G3P"
        );
    }

    #[test]
    fn bad_secrets_are_rejected() {
        assert_eq!(decode_secret(""), Err(SecretError::Empty));
        assert_eq!(decode_secret("   "), Err(SecretError::Empty));
        assert_eq!(decode_secret("not base64!!"), Err(SecretError::Malformed));
    }

    #[test]
    fn seconds_remaining_counts_down_within_the_step() {
        assert_eq!(seconds_remaining(1_600_000_020), 30);
        assert_eq!(seconds_remaining(1_600_000_049), 1);
    }

    #[test]
    fn confirmation_keys_match_the_python_vectors() {
        assert_eq!(
            generate_confirmation_key(SECRET, "conf", 1_600_000_000).unwrap(),
            "BC2NgWevGICPmDom0k0/EyoHDLQ="
        );
        assert_eq!(
            generate_confirmation_key(SECRET, "allow", 1_600_000_000).unwrap(),
            "FBLyXhsXoQ8CrLErKL8fdCWvq1w="
        );
    }

    #[test]
    fn device_id_matches_the_python_vector() {
        assert_eq!(
            device_id("76561198000000000"),
            "android:5c9df5a2-d7de-1e2c-8fc8-766523ca130f"
        );
    }
}
