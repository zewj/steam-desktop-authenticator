//! Reading .maFile account files, including SDA's encrypted-at-rest format.
//!
//! An .maFile is JSON holding shared_secret and identity_secret. SDA can
//! encrypt it with a passkey; when it does, the file body is base64 ciphertext
//! and the per-account IV and salt live in the manifest.json beside it.

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

const PBKDF2_ITERATIONS: u32 = 50_000;
const KEY_SIZE_BYTES: usize = 32;

#[derive(Debug)]
pub enum MaFileError {
    Io(String),
    NoSecret(String),
    Encrypted(String),
    WrongPasskey,
    Malformed(String),
}

impl std::fmt::Display for MaFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MaFileError::Io(m) => write!(f, "{m}"),
            MaFileError::NoSecret(n) => write!(f, "{n} has no shared_secret"),
            MaFileError::Encrypted(n) => write!(f, "{n} is encrypted; passkey needed"),
            MaFileError::WrongPasskey => write!(f, "wrong passkey"),
            MaFileError::Malformed(m) => write!(f, "{m}"),
        }
    }
}

/// What the UI needs. Secrets stay in the backend: `shared_secret` is never
/// serialised to the frontend, only the codes derived from it.
#[derive(Debug, Clone, Serialize)]
pub struct AccountView {
    pub label: String,
    pub account_name: String,
    pub steamid: String,
    pub revocation_code: String,
    pub device_id: String,
    pub has_identity_secret: bool,
    pub path: String,
}

#[derive(Debug, Clone)]
pub struct Account {
    pub account_name: String,
    pub shared_secret: String,
    pub identity_secret: String,
    pub steamid: String,
    pub revocation_code: String,
    pub device_id: String,
    pub refresh_token: String,
    pub path: PathBuf,
}

impl Account {
    /// The device identifier Steam ties confirmations to. Derived from the
    /// SteamID when the file predates us storing it.
    pub fn effective_device_id(&self) -> String {
        if self.device_id.is_empty() {
            crate::totp::device_id(&self.steamid)
        } else {
            self.device_id.clone()
        }
    }
}

impl Account {
    pub fn label(&self) -> String {
        if !self.account_name.is_empty() {
            return self.account_name.clone();
        }
        if !self.steamid.is_empty() {
            return self.steamid.clone();
        }
        self.path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "account".into())
    }

    pub fn view(&self) -> AccountView {
        AccountView {
            label: self.label(),
            account_name: self.account_name.clone(),
            steamid: self.steamid.clone(),
            revocation_code: self.revocation_code.clone(),
            device_id: if self.device_id.is_empty() && !self.steamid.is_empty() {
                crate::totp::device_id(&self.steamid)
            } else {
                self.device_id.clone()
            },
            has_identity_secret: !self.identity_secret.is_empty(),
            path: self.path.to_string_lossy().to_string(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct RawSession {
    #[serde(default, alias = "steamid", alias = "SteamID")]
    steam_id: Option<serde_json::Value>,
    /// Written at enrollment. Confirmations need a steamcommunity.com session,
    /// which this is exchanged for; codes alone never touch it.
    #[serde(default, alias = "oauth_token", alias = "OAuthToken")]
    oauth_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawMaFile {
    #[serde(default, alias = "AccountName")]
    account_name: Option<String>,
    #[serde(default, alias = "SharedSecret")]
    shared_secret: Option<String>,
    #[serde(default, alias = "IdentitySecret")]
    identity_secret: Option<String>,
    #[serde(default, alias = "RevocationCode")]
    revocation_code: Option<String>,
    #[serde(default, alias = "DeviceID")]
    device_id: Option<String>,
    #[serde(default)]
    steamid: Option<serde_json::Value>,
    #[serde(default, alias = "session")]
    #[serde(rename = "Session")]
    session: Option<RawSession>,
}

fn value_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        _ => String::new(),
    }
}

fn parse_account(text: &str, path: &Path) -> Result<Account, MaFileError> {
    let raw: RawMaFile =
        serde_json::from_str(text).map_err(|e| MaFileError::Malformed(e.to_string()))?;

    let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
    let shared_secret = raw.shared_secret.unwrap_or_default();
    if shared_secret.is_empty() {
        return Err(MaFileError::NoSecret(name));
    }

    let steamid = raw
        .steamid
        .as_ref()
        .map(value_to_string)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            raw.session
                .as_ref()
                .and_then(|s| s.steam_id.as_ref())
                .map(value_to_string)
        })
        .unwrap_or_default();

    Ok(Account {
        account_name: raw.account_name.unwrap_or_default(),
        shared_secret,
        identity_secret: raw.identity_secret.unwrap_or_default(),
        steamid,
        revocation_code: raw.revocation_code.unwrap_or_default(),
        device_id: raw.device_id.unwrap_or_default(),
        refresh_token: raw
            .session
            .as_ref()
            .and_then(|s| s.oauth_token.clone())
            .unwrap_or_default(),
        path: path.to_path_buf(),
    })
}

pub fn derive_key(passkey: &str, salt_b64: &str) -> Result<Vec<u8>, MaFileError> {
    let salt = BASE64
        .decode(salt_b64)
        .map_err(|_| MaFileError::Malformed("bad salt".into()))?;
    let mut key = vec![0u8; KEY_SIZE_BYTES];
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(passkey.as_bytes(), &salt, PBKDF2_ITERATIONS, &mut key);
    Ok(key)
}

/// Reverse SDA's AES-256-CBC encryption of an .maFile body.
pub fn decrypt(
    ciphertext_b64: &str,
    passkey: &str,
    iv_b64: &str,
    salt_b64: &str,
) -> Result<String, MaFileError> {
    let key = derive_key(passkey, salt_b64)?;
    let iv = BASE64
        .decode(iv_b64)
        .map_err(|_| MaFileError::Malformed("bad iv".into()))?;
    let mut buffer = BASE64
        .decode(ciphertext_b64.trim())
        .map_err(|_| MaFileError::Malformed("body is not base64".into()))?;

    let cipher = Aes256CbcDec::new_from_slices(&key, &iv)
        .map_err(|_| MaFileError::Malformed("bad key or iv length".into()))?;
    let plain = cipher
        .decrypt_padded_mut::<Pkcs7>(&mut buffer)
        .map_err(|_| MaFileError::WrongPasskey)?;

    String::from_utf8(plain.to_vec()).map_err(|_| MaFileError::WrongPasskey)
}

#[derive(Debug, Deserialize)]
struct ManifestEntry {
    #[serde(default)]
    filename: Option<String>,
    #[serde(default)]
    encryption_iv: Option<String>,
    #[serde(default)]
    encryption_salt: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Manifest {
    #[serde(default)]
    entries: Vec<ManifestEntry>,
}

fn read_manifest(dir: &Path) -> Option<Manifest> {
    let text = std::fs::read_to_string(dir.join("manifest.json")).ok()?;
    serde_json::from_str(text.trim_start_matches('\u{feff}')).ok()
}

fn crypto_params(path: &Path) -> (Option<String>, Option<String>) {
    let Some(dir) = path.parent() else {
        return (None, None);
    };
    let Some(manifest) = read_manifest(dir) else {
        return (None, None);
    };
    let target = path
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    for entry in manifest.entries {
        let name = entry
            .filename
            .as_deref()
            .and_then(|f| Path::new(f).file_name().map(|n| n.to_string_lossy().to_lowercase()));
        if name.as_deref() == Some(target.as_str()) {
            return (entry.encryption_iv, entry.encryption_salt);
        }
    }
    (None, None)
}

/// Load one .maFile, decrypting it if needed.
pub fn load_mafile(path: &Path, passkey: Option<&str>) -> Result<Account, MaFileError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| MaFileError::Io(format!("{}: {e}", path.display())))?;
    let text = text.trim_start_matches('\u{feff}').trim();

    // Plaintext JSON is the common case.
    if let Ok(account) = parse_account(text, path) {
        return Ok(account);
    }
    if serde_json::from_str::<serde_json::Value>(text).is_ok() {
        // Valid JSON that simply lacks a secret: report that, not "encrypted".
        return parse_account(text, path);
    }

    let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
    let (iv, salt) = crypto_params(path);
    let (Some(iv), Some(salt)) = (iv, salt) else {
        return Err(MaFileError::Malformed(format!(
            "{name} looks encrypted but manifest.json has no IV/salt for it"
        )));
    };
    let Some(passkey) = passkey.filter(|p| !p.is_empty()) else {
        return Err(MaFileError::Encrypted(name));
    };

    let plaintext = decrypt(text, passkey, &iv, &salt)?;
    parse_account(&plaintext, path).map_err(|_| MaFileError::WrongPasskey)
}

/// Load every .maFile in a directory. Returns (accounts, error messages).
pub fn load_directory(dir: &Path, passkey: Option<&str>) -> (Vec<Account>, Vec<String>) {
    let mut names: Vec<String> = Vec::new();

    if let Some(manifest) = read_manifest(dir) {
        for entry in manifest.entries {
            if let Some(file) = entry.filename {
                if let Some(name) = Path::new(&file).file_name() {
                    names.push(name.to_string_lossy().to_string());
                }
            }
        }
    }

    if let Ok(read) = std::fs::read_dir(dir) {
        let mut found: Vec<String> = read
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.to_lowercase().ends_with(".mafile"))
            .collect();
        found.sort();
        for name in found {
            if !names.contains(&name) {
                names.push(name);
            }
        }
    }

    let mut accounts = Vec::new();
    let mut errors = Vec::new();
    for name in names {
        let path = dir.join(&name);
        if !path.is_file() {
            errors.push(format!("{name}: listed in manifest.json but missing"));
            continue;
        }
        match load_mafile(&path, passkey) {
            Ok(account) => accounts.push(account),
            Err(e) => errors.push(e.to_string()),
        }
    }
    (accounts, errors)
}

/// Places an existing SDA install tends to keep maFiles.
pub fn default_directories() -> Vec<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();

    if let Ok(exe) = std::env::current_exe() {
        // Alongside the app, and one level up: during `tauri dev` the binary
        // lives in target/debug, so also try the project folder.
        for ancestor in exe.ancestors().take(6) {
            candidates.push(ancestor.join("maFiles"));
        }
    }
    if let Ok(home) = std::env::var("USERPROFILE") {
        let desktop = Path::new(&home).join("Desktop");
        candidates.push(desktop.join("maFiles"));
        candidates.push(Path::new(&home).join("maFiles"));

        // Any folder on the Desktop holding a maFiles child. A portable build
        // run from Downloads is nowhere near the account files, and walking up
        // from the executable will never reach them.
        if let Ok(entries) = std::fs::read_dir(&desktop) {
            for entry in entries.flatten().take(128) {
                let nested = entry.path().join("maFiles");
                if nested.is_dir() {
                    candidates.push(nested);
                }
            }
        }
    }
    if let Ok(appdata) = std::env::var("APPDATA") {
        candidates.push(
            Path::new(&appdata)
                .join("SteamDesktopAuthenticator")
                .join("maFiles"),
        );
    }

    let mut seen = Vec::new();
    let mut out = Vec::new();
    for path in candidates {
        let key = path.to_string_lossy().to_lowercase();
        if !seen.contains(&key) && path.is_dir() {
            seen.push(key);
            out.push(path);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::{block_padding::Pkcs7 as Pad, BlockEncryptMut};

    type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

    const SECRET: &str = "cnOgv/KdpLoP6Nbh0GMkXkPXALQ=";

    fn plain_json() -> String {
        serde_json::json!({
            "account_name": "testuser",
            "shared_secret": SECRET,
            "identity_secret": SECRET,
            "revocation_code": "R12345",
            "Session": { "SteamID": 76561198000000000u64 }
        })
        .to_string()
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sda-rs-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn loads_plaintext_mafile() {
        let dir = temp_dir("plain");
        let path = dir.join("a.maFile");
        std::fs::write(&path, plain_json()).unwrap();

        let account = load_mafile(&path, None).unwrap();
        assert_eq!(account.account_name, "testuser");
        assert_eq!(account.shared_secret, SECRET);
        assert_eq!(account.steamid, "76561198000000000");
        assert_eq!(account.label(), "testuser");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_secret_is_an_error() {
        let dir = temp_dir("nosecret");
        let path = dir.join("b.maFile");
        std::fs::write(&path, r#"{"account_name":"x"}"#).unwrap();
        assert!(matches!(
            load_mafile(&path, None),
            Err(MaFileError::NoSecret(_))
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn encrypted_round_trip_matches_sda_format() {
        let dir = temp_dir("enc");
        let iv = [7u8; 16];
        let salt = [9u8; 8];
        let iv_b64 = BASE64.encode(iv);
        let salt_b64 = BASE64.encode(salt);
        let passkey = "hunter2";

        let key = derive_key(passkey, &salt_b64).unwrap();
        let plaintext = plain_json();
        let mut buffer = vec![0u8; plaintext.len() + 16];
        buffer[..plaintext.len()].copy_from_slice(plaintext.as_bytes());
        let encrypted = Aes256CbcEnc::new_from_slices(&key, &iv)
            .unwrap()
            .encrypt_padded_mut::<Pad>(&mut buffer, plaintext.len())
            .unwrap();
        let body = BASE64.encode(encrypted);

        let path = dir.join("c.maFile");
        std::fs::write(&path, &body).unwrap();
        std::fs::write(
            dir.join("manifest.json"),
            serde_json::json!({
                "encrypted": true,
                "entries": [{
                    "filename": "c.maFile",
                    "encryption_iv": iv_b64,
                    "encryption_salt": salt_b64
                }]
            })
            .to_string(),
        )
        .unwrap();

        let account = load_mafile(&path, Some(passkey)).unwrap();
        assert_eq!(account.shared_secret, SECRET);

        assert!(matches!(
            load_mafile(&path, None),
            Err(MaFileError::Encrypted(_))
        ));
        assert!(matches!(
            load_mafile(&path, Some("wrong")),
            Err(MaFileError::WrongPasskey)
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn directory_load_reports_errors_without_failing() {
        let dir = temp_dir("mixed");
        std::fs::write(dir.join("good.maFile"), plain_json()).unwrap();
        std::fs::write(dir.join("bad.maFile"), r#"{"account_name":"x"}"#).unwrap();

        let (accounts, errors) = load_directory(&dir, None);
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].account_name, "testuser");
        assert_eq!(errors.len(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn account_view_never_carries_secrets() {
        let dir = temp_dir("view");
        let path = dir.join("v.maFile");
        std::fs::write(&path, plain_json()).unwrap();

        let view = load_mafile(&path, None).unwrap().view();
        let json = serde_json::to_string(&view).unwrap();
        assert!(!json.contains(SECRET), "secret leaked into the UI payload");
        assert!(view.has_identity_secret);
        std::fs::remove_dir_all(&dir).ok();
    }
}
