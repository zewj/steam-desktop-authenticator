//! Attaching a new Steam Guard authenticator, producing an .maFile.
//!
//! Ported from the Python implementation that was verified against live Steam.
//! Two things that implementation learned the hard way and are preserved here:
//!
//!   * These endpoints take ordinary form-encoded parameters, not protobuf.
//!   * Failures arrive as HTTP 200 with an empty body and the real code in an
//!     `X-eresult` header. A client that reads only the body sees every
//!     failure as an empty success.
//!
//! AddAuthenticator is the point of no return: Steam considers the
//! authenticator attached the moment it responds, so the .maFile is written
//! and flushed before that call returns.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rsa::{BigUint, Pkcs1v15Encrypt, RsaPublicKey};
use serde::Serialize;
use serde_json::Value;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::State;

const API: &str = "https://api.steampowered.com";
const USER_AGENT: &str =
    "Mozilla/5.0 (Linux; U; Android 9; en-us; Valve Steam App) AppleWebKit/537.36 \
     (KHTML, like Gecko) Mobile Safari/537.36";

pub const GUARD_NONE: i64 = 1;
pub const GUARD_EMAIL_CODE: i64 = 2;
pub const GUARD_DEVICE_CODE: i64 = 3;

fn eresult_name(code: i64) -> &'static str {
    match code {
        2 => "Fail",
        5 => "Incorrect password",
        8 => "Invalid parameter",
        9 => "Login session not found or expired",
        11 => "Invalid state",
        15 => "Access denied",
        16 => "Timeout",
        17 => "Account banned",
        18 => "Account not found",
        20 => "Steam service unavailable",
        21 => "Not logged on",
        25 => "Limit exceeded",
        27 => "Session expired",
        29 => "Duplicate request",
        63 => "Email verification required",
        65 => "Two-factor code mismatch",
        84 => "Rate limited by Steam",
        85 => "Two-factor code required",
        88 => "Confirmation code mismatch",
        _ => "Steam rejected the request",
    }
}

fn add_status_help(status: i64) -> String {
    match status {
        // Not necessarily a missing phone: Steam confirms by email when no
        // phone is attached, and accounts without one enroll fine.
        2 => "Steam refused to add an authenticator. The account may be too new, \
              or restricted from changing Steam Guard right now. Waiting and \
              retrying usually clears it."
            .into(),
        29 => "This account already has an authenticator attached. Remove it from the \
               Steam mobile app first, or use its revocation code."
            .into(),
        84 => "Steam is rate limiting this account. Wait a while before retrying.".into(),
        other => format!("Steam refused to add the authenticator (status {other})."),
    }
}

#[derive(Debug)]
pub struct SteamError {
    pub message: String,
    pub eresult: Option<i64>,
}

impl std::fmt::Display for SteamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl SteamError {
    fn new(message: impl Into<String>) -> Self {
        Self { message: message.into(), eresult: None }
    }
    fn with_code(message: impl Into<String>, eresult: i64) -> Self {
        Self { message: message.into(), eresult: Some(eresult) }
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Which verb an endpoint takes.
///
/// Steam serves the RSA public key over GET only and answers a POST with
/// HTTP 405. Deriving the verb from the path keeps that knowledge in one
/// place — losing it at a call site is exactly how it broke once already.
fn is_get_endpoint(path: &str) -> bool {
    path.contains("GetPasswordRSAPublicKey")
}

/// Call a Steam WebAPI method and return the `response` object.
pub(crate) async fn call(
    path: &str,
    params: &[(&str, String)],
    access_token: Option<&str>,
) -> Result<Value, SteamError> {
    let encoded = params
        .iter()
        .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&");

    let mut url = format!("{API}{path}");
    let mut query: Vec<String> = Vec::new();
    if let Some(token) = access_token {
        query.push(format!("access_token={}", urlencoding::encode(token)));
    }
    if is_get_endpoint(path) && !encoded.is_empty() {
        query.push(encoded.clone());
    }
    if !query.is_empty() {
        url.push('?');
        url.push_str(&query.join("&"));
    }

    let client = reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .build()
        .map_err(|e| SteamError::new(format!("could not build HTTP client: {e}")))?;

    let request = if is_get_endpoint(path) {
        client.get(&url)
    } else {
        // Encode the body by hand and set Content-Length explicitly. reqwest
        // omits the header for an empty form, and Steam answers a POST without
        // it with HTTP 411 Length Required — how QueryTime failed with no params.
        client
            .post(&url)
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .header(reqwest::header::CONTENT_LENGTH, encoded.len().to_string())
            .body(encoded)
    };

    let response = request
        .send()
        .await
        .map_err(|e| SteamError::new(format!("Could not reach Steam: {e}")))?;

    if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        return Err(SteamError::with_code(
            "Steam rejected the login token (401). It may have expired — start the login again.",
            15,
        ));
    }

    let eresult = response
        .headers()
        .get("x-eresult")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<i64>().ok());
    let error_message = response
        .headers()
        .get("x-error_message")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let status = response.status();
    let body = response.text().await.unwrap_or_default();

    if let Some(code) = eresult {
        if code != 1 {
            let label = error_message.unwrap_or_else(|| eresult_name(code).to_string());
            return Err(SteamError::with_code(label, code));
        }
    } else if !status.is_success() {
        return Err(SteamError::new(format!("HTTP {status} from {path}")));
    }

    if body.is_empty() {
        return Ok(Value::Object(Default::default()));
    }
    let parsed: Value = serde_json::from_str(&body)
        .map_err(|_| SteamError::new(format!("Unreadable reply from {path}")))?;
    Ok(parsed.get("response").cloned().unwrap_or(Value::Object(Default::default())))
}

/// Seconds to add to the local clock to match Steam's.
pub async fn query_time_offset() -> Result<i64, SteamError> {
    let before = now();
    let response = call("/ITwoFactorService/QueryTime/v1/", &[], None).await?;

    // server_time comes back as a quoted string; str_field handles either form.
    let server: i64 = str_field(&response, "server_time").parse().unwrap_or(0);
    if server == 0 {
        return Err(SteamError::new("Steam returned no server time"));
    }
    // Charge half the round trip to the response leg.
    Ok(server - (before + now()) / 2)
}

pub(crate) fn str_field(value: &Value, key: &str) -> String {
    match value.get(key) {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        _ => String::new(),
    }
}

fn encrypt_password(password: &str, modulus_hex: &str, exponent_hex: &str) -> Result<String, SteamError> {
    let n = BigUint::parse_bytes(modulus_hex.as_bytes(), 16)
        .ok_or_else(|| SteamError::new("bad RSA modulus"))?;
    let e = BigUint::parse_bytes(exponent_hex.as_bytes(), 16)
        .ok_or_else(|| SteamError::new("bad RSA exponent"))?;
    let key = RsaPublicKey::new(n, e).map_err(|e| SteamError::new(format!("bad RSA key: {e}")))?;

    let mut rng = rand::thread_rng();
    let encrypted = key
        .encrypt(&mut rng, Pkcs1v15Encrypt, password.as_bytes())
        .map_err(|e| SteamError::new(format!("could not encrypt password: {e}")))?;
    Ok(BASE64.encode(encrypted))
}

#[derive(Default)]
pub struct Enroller {
    pub account_name: String,
    pub steamid: String,
    pub client_id: String,
    pub request_id: String,
    pub access_token: String,
    pub refresh_token: String,
    pub confirmations: Vec<i64>,
    pub shared_secret: String,
    pub revocation_code: String,
    pub file_path: PathBuf,
}

#[derive(Serialize)]
pub struct BeginResult {
    pub steamid: String,
    pub needs_code: Option<i64>,
    pub summary: String,
}

#[derive(Serialize)]
pub struct EnrollResult {
    pub account_name: String,
    pub steamid: String,
    pub revocation_code: String,
    pub path: String,
    pub phone_hint: String,
}

fn guard_summary(kinds: &[i64]) -> String {
    if kinds.is_empty() {
        return "no confirmation needed".into();
    }
    kinds
        .iter()
        .map(|k| match *k {
            GUARD_EMAIL_CODE => "a code emailed to you",
            GUARD_DEVICE_CODE => "a code from your existing authenticator",
            4 => "approval in the Steam mobile app",
            5 => "approval via a link emailed to you",
            _ => "an unknown step",
        })
        .collect::<Vec<_>>()
        .join("; ")
}

type EnrollState<'a> = State<'a, crate::AppState>;

fn slot<'a>(state: &'a EnrollState<'a>) -> &'a Mutex<Option<Enroller>> {
    &state.enrollment
}

#[tauri::command]
pub async fn begin_login(
    account_name: String,
    password: String,
    state: EnrollState<'_>,
) -> Result<BeginResult, String> {
    if account_name.trim().is_empty() || password.is_empty() {
        return Err("Account name and password are both required.".into());
    }

    let key = call(
        "/IAuthenticationService/GetPasswordRSAPublicKey/v1/",
        &[("account_name", account_name.clone())],
        None,
    )
    .await
    .map_err(|e| e.to_string())?;

    let modulus = str_field(&key, "publickey_mod");
    let exponent = str_field(&key, "publickey_exp");
    if modulus.is_empty() {
        return Err("Steam did not return an encryption key for that account name.".into());
    }
    let encrypted = encrypt_password(&password, &modulus, &exponent).map_err(|e| e.to_string())?;

    // platform_type 3 = mobile app, the session type Steam requires before it
    // will attach an authenticator. device_details is a nested message; both
    // spellings are sent so either form encoding is understood.
    let device = "Steam Desktop Authenticator".to_string();
    let params = vec![
        ("account_name", account_name.clone()),
        ("encrypted_password", encrypted),
        ("encryption_timestamp", str_field(&key, "timestamp")),
        ("remember_login", "1".into()),
        ("persistence", "1".into()),
        ("website_id", "Mobile".into()),
        ("platform_type", "3".into()),
        ("device_friendly_name", device.clone()),
        ("device_details[device_friendly_name]", device),
        ("device_details[platform_type]", "3".into()),
        ("device_details[os_type]", "-500".into()),
    ];

    let session = call(
        "/IAuthenticationService/BeginAuthSessionViaCredentials/v1/",
        &params,
        None,
    )
    .await
    .map_err(|e| e.to_string())?;

    let client_id = str_field(&session, "client_id");
    let request_id = str_field(&session, "request_id");
    if client_id.is_empty() || request_id.is_empty() {
        return Err("Steam accepted the password but returned no login session.".into());
    }

    let confirmations: Vec<i64> = session
        .get("allowed_confirmations")
        .and_then(|v| v.as_array())
        .map(|list| {
            list.iter()
                .filter_map(|c| c.get("confirmation_type").and_then(|t| t.as_i64()))
                .filter(|t| *t != GUARD_NONE)
                .collect()
        })
        .unwrap_or_default();

    let steamid = str_field(&session, "steamid");
    let needs_code = confirmations
        .iter()
        .find(|k| **k == GUARD_EMAIL_CODE || **k == GUARD_DEVICE_CODE)
        .copied();

    let result = BeginResult {
        steamid: steamid.clone(),
        needs_code,
        summary: guard_summary(&confirmations),
    };

    *slot(&state).lock().unwrap() = Some(Enroller {
        account_name,
        steamid,
        client_id,
        request_id,
        confirmations,
        ..Default::default()
    });

    Ok(result)
}

#[tauri::command]
pub async fn submit_guard_code(
    code: String,
    code_type: i64,
    state: EnrollState<'_>,
) -> Result<(), String> {
    let (client_id, steamid) = {
        let guard = slot(&state).lock().unwrap();
        let e = guard.as_ref().ok_or("no login in progress")?;
        (e.client_id.clone(), e.steamid.clone())
    };

    call(
        "/IAuthenticationService/UpdateAuthSessionWithSteamGuardCode/v1/",
        &[
            ("client_id", client_id),
            ("steamid", steamid),
            ("code", code.trim().to_uppercase()),
            ("code_type", code_type.to_string()),
        ],
        None,
    )
    .await
    .map_err(|e| e.to_string())?;
    Ok(())
}

/// One poll. Returns true once Steam hands over a token.
#[tauri::command]
pub async fn poll_login(state: EnrollState<'_>) -> Result<bool, String> {
    let (client_id, request_id) = {
        let guard = slot(&state).lock().unwrap();
        let e = guard.as_ref().ok_or("no login in progress")?;
        (e.client_id.clone(), e.request_id.clone())
    };

    let result = call(
        "/IAuthenticationService/PollAuthSessionStatus/v1/",
        &[("client_id", client_id), ("request_id", request_id)],
        None,
    )
    .await
    .map_err(|e| e.to_string())?;

    let access = str_field(&result, "access_token");
    let refresh = str_field(&result, "refresh_token");
    let new_client = str_field(&result, "new_client_id");
    let account = str_field(&result, "account_name");

    let mut guard = slot(&state).lock().unwrap();
    let enroller = guard.as_mut().ok_or("no login in progress")?;
    if !new_client.is_empty() {
        enroller.client_id = new_client;
    }
    if access.is_empty() && refresh.is_empty() {
        return Ok(false);
    }
    enroller.access_token = if access.is_empty() { refresh.clone() } else { access };
    enroller.refresh_token = refresh;
    if !account.is_empty() {
        enroller.account_name = account;
    }
    Ok(true)
}

/// Sign in again for an account that already has an authenticator, to refresh
/// its saved session tokens.
///
/// Only the password is needed: this app holds the account's `shared_secret`,
/// so it answers Steam's own Guard prompt itself.
pub async fn refresh_session(
    account_name: &str,
    password: &str,
    shared_secret: &str,
) -> Result<(String, String), SteamError> {
    if account_name.is_empty() || password.is_empty() {
        return Err(SteamError::new("Account name and password are both required."));
    }

    let key = call(
        "/IAuthenticationService/GetPasswordRSAPublicKey/v1/",
        &[("account_name", account_name.to_string())],
        None,
    )
    .await?;

    let modulus = str_field(&key, "publickey_mod");
    if modulus.is_empty() {
        return Err(SteamError::new(
            "Steam did not return an encryption key for that account name.",
        ));
    }
    let encrypted = encrypt_password(password, &modulus, &str_field(&key, "publickey_exp"))?;

    let device = "Steam Desktop Authenticator".to_string();
    let session = call(
        "/IAuthenticationService/BeginAuthSessionViaCredentials/v1/",
        &[
            ("account_name", account_name.to_string()),
            ("encrypted_password", encrypted),
            ("encryption_timestamp", str_field(&key, "timestamp")),
            ("remember_login", "1".into()),
            ("persistence", "1".into()),
            ("website_id", "Mobile".into()),
            ("platform_type", "3".into()),
            ("device_friendly_name", device.clone()),
            ("device_details[device_friendly_name]", device),
            ("device_details[platform_type]", "3".into()),
            ("device_details[os_type]", "-500".into()),
        ],
        None,
    )
    .await?;

    let client_id = str_field(&session, "client_id");
    let request_id = str_field(&session, "request_id");
    let steamid = str_field(&session, "steamid");
    if client_id.is_empty() || request_id.is_empty() {
        return Err(SteamError::new(
            "Steam accepted the password but returned no login session.",
        ));
    }

    let wants_device_code = session
        .get("allowed_confirmations")
        .and_then(|v| v.as_array())
        .map(|list| {
            list.iter().any(|c| {
                c.get("confirmation_type").and_then(|t| t.as_i64()) == Some(GUARD_DEVICE_CODE)
            })
        })
        .unwrap_or(false);

    if wants_device_code {
        let offset = query_time_offset().await.unwrap_or(0);
        let code = crate::totp::generate_auth_code(shared_secret, now() + offset)
            .map_err(|e| SteamError::new(format!("could not generate a Guard code: {e}")))?;
        call(
            "/IAuthenticationService/UpdateAuthSessionWithSteamGuardCode/v1/",
            &[
                ("client_id", client_id.clone()),
                ("steamid", steamid.clone()),
                ("code", code),
                ("code_type", GUARD_DEVICE_CODE.to_string()),
            ],
            None,
        )
        .await?;
    }

    // Poll until Steam hands over the tokens. Anything needing approval
    // elsewhere (email link, mobile confirm) resolves here too.
    for _ in 0..40 {
        let result = call(
            "/IAuthenticationService/PollAuthSessionStatus/v1/",
            &[
                ("client_id", client_id.clone()),
                ("request_id", request_id.clone()),
            ],
            None,
        )
        .await?;

        let access = str_field(&result, "access_token");
        let refresh = str_field(&result, "refresh_token");
        if !access.is_empty() || !refresh.is_empty() {
            return Ok((access, refresh));
        }
        tokio::time::sleep(std::time::Duration::from_millis(2500)).await;
    }

    Err(SteamError::new(
        "Timed out waiting for Steam to approve the sign-in.",
    ))
}

#[tauri::command]
pub fn enrollment_target_dir() -> String {
    target_dir().to_string_lossy().to_string()
}

fn target_dir() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        for ancestor in exe.ancestors().take(6) {
            let candidate = ancestor.join("maFiles");
            if candidate.is_dir() {
                return candidate;
            }
        }
    }
    if let Ok(home) = std::env::var("USERPROFILE") {
        return PathBuf::from(home).join("Desktop").join("maFiles");
    }
    PathBuf::from("maFiles")
}

#[tauri::command]
pub async fn add_authenticator(state: EnrollState<'_>) -> Result<EnrollResult, String> {
    let (steamid, access_token, account_name) = {
        let guard = slot(&state).lock().unwrap();
        let e = guard.as_ref().ok_or("no login in progress")?;
        if e.access_token.is_empty() {
            return Err("Not logged in yet.".into());
        }
        (e.steamid.clone(), e.access_token.clone(), e.account_name.clone())
    };

    let device = crate::totp::device_id(&steamid);
    let result = call(
        "/ITwoFactorService/AddAuthenticator/v1/",
        &[
            ("steamid", steamid.clone()),
            ("authenticator_type", "1".into()),
            ("device_identifier", device.clone()),
            ("sms_phone_id", "1".into()),
            ("version", "2".into()),
        ],
        Some(&access_token),
    )
    .await
    .map_err(|e| e.to_string())?;

    let status = result.get("status").and_then(|v| v.as_i64()).unwrap_or(0);
    if status != 1 {
        return Err(add_status_help(status));
    }

    let shared_secret = str_field(&result, "shared_secret");
    if shared_secret.is_empty() {
        return Err("Steam reported success but returned no shared secret.".into());
    }

    let account_name = {
        let from_steam = str_field(&result, "account_name");
        if from_steam.is_empty() { account_name } else { from_steam }
    };
    let revocation_code = str_field(&result, "revocation_code");

    let refresh = slot(&state).lock().unwrap().as_ref().map(|e| e.refresh_token.clone()).unwrap_or_default();
    let data = serde_json::json!({
        "shared_secret": shared_secret,
        "serial_number": str_field(&result, "serial_number"),
        "revocation_code": revocation_code,
        "uri": str_field(&result, "uri"),
        "server_time": str_field(&result, "server_time"),
        "account_name": account_name,
        "token_gid": str_field(&result, "token_gid"),
        "identity_secret": str_field(&result, "identity_secret"),
        "secret_1": str_field(&result, "secret_1"),
        "status": status,
        "device_id": device,
        "fully_enrolled": false,
        // Both tokens, in the shape current SDA writes. Storing only the
        // refresh token (as this app first did) throws away the one the
        // community site actually accepts, which is what confirmations need.
        // OAuthToken is kept so older readers still find something.
        "Session": {
            "SteamID": steamid.parse::<u64>().unwrap_or(0),
            "AccessToken": access_token,
            "RefreshToken": refresh,
            "SessionID": "",
            "OAuthToken": if refresh.is_empty() { access_token.clone() } else { refresh.clone() }
        }
    });

    let path = write_mafile(&data, &steamid, &account_name).map_err(|e| e.to_string())?;

    {
        let mut guard = slot(&state).lock().unwrap();
        let enroller = guard.as_mut().ok_or("no login in progress")?;
        enroller.shared_secret = shared_secret;
        enroller.revocation_code = revocation_code.clone();
        enroller.file_path = path.clone();
    }

    Ok(EnrollResult {
        account_name,
        steamid,
        revocation_code,
        path: path.to_string_lossy().to_string(),
        phone_hint: str_field(&result, "phone_number_hint"),
    })
}

/// Write the .maFile and flush it before returning: this is the only copy of
/// the revocation code.
fn write_mafile(data: &Value, steamid: &str, account_name: &str) -> std::io::Result<PathBuf> {
    use std::io::Write;

    let dir = target_dir();
    std::fs::create_dir_all(&dir)?;

    let stem = if steamid.is_empty() { account_name } else { steamid };
    let mut path = dir.join(format!("{stem}.maFile"));
    if path.exists() {
        // Never clobber another account's secrets.
        path = dir.join(format!("{stem}-{}.maFile", now()));
    }

    let mut file = std::fs::File::create(&path)?;
    file.write_all(serde_json::to_string_pretty(data)?.as_bytes())?;
    file.flush()?;
    file.sync_all()?;

    update_manifest(&dir, &path, steamid)?;
    Ok(path)
}

/// Keep a manifest.json so the official SDA can read these files too.
fn update_manifest(dir: &PathBuf, file: &PathBuf, steamid: &str) -> std::io::Result<()> {
    let manifest_path = dir.join("manifest.json");
    let mut manifest: Value = std::fs::read_to_string(&manifest_path)
        .ok()
        .and_then(|t| serde_json::from_str(t.trim_start_matches('\u{feff}')).ok())
        .unwrap_or_else(|| {
            serde_json::json!({
                "encrypted": false, "first_run": false, "entries": [],
                "periodic_checking": false,
                "auto_confirm_market_transactions": false,
                "auto_confirm_trades": false
            })
        });

    let name = file.file_name().unwrap_or_default().to_string_lossy().to_string();
    let entries = manifest["entries"].as_array().cloned().unwrap_or_default();
    let mut kept: Vec<Value> = entries
        .into_iter()
        .filter(|e| e.get("filename").and_then(|f| f.as_str()) != Some(name.as_str()))
        .collect();
    kept.push(serde_json::json!({
        "encryption_iv": Value::Null,
        "encryption_salt": Value::Null,
        "filename": name,
        "steamid": steamid.parse::<u64>().unwrap_or(0)
    }));
    manifest["entries"] = Value::Array(kept);

    std::fs::write(&manifest_path, serde_json::to_string_pretty(&manifest)?)?;
    Ok(())
}

#[tauri::command]
pub async fn finalize_authenticator(
    activation_code: String,
    state: EnrollState<'_>,
) -> Result<bool, String> {
    let (steamid, access_token, shared_secret, path) = {
        let guard = slot(&state).lock().unwrap();
        let e = guard.as_ref().ok_or("No pending authenticator to finalize.")?;
        if e.shared_secret.is_empty() {
            return Err("No pending authenticator to finalize.".into());
        }
        (
            e.steamid.clone(),
            e.access_token.clone(),
            e.shared_secret.clone(),
            e.file_path.clone(),
        )
    };

    let offset = query_time_offset().await.unwrap_or(0);
    let mut last_error: Option<String> = None;

    for attempt in 0..5 {
        let timestamp = now() + offset + attempt * crate::totp::STEP_SECONDS;
        let code = crate::totp::generate_auth_code(&shared_secret, timestamp)
            .map_err(|e| e.to_string())?;

        let outcome = call(
            "/ITwoFactorService/FinalizeAddAuthenticator/v1/",
            &[
                ("steamid", steamid.clone()),
                ("authenticator_code", code),
                ("authenticator_time", timestamp.to_string()),
                ("activation_code", activation_code.trim().to_string()),
                ("validate_sms_code", "1".into()),
            ],
            Some(&access_token),
        )
        .await;

        match outcome {
            Err(e) if e.eresult == Some(88) => {
                return Err("Steam rejected that confirmation code. Check the code from \
                            the SMS or email and try again."
                    .into())
            }
            Err(e) => {
                last_error = Some(e.to_string());
                continue;
            }
            Ok(result) => {
                if result.get("success").and_then(|v| v.as_bool()).unwrap_or(false) {
                    mark_fully_enrolled(&path);
                    return Ok(true);
                }
                if result.get("want_more").and_then(|v| v.as_bool()).unwrap_or(false) {
                    continue; // clock drift; Steam wants the next code in the sequence
                }
                last_error = Some("Steam did not accept the activation.".into());
            }
        }
    }

    Err(last_error.unwrap_or_else(|| {
        "Steam kept asking for another code; check the system clock and try again.".into()
    }))
}

fn mark_fully_enrolled(path: &PathBuf) {
    let Ok(text) = std::fs::read_to_string(path) else { return };
    let Ok(mut data) = serde_json::from_str::<Value>(&text) else { return };
    data["fully_enrolled"] = Value::Bool(true);
    if let Ok(pretty) = serde_json::to_string_pretty(&data) {
        let _ = std::fs::write(path, pretty);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::traits::PublicKeyParts;
    use rsa::{Pkcs1v15Encrypt as Enc, RsaPrivateKey};

    #[test]
    fn password_encryption_round_trips_against_a_real_key() {
        let mut rng = rand::thread_rng();
        let private = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public = private.to_public_key();

        let modulus = format!("{:x}", public.n());
        let exponent = format!("{:x}", public.e());

        let encrypted = encrypt_password("hunter2 correct horse", &modulus, &exponent).unwrap();
        let raw = BASE64.decode(encrypted).unwrap();
        assert_eq!(raw.len(), 256);

        let decrypted = private.decrypt(Enc, &raw).unwrap();
        assert_eq!(decrypted, b"hunter2 correct horse");
    }

    #[test]
    fn eresult_names_cover_the_ones_that_matter() {
        assert_eq!(eresult_name(5), "Incorrect password");
        assert_eq!(eresult_name(84), "Rate limited by Steam");
        assert_eq!(eresult_name(88), "Confirmation code mismatch");
    }

    #[test]
    fn add_status_help_explains_each_failure() {
        assert!(add_status_help(2).contains("too new"));
        assert!(add_status_help(29).contains("already has"));
        assert!(add_status_help(84).to_lowercase().contains("rate limit"));
    }

    #[test]
    fn status_2_does_not_blame_a_missing_phone() {
        // Steam confirms by email when no phone is attached; accounts without
        // one enroll fine. Saying otherwise sends people off to add a phone
        // they do not need.
        assert!(
            !add_status_help(2).to_lowercase().contains("phone"),
            "status 2 should not claim a phone number is required"
        );
    }

    #[test]
    fn guard_summary_describes_each_step() {
        assert_eq!(guard_summary(&[]), "no confirmation needed");
        assert!(guard_summary(&[GUARD_EMAIL_CODE]).contains("emailed"));
        assert!(guard_summary(&[GUARD_DEVICE_CODE]).contains("existing authenticator"));
    }

    // Live checks. Not run by default; `cargo test -- --ignored` exercises them.
    // They use a deliberately invalid account and send no credentials — they
    // exist to catch the two transport bugs that only the real API reveals:
    // a POST to the RSA endpoint returns 405, and a POST with no
    // Content-Length returns 411.

    #[tokio::test]
    #[ignore = "hits the live Steam API"]
    async fn live_rsa_key_endpoint_answers_a_get() {
        let response = call(
            "/IAuthenticationService/GetPasswordRSAPublicKey/v1/",
            &[("account_name", "zzq_not_a_real_account_9182".to_string())],
            None,
        )
        .await
        .expect("RSA key request failed");
        assert!(
            !str_field(&response, "publickey_mod").is_empty(),
            "no modulus returned"
        );
    }

    #[tokio::test]
    #[ignore = "hits the live Steam API"]
    async fn live_query_time_answers_an_empty_post() {
        let offset = query_time_offset().await.expect("time sync failed");
        assert!(offset.abs() < 86_400, "implausible clock offset {offset}");
    }

    #[test]
    fn rsa_key_endpoint_uses_get_everything_else_posts() {
        // Steam answers a POST to this one with 405 Method Not Allowed.
        assert!(is_get_endpoint(
            "/IAuthenticationService/GetPasswordRSAPublicKey/v1/"
        ));
        for path in [
            "/IAuthenticationService/BeginAuthSessionViaCredentials/v1/",
            "/IAuthenticationService/PollAuthSessionStatus/v1/",
            "/IAuthenticationService/UpdateAuthSessionWithSteamGuardCode/v1/",
            "/ITwoFactorService/AddAuthenticator/v1/",
            "/ITwoFactorService/FinalizeAddAuthenticator/v1/",
            "/ITwoFactorService/QueryTime/v1/",
        ] {
            assert!(!is_get_endpoint(path), "{path} should POST");
        }
    }

    #[test]
    fn str_field_reads_numbers_and_strings() {
        let value = serde_json::json!({ "a": "text", "b": 42, "c": null });
        assert_eq!(str_field(&value, "a"), "text");
        assert_eq!(str_field(&value, "b"), "42");
        assert_eq!(str_field(&value, "c"), "");
        assert_eq!(str_field(&value, "missing"), "");
    }
}
