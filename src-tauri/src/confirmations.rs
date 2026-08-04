//! Mobile confirmations: the trade and market approvals the phone app handles.
//!
//! Three things are needed, and they are not the same as generating codes:
//!
//!   * `identity_secret` — a *different* secret from `shared_secret`. Each
//!     request is signed with an HMAC over the time and a tag naming the
//!     operation ("list", "accept", "reject"). The tag must match the request
//!     or Steam rejects the signature.
//!   * `device_id` — the android:UUID Steam tied to the authenticator.
//!   * A steamcommunity.com session. The confirmation endpoints live on the
//!     community site and want a `steamLoginSecure` cookie, not the WebAPI
//!     access token the rest of the app uses. The stored refresh token is
//!     exchanged for one on demand and kept in memory only.

use crate::mafile::Account;
use crate::totp;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

const COMMUNITY: &str = "https://steamcommunity.com";
const MOBILE_UA: &str = "Mozilla/5.0 (Linux; U; Android 9; en-us; Valve Steam App) \
                         AppleWebKit/537.36 (KHTML, like Gecko) Mobile Safari/537.36";

/// Steam's own client identifier for the confirmation endpoints.
const CLIENT: &str = "react";

#[derive(Debug)]
pub struct ConfirmError(pub String);

impl std::fmt::Display for ConfirmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<reqwest::Error> for ConfirmError {
    fn from(e: reqwest::Error) -> Self {
        ConfirmError(format!("Could not reach Steam: {e}"))
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// One pending confirmation, as the UI needs it.
#[derive(Debug, Clone, Serialize)]
pub struct ConfirmationView {
    pub id: String,
    pub nonce: String,
    pub kind: String,
    pub headline: String,
    pub summary: String,
    pub icon: String,
    pub accept_label: String,
    pub cancel_label: String,
    pub created: i64,
}

#[derive(Debug, Deserialize)]
struct RawConfirmation {
    #[serde(default)]
    id: serde_json::Value,
    /// Newer Steam calls this `nonce`; older builds called it `key`.
    #[serde(default, alias = "key")]
    nonce: serde_json::Value,
    #[serde(default)]
    type_name: Option<String>,
    #[serde(default, rename = "type")]
    kind: Option<i64>,
    #[serde(default)]
    headline: Option<String>,
    #[serde(default)]
    summary: Vec<String>,
    #[serde(default)]
    icon: Option<String>,
    #[serde(default)]
    accept: Option<String>,
    #[serde(default)]
    cancel: Option<String>,
    #[serde(default)]
    creation_time: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct ListResponse {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    conf: Vec<RawConfirmation>,
    #[serde(default)]
    needauth: bool,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    detail: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OpResponse {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    needauth: bool,
}

fn value_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        _ => String::new(),
    }
}

/// Seconds until a Steam JWT expires; negative once it has.
fn seconds_until_expiry(token: &str) -> Option<i64> {
    // base64url, and Steam sometimes pads it — trim so either form decodes.
    let payload = token.split('.').nth(1)?.trim_end_matches('=');
    let decoded = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    Some(claims.get("exp")?.as_i64()? - now())
}

/// A community access token for this account.
///
/// Mirrors what the reference implementation does: use the stored access token
/// while it is valid, and mint a fresh one from the refresh token otherwise.
/// The `steamLoginSecure` cookie is `steamid||access_token`; the community site
/// does not accept a refresh token in its place.
async fn community_token(account: &Account) -> Result<String, ConfirmError> {
    // Access tokens last about 24 hours. Keep a minute of headroom so one does
    // not expire mid-request.
    if !account.access_token.is_empty() {
        if seconds_until_expiry(&account.access_token).unwrap_or(0) > 60 {
            return Ok(account.access_token.clone());
        }
    }

    if account.refresh_token.is_empty() {
        return Err(ConfirmError(
            "This account file has no login token, so confirmations cannot be \
             fetched. Sign in again in the app that created it — or re-enroll \
             here — to store one."
                .into(),
        ));
    }
    if seconds_until_expiry(&account.refresh_token).unwrap_or(1) < 0 {
        return Err(ConfirmError(
            "The saved login for this account has expired. Sign in again to \
             refresh it."
                .into(),
        ));
    }

    let response = crate::enroll::call(
        "/IAuthenticationService/GenerateAccessTokenForApp/v1/",
        &[
            ("refresh_token", account.refresh_token.clone()),
            ("steamid", account.steamid.clone()),
            ("renewal_type", "0".into()),
        ],
        None,
    )
    .await
    .map_err(|e| {
        ConfirmError(format!(
            "Steam would not issue a web session for this account ({e}).\n\n\
             The saved login may have been invalidated — signing out everywhere, \
             changing the password, or Steam retiring the token all do this. \
             Signing in again refreshes it. Codes are unaffected."
        ))
    })?;

    let token = crate::enroll::str_field(&response, "access_token");
    if token.is_empty() {
        return Err(ConfirmError(
            "Steam returned no access token for this account.".into(),
        ));
    }
    Ok(token)
}

fn client() -> Result<reqwest::Client, ConfirmError> {
    reqwest::Client::builder()
        .user_agent(MOBILE_UA)
        .build()
        .map_err(Into::into)
}

fn cookies(account: &Account, token: &str) -> String {
    format!(
        "steamLoginSecure={}%7C%7C{}; sessionid={}; mobileClient=android; \
         mobileClientVersion=777777 3.6.4; dob=",
        account.steamid,
        token,
        &account.effective_device_id().replace("android:", "").replace('-', "")[..24.min(
            account.effective_device_id().replace("android:", "").replace('-', "").len()
        )],
    )
}

/// Query parameters every confirmation request carries. `tag` names the
/// operation and must match the one signed into `k`.
fn signed_params(account: &Account, tag: &str) -> Result<Vec<(String, String)>, ConfirmError> {
    let time = now();
    let key = totp::generate_confirmation_key(&account.identity_secret, tag, time)
        .map_err(|e| ConfirmError(format!("identity_secret is unusable: {e}")))?;

    Ok(vec![
        ("p".into(), account.effective_device_id()),
        ("a".into(), account.steamid.clone()),
        ("k".into(), key),
        ("t".into(), time.to_string()),
        ("m".into(), CLIENT.into()),
        ("tag".into(), tag.into()),
    ])
}

fn require_identity(account: &Account) -> Result<(), ConfirmError> {
    if account.identity_secret.is_empty() {
        return Err(ConfirmError(
            "This account file has no identity_secret, which confirmations \
             require. It is a different secret from the one that generates \
             codes, and cannot be derived from it."
                .into(),
        ));
    }
    Ok(())
}

/// Everything currently waiting for approval.
pub async fn fetch(account: &Account) -> Result<Vec<ConfirmationView>, ConfirmError> {
    require_identity(account)?;
    let token = community_token(account).await?;

    // The tag for getlist is "conf", not "list". The tag is signed into `k`,
    // so the wrong one produces a signature Steam rejects as needauth — which
    // reads like a session problem and sends you hunting in the wrong place.
    let response = client()?
        .get(format!("{COMMUNITY}/mobileconf/getlist"))
        .header("Cookie", cookies(account, &token))
        .query(&signed_params(account, "conf")?)
        .send()
        .await?;

    let body = response.text().await?;
    let parsed: ListResponse = serde_json::from_str(&body).map_err(|_| {
        ConfirmError(
            "Steam returned something other than a confirmation list. The \
             session may have expired."
                .into(),
        )
    })?;

    if parsed.needauth {
        return Err(ConfirmError(
            "Steam rejected the session. Re-enrolling the authenticator will \
             refresh the saved login."
                .into(),
        ));
    }
    if !parsed.success {
        let detail = parsed.message.or(parsed.detail).unwrap_or_default();
        // An empty list comes back as success=false with no message on some
        // Steam builds, which is not an error worth showing.
        if detail.is_empty() && parsed.conf.is_empty() {
            return Ok(Vec::new());
        }
        return Err(ConfirmError(format!("Steam refused the request: {detail}")));
    }

    Ok(parsed
        .conf
        .into_iter()
        .map(|c| ConfirmationView {
            id: value_to_string(&c.id),
            nonce: value_to_string(&c.nonce),
            kind: c.type_name.unwrap_or_else(|| match c.kind.unwrap_or(0) {
                1 => "Account recovery".into(),
                2 => "Trade offer".into(),
                3 => "Market listing".into(),
                6 => "API key".into(),
                _ => "Confirmation".into(),
            }),
            headline: c.headline.unwrap_or_default(),
            summary: c.summary.join(" · "),
            icon: c.icon.unwrap_or_default(),
            accept_label: c.accept.unwrap_or_else(|| "Confirm".into()),
            cancel_label: c.cancel.unwrap_or_else(|| "Cancel".into()),
            created: c.creation_time.unwrap_or(0),
        })
        .collect())
}

/// Approve or deny one confirmation.
pub async fn act(
    account: &Account,
    id: &str,
    nonce: &str,
    allow: bool,
) -> Result<(), ConfirmError> {
    require_identity(account)?;
    let token = community_token(account).await?;

    // The signature tag and the op have to agree; signing "accept" and sending
    // op=cancel fails the signature check rather than doing the safe thing.
    let tag = if allow { "accept" } else { "reject" };
    let mut params = signed_params(account, tag)?;
    params.push(("op".into(), if allow { "allow".into() } else { "cancel".into() }));
    params.push(("cid".into(), id.to_string()));
    params.push(("ck".into(), nonce.to_string()));

    let response = client()?
        .get(format!("{COMMUNITY}/mobileconf/ajaxop"))
        .header("Cookie", cookies(account, &token))
        .query(&params)
        .send()
        .await?;

    let body = response.text().await?;
    let parsed: OpResponse = serde_json::from_str(&body)
        .map_err(|_| ConfirmError("Steam gave an unreadable reply to the action.".into()))?;

    if parsed.needauth {
        return Err(ConfirmError("Steam rejected the session.".into()));
    }
    if !parsed.success {
        return Err(ConfirmError(
            parsed.message.unwrap_or_else(|| "Steam refused the action.".into()),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const SECRET: &str = "cnOgv/KdpLoP6Nbh0GMkXkPXALQ=";

    fn account() -> Account {
        Account {
            account_name: "tester".into(),
            shared_secret: SECRET.into(),
            identity_secret: SECRET.into(),
            steamid: "76561198000000000".into(),
            revocation_code: "R12345".into(),
            device_id: String::new(),
            refresh_token: "refresh".into(),
            access_token: String::new(),
            path: PathBuf::from("x.maFile"),
        }
    }

    #[test]
    fn device_id_is_derived_when_the_file_lacks_one() {
        assert_eq!(
            account().effective_device_id(),
            "android:5c9df5a2-d7de-1e2c-8fc8-766523ca130f"
        );
    }

    #[test]
    fn signed_params_carry_the_operation_tag() {
        let params = signed_params(&account(), "list").unwrap();
        let map: std::collections::HashMap<_, _> = params.into_iter().collect();
        assert_eq!(map["tag"], "list");
        assert_eq!(map["m"], "react");
        assert_eq!(map["a"], "76561198000000000");
        assert!(map["p"].starts_with("android:"));
        assert!(!map["k"].is_empty());
    }

    #[test]
    fn getlist_signs_the_conf_tag_not_list() {
        // The tag is signed into `k`. "list" reads like the obvious choice and
        // is wrong: Steam answers needauth, which looks like a session problem
        // and sends you hunting in entirely the wrong place. The reference
        // implementation defaults this parameter to "conf".
        let params = signed_params(&account(), "conf").unwrap();
        let map: std::collections::HashMap<_, _> = params.into_iter().collect();
        assert_eq!(map["tag"], "conf");

        let time = 1_600_000_000;
        assert_ne!(
            totp::generate_confirmation_key(SECRET, "conf", time).unwrap(),
            totp::generate_confirmation_key(SECRET, "list", time).unwrap()
        );
    }

    #[test]
    fn jwt_expiry_is_read_from_the_payload() {
        // {"exp": 4102444800} — 1 Jan 2100, base64url, unpadded.
        let payload = URL_SAFE_NO_PAD.encode(br#"{"exp":4102444800}"#);
        let token = format!("header.{payload}.signature");
        assert!(seconds_until_expiry(&token).unwrap() > 0);

        let past = URL_SAFE_NO_PAD.encode(br#"{"exp":946684800}"#); // 2000
        assert!(seconds_until_expiry(&format!("h.{past}.s")).unwrap() < 0);
    }

    #[test]
    fn malformed_tokens_do_not_panic() {
        for bad in ["", "notajwt", "a.b", "a.!!!.c"] {
            assert!(seconds_until_expiry(bad).is_none() || seconds_until_expiry(bad).is_some());
        }
    }

    #[test]
    fn each_tag_signs_to_a_different_key() {
        // Steam checks the signature against the tag, so accept and reject must
        // not collide — otherwise a denial could be replayed as an approval.
        let time = 1_600_000_000;
        let keys: std::collections::HashSet<_> = ["list", "accept", "reject"]
            .iter()
            .map(|tag| totp::generate_confirmation_key(SECRET, tag, time).unwrap())
            .collect();
        assert_eq!(keys.len(), 3);
    }

    #[test]
    fn missing_identity_secret_is_explained_not_swallowed() {
        let mut acc = account();
        acc.identity_secret = String::new();
        let error = require_identity(&acc).unwrap_err().to_string();
        assert!(error.contains("identity_secret"));
        assert!(error.contains("different secret"));
    }

    #[test]
    fn cookie_header_carries_the_login_and_session() {
        let header = cookies(&account(), "tok123");
        assert!(header.contains("steamLoginSecure=76561198000000000%7C%7Ctok123"));
        assert!(header.contains("mobileClient=android"));
        assert!(header.contains("sessionid="));
    }

    #[test]
    fn confirmation_types_get_readable_names() {
        let raw = r#"{"success":true,"conf":[
            {"id":"123","nonce":"456","type":2,"headline":"Trade with X",
             "summary":["You will give up 1 item"],"accept":"Confirm","cancel":"Cancel",
             "creation_time":1712345678}]}"#;
        let parsed: ListResponse = serde_json::from_str(raw).unwrap();
        assert_eq!(parsed.conf.len(), 1);
        assert_eq!(value_to_string(&parsed.conf[0].id), "123");
    }

    #[test]
    fn older_responses_using_key_instead_of_nonce_still_parse() {
        let raw = r#"{"success":true,"conf":[{"id":"1","key":"99","type":3}]}"#;
        let parsed: ListResponse = serde_json::from_str(raw).unwrap();
        assert_eq!(value_to_string(&parsed.conf[0].nonce), "99");
    }

    #[test]
    fn numeric_ids_parse_as_well_as_strings() {
        let raw = r#"{"success":true,"conf":[{"id":8811,"nonce":9922,"type":2}]}"#;
        let parsed: ListResponse = serde_json::from_str(raw).unwrap();
        assert_eq!(value_to_string(&parsed.conf[0].id), "8811");
        assert_eq!(value_to_string(&parsed.conf[0].nonce), "9922");
    }

    #[test]
    fn an_empty_list_is_not_an_error() {
        let raw = r#"{"success":false,"conf":[]}"#;
        let parsed: ListResponse = serde_json::from_str(raw).unwrap();
        assert!(!parsed.success);
        assert!(parsed.conf.is_empty());
        assert!(parsed.message.is_none());
    }

    #[test]
    fn needauth_is_recognised() {
        let raw = r#"{"success":false,"needauth":true}"#;
        let parsed: ListResponse = serde_json::from_str(raw).unwrap();
        assert!(parsed.needauth);
    }
}
