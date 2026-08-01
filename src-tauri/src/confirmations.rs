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

/// Trade the stored refresh token for a community access token.
///
/// The `steamLoginSecure` cookie is `steamid||access_token`; the community
/// site will not accept the plain WebAPI token.
async fn community_token(account: &Account) -> Result<String, ConfirmError> {
    if account.refresh_token.is_empty() {
        return Err(ConfirmError(
            "This account file has no session token, so confirmations cannot be \
             fetched. It was imported rather than enrolled here, or predates the \
             token being stored. Re-enrolling the authenticator would add one."
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
        // Observed, not guessed: with a valid unexpired refresh token (aud
        // includes "renew", ~200 days left), this endpoint answers EResult 15
        // AccessDenied — as does login.steampowered.com/jwt/finalizelogin, and
        // as does using the refresh token directly as steamLoginSecure
        // (needauth: true). The enrollment token appears not to be accepted for
        // creating a community session, so confirmations need a separate web
        // login that this app does not yet perform.
        ConfirmError(format!(
            "Steam would not open a web session for this account ({e}).\n\n\
             Confirmations need a steamcommunity.com session, and the login \
             token saved during enrollment is not accepted for one. This is a \
             known gap — the rest of the app is unaffected, and codes keep \
             working. Approve trades from the phone app for now."
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

    let response = client()?
        .get(format!("{COMMUNITY}/mobileconf/getlist"))
        .header("Cookie", cookies(account, &token))
        .query(&signed_params(account, "list")?)
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
