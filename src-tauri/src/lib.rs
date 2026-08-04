pub mod confirmations;
pub mod enroll;
pub mod mafile;
pub mod totp;

use mafile::{Account, AccountView};
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::{Manager, State};

/// Secrets live here and never cross the IPC boundary. The frontend gets
/// account metadata and finished codes, never a shared_secret.
#[derive(Default)]
pub struct AppState {
    accounts: Mutex<Vec<Account>>,
    clock_offset: Mutex<i64>,
    passkey: Mutex<Option<String>>,
    enrollment: Mutex<Option<enroll::Enroller>>,
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[derive(Serialize)]
pub struct LoadResult {
    accounts: Vec<AccountView>,
    errors: Vec<String>,
    directory: String,
    needs_passkey: bool,
}

#[derive(Serialize)]
pub struct CodeView {
    code: String,
    /// Wall-clock ms (Steam-corrected) at which this code stops being valid.
    expires_at_ms: i64,
    step_ms: i64,
    clock_offset: i64,
}

fn adopt(state: &State<AppState>, accounts: Vec<Account>) -> Vec<AccountView> {
    let views: Vec<AccountView> = accounts.iter().map(|a| a.view()).collect();
    *state.accounts.lock().unwrap() = accounts;
    views
}

#[tauri::command]
fn load_default_accounts(state: State<AppState>) -> LoadResult {
    let passkey = state.passkey.lock().unwrap().clone();

    for dir in mafile::default_directories() {
        let (accounts, errors) = mafile::load_directory(&dir, passkey.as_deref());
        if !accounts.is_empty() {
            return LoadResult {
                accounts: adopt(&state, accounts),
                errors,
                directory: dir.to_string_lossy().to_string(),
                needs_passkey: false,
            };
        }
        if errors.iter().any(|e| e.contains("encrypted")) {
            return LoadResult {
                accounts: Vec::new(),
                errors,
                directory: dir.to_string_lossy().to_string(),
                needs_passkey: true,
            };
        }
    }

    LoadResult {
        accounts: Vec::new(),
        errors: Vec::new(),
        directory: String::new(),
        needs_passkey: false,
    }
}

#[tauri::command]
fn load_folder(path: String, passkey: Option<String>, state: State<AppState>) -> LoadResult {
    let dir = PathBuf::from(&path);
    let (accounts, errors) = mafile::load_directory(&dir, passkey.as_deref());

    if !accounts.is_empty() {
        if let Some(key) = passkey {
            *state.passkey.lock().unwrap() = Some(key);
        }
    }
    let needs_passkey = accounts.is_empty() && errors.iter().any(|e| e.contains("encrypted"));

    LoadResult {
        accounts: adopt(&state, accounts),
        errors,
        directory: path,
        needs_passkey,
    }
}

#[tauri::command]
fn load_file(path: String, passkey: Option<String>, state: State<AppState>) -> Result<LoadResult, String> {
    let file = PathBuf::from(&path);
    match mafile::load_mafile(&file, passkey.as_deref()) {
        Ok(account) => {
            if let Some(key) = passkey {
                *state.passkey.lock().unwrap() = Some(key);
            }
            let mut accounts = state.accounts.lock().unwrap().clone();
            accounts.retain(|a| a.path != account.path);
            accounts.push(account);
            Ok(LoadResult {
                accounts: adopt(&state, accounts),
                errors: Vec::new(),
                directory: file
                    .parent()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default(),
                needs_passkey: false,
            })
        }
        Err(mafile::MaFileError::Encrypted(name)) => Ok(LoadResult {
            accounts: state.accounts.lock().unwrap().iter().map(|a| a.view()).collect(),
            errors: vec![format!("{name} is encrypted")],
            directory: String::new(),
            needs_passkey: true,
        }),
        Err(e) => Err(e.to_string()),
    }
}

#[tauri::command]
fn current_code(index: usize, state: State<AppState>) -> Result<CodeView, String> {
    let accounts = state.accounts.lock().unwrap();
    let account = accounts.get(index).ok_or("no such account")?;
    let offset = *state.clock_offset.lock().unwrap();

    let corrected = now() + offset;
    let code = totp::generate_auth_code(&account.shared_secret, corrected)
        .map_err(|e| e.to_string())?;

    // Anchor the expiry to the step boundary so the UI can animate locally
    // without asking the backend again every frame.
    let step_start = corrected - corrected.rem_euclid(totp::STEP_SECONDS);
    let expires_at = step_start + totp::STEP_SECONDS;

    Ok(CodeView {
        code,
        expires_at_ms: (expires_at - offset) * 1000 + (now_ms() - now() * 1000).clamp(0, 999),
        step_ms: totp::STEP_SECONDS * 1000,
        clock_offset: offset,
    })
}

#[tauri::command]
async fn sync_time(state: State<'_, AppState>) -> Result<i64, String> {
    let offset = enroll::query_time_offset().await.map_err(|e| e.to_string())?;
    *state.clock_offset.lock().unwrap() = offset;
    Ok(offset)
}

/// Pending trade and market confirmations for one account.
#[tauri::command]
async fn list_confirmations(
    index: usize,
    state: State<'_, AppState>,
) -> Result<Vec<confirmations::ConfirmationView>, String> {
    // Clone out of the lock: the guard cannot be held across an await.
    let account = {
        let accounts = state.accounts.lock().unwrap();
        accounts.get(index).cloned().ok_or("no such account")?
    };
    confirmations::fetch(&account).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn respond_to_confirmation(
    index: usize,
    id: String,
    nonce: String,
    allow: bool,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let account = {
        let accounts = state.accounts.lock().unwrap();
        accounts.get(index).cloned().ok_or("no such account")?
    };
    confirmations::act(&account, &id, &nonce, allow)
        .await
        .map_err(|e| e.to_string())
}

/// Sign in again for an account whose saved session has stopped working, and
/// write the refreshed tokens back to its .maFile.
#[tauri::command]
async fn relogin(
    index: usize,
    password: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let (name, secret, path) = {
        let accounts = state.accounts.lock().unwrap();
        let a = accounts.get(index).ok_or("no such account")?;
        (a.account_name.clone(), a.shared_secret.clone(), a.path.clone())
    };
    if name.is_empty() {
        return Err("This account file has no account name to sign in with.".into());
    }

    let (access, refresh) = enroll::refresh_session(&name, &password, &secret)
        .await
        .map_err(|e| e.to_string())?;

    mafile::update_session_tokens(&path, &access, &refresh).map_err(|e| e.to_string())?;

    // Reload so the in-memory account carries the new tokens.
    let reloaded = mafile::load_mafile(&path, state.passkey.lock().unwrap().as_deref())
        .map_err(|e| e.to_string())?;
    {
        let mut accounts = state.accounts.lock().unwrap();
        if let Some(slot) = accounts.get_mut(index) {
            *slot = reloaded;
        }
    }
    Ok(name)
}

#[tauri::command]
fn account_details(index: usize, state: State<AppState>) -> Result<AccountView, String> {
    let accounts = state.accounts.lock().unwrap();
    accounts
        .get(index)
        .map(|a| a.view())
        .ok_or_else(|| "no such account".into())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .setup(|app| {
            app.manage(AppState::default());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            load_default_accounts,
            load_folder,
            load_file,
            current_code,
            sync_time,
            account_details,
            list_confirmations,
            respond_to_confirmation,
            relogin,
            enroll::begin_login,
            enroll::submit_guard_code,
            enroll::poll_login,
            enroll::add_authenticator,
            enroll::finalize_authenticator,
            enroll::enrollment_target_dir,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
