// Sésamo desktop (macOS) — a thin native wrapper around the self-hosted
// Sésamo web app.
//
// The web UI uses *relative* API paths (`/auth/mode`, `/api/...`) and same-origin
// session cookies, so the wrapper must point a real webview at the user's server
// origin rather than bundling the assets locally. The bundled launcher only
// collects the server URL; the vault itself is loaded from that origin, exactly
// like a browser tab. This preserves the zero-knowledge model end to end: the
// master password, key derivation and all crypto stay inside the webview and the
// desktop shell never sees plaintext or adds anything server-side.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::fs;
use std::path::PathBuf;
use tauri::{Manager, WebviewUrl, WebviewWindowBuilder};

fn config_file(app: &tauri::AppHandle) -> Option<PathBuf> {
    app.path()
        .app_config_dir()
        .ok()
        .map(|dir| dir.join("server.txt"))
}

/// Return the saved server URL, if the user has connected before.
#[tauri::command]
fn get_server(app: tauri::AppHandle) -> Option<String> {
    let path = config_file(&app)?;
    fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Forget the saved server URL so the launcher asks again next time.
#[tauri::command]
fn forget_server(app: tauri::AppHandle) -> Result<(), String> {
    if let Some(path) = config_file(&app) {
        let _ = fs::remove_file(path);
    }
    Ok(())
}

/// Open the vault window pointed at `url`, persist the choice, and close the
/// launcher. Only http(s) origins are accepted.
#[tauri::command]
fn open_vault(app: tauri::AppHandle, url: String) -> Result<(), String> {
    let trimmed = url.trim().to_string();
    let parsed = tauri::Url::parse(&trimmed).map_err(|e| format!("Invalid URL: {e}"))?;
    match parsed.scheme() {
        "http" | "https" => {}
        _ => return Err("Server URL must start with http:// or https://".into()),
    }

    // Reuse the vault window if it already exists (e.g. reconnecting).
    if app.get_webview_window("vault").is_none() {
        WebviewWindowBuilder::new(&app, "vault", WebviewUrl::External(parsed))
            .title("Sésamo")
            .inner_size(1160.0, 800.0)
            .min_inner_size(720.0, 560.0)
            .center()
            .build()
            .map_err(|e| e.to_string())?;
    }

    // Remember the server only once the window was created successfully.
    if let Some(path) = config_file(&app) {
        if let Some(dir) = path.parent() {
            let _ = fs::create_dir_all(dir);
        }
        let _ = fs::write(&path, &trimmed);
    }

    if let Some(launcher) = app.get_webview_window("launcher") {
        let _ = launcher.close();
    }
    Ok(())
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            get_server,
            open_vault,
            forget_server
        ])
        .run(tauri::generate_context!())
        .expect("error while running the Sésamo desktop app");
}
