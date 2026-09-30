//! Hold a quit until in-flight 1Password work has finished.
//!
//! Quitting while `op` was part-way through a write once left 1Password with a
//! truncated CA database, so a quit that arrives mid-operation waits for the
//! connection to go idle and then exits on its own.

use std::sync::atomic::Ordering;
use std::time::Duration;

use log::info;
use tauri::{AppHandle, Emitter, Manager, RunEvent, WindowEvent};

use crate::state::AppState;

pub const QUIT_MENU_ID: &str = "opca-quit";

/// macOS's predefined Quit terminates the process without an `ExitRequested`
/// event that could be held, so it is replaced with one routed through
/// [`request_quit`].
#[cfg(target_os = "macos")]
pub fn install_quit_menu(app: &AppHandle) -> tauri::Result<()> {
    use tauri::menu::{Menu, MenuItem, MenuItemKind};

    let menu = Menu::default(app)?;
    if let Some(MenuItemKind::Submenu(app_menu)) = menu.items()?.first() {
        let predefined_quit = app_menu.items()?.len() - 1;
        app_menu.remove_at(predefined_quit)?;
        app_menu.append(&MenuItem::with_id(app, QUIT_MENU_ID, "Quit opCA", true, Some("CmdOrCtrl+Q"))?)?;
    }
    app.set_menu(menu)?;
    Ok(())
}

/// Exit now if idle; otherwise tell the window and exit once idle.
pub fn request_quit(app: &AppHandle) {
    let state = app.state::<AppState>();
    if !state.is_busy() {
        app.exit(0);
        return;
    }
    if state.quit_pending.swap(true, Ordering::SeqCst) {
        return;
    }
    info!("[tauri] quit requested during a 1Password operation; waiting for it to finish");
    let _ = app.emit("quit-pending", ());

    let app = app.clone();
    std::thread::spawn(move || loop {
        // `exit` is itself held (and retried here) if new work started meanwhile.
        if !app.state::<AppState>().is_busy() {
            app.exit(0);
        }
        std::thread::sleep(Duration::from_millis(250));
    });
}

pub fn on_run_event(app: &AppHandle, event: RunEvent) {
    match event {
        RunEvent::ExitRequested { api, .. } if app.state::<AppState>().is_busy() => {
            api.prevent_exit();
            request_quit(app);
        }
        RunEvent::WindowEvent { event: WindowEvent::CloseRequested { api, .. }, .. }
            if app.state::<AppState>().is_busy() =>
        {
            api.prevent_close();
            request_quit(app);
        }
        _ => {}
    }
}
