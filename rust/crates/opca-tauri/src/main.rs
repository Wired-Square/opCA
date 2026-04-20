#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod state;

use log::info;
use state::AppState;

/// Spawn a background `op --version` so that macOS caches the AMFI / code-
/// signature verification for the `op` binary.  Subsequent spawns in the same
/// session then skip the expensive OCSP check, cutting several seconds off
/// every real `op` call.
#[cfg(target_os = "macos")]
fn warmup_op_cli() {
    std::thread::spawn(|| {
        let _ = std::process::Command::new("op")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    });
}

/// Extend `PATH` so that bundled macOS `.app` builds (which inherit a minimal
/// PATH from launchd) can find CLI tools like `op` installed via Homebrew or
/// common package managers.
#[cfg(target_os = "macos")]
fn extend_path() {
    let extra_dirs: &[&str] = &[
        "/opt/homebrew/bin",
        "/usr/local/bin",
        "/usr/local/sbin",
    ];

    let current = std::env::var("PATH").unwrap_or_default();
    let mut dirs: Vec<&str> = current.split(':').collect();

    for dir in extra_dirs {
        if !dirs.contains(dir) {
            dirs.push(dir);
        }
    }

    // SAFETY: called once at the very start of main(), before any threads are
    // spawned, so there are no concurrent readers of the environment.
    unsafe { std::env::set_var("PATH", dirs.join(":")) };
}

fn main() {
    #[cfg(target_os = "macos")]
    extend_path();
    #[cfg(target_os = "macos")]
    warmup_op_cli();

    tauri::Builder::default()
        .plugin(
            tauri_plugin_log::Builder::new()
                .level(log::LevelFilter::Debug)
                .timezone_strategy(tauri_plugin_log::TimezoneStrategy::UseLocal)
                .max_file_size(5_000_000) // 5 MB
                .rotation_strategy(tauri_plugin_log::RotationStrategy::KeepOne)
                .targets([
                    tauri_plugin_log::Target::new(
                        tauri_plugin_log::TargetKind::LogDir {
                            file_name: Some("opca".to_string()),
                        },
                    ),
                    tauri_plugin_log::Target::new(
                        tauri_plugin_log::TargetKind::Stdout,
                    ),
                ])
                .build(),
        )
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_shell::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            commands::connect::connect,
            commands::connect::disconnect,
            commands::connect::list_vaults,
            commands::connect::create_vault,
            commands::connect::check_vault_state,
            commands::connect::check_op_cli,
            commands::lock::acquire_lock,
            commands::lock::release_lock,
            commands::dashboard::get_dashboard,
            commands::ca::get_ca_info,
            commands::ca::get_ca_config,
            commands::ca::update_ca_config,
            commands::ca::init_ca,
            commands::ca::test_stores,
            commands::ca::upload_ca_cert,
            commands::ca::upload_ca_database,
            commands::ca::resign_ca,
            commands::csr::decode_csr,
            commands::csr::list_csrs,
            commands::csr::get_csr_info,
            commands::csr::create_csr,
            commands::csr::sign_csr,
            commands::csr::import_csr_cert,
            commands::cert::list_certs,
            commands::cert::list_external_certs,
            commands::cert::get_cert_info,
            commands::cert::backfill_cert,
            commands::cert::create_cert,
            commands::cert::revoke_cert,
            commands::cert::renew_cert,
            commands::cert::rekey_cert,
            commands::cert::ignore_cert,
            commands::cert::unignore_cert,
            commands::cert::import_cert,
            commands::files::read_text_file,
            commands::dkim::list_dkim_keys,
            commands::dkim::get_dkim_info,
            commands::dkim::create_dkim_key,
            commands::dkim::delete_dkim_key,
            commands::dkim::verify_dkim_dns,
            commands::dkim::deploy_dkim_route53,
            commands::crl::get_crl_info,
            commands::crl::generate_crl,
            commands::crl::upload_crl,
            commands::database::get_database_info,
            commands::database::get_action_log,
            commands::openvpn::get_openvpn_params,
            commands::openvpn::generate_openvpn_dh,
            commands::openvpn::generate_openvpn_ta,
            commands::openvpn::setup_openvpn_server,
            commands::openvpn::list_openvpn_templates,
            commands::openvpn::get_openvpn_template,
            commands::openvpn::save_openvpn_template,
            commands::openvpn::list_vpn_clients,
            commands::openvpn::generate_openvpn_profile,
            commands::openvpn::list_openvpn_profiles,
            commands::openvpn::send_profile_to_vault,
            commands::vault::vault_backup,
            commands::vault::vault_restore,
            commands::vault::vault_info,
            commands::vault::vault_default_filename,
            commands::vault::generate_password,
            commands::vault::store_password_in_op,
            commands::vault::file_md5,
            commands::update::check_for_updates,
            commands::logs::get_log_contents,
            commands::logs::get_log_path,
        ])
        .setup(|_app| {
            info!("opCA v{} starting", env!("CARGO_PKG_VERSION"));
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("failed to run opCA desktop application");
}
