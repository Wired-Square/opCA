pub mod aws;
pub mod ca;
pub mod cert;
pub mod crl;
pub mod csr;
pub mod database;
pub mod dkim;
pub mod openvpn;
pub mod vault;

use opca_core::error::OpcaError;
use opca_core::op::{self, ShellRunner};

use crate::app::AppContext;
use crate::output;
use crate::{Cli, Commands};

/// Dispatch the parsed CLI to the appropriate command handler.
pub fn dispatch(cli: Cli) -> Result<(), OpcaError> {
    if let Commands::Ca(crate::CaArgs {
        action: crate::CaAction::Init { create_vault: true, .. },
    }) = &cli.command
    {
        let created = op::create_vault_standalone(&cli.vault, cli.account.as_deref())?;
        output::print_result(&format!("Created vault {}", created.name), true);
    }

    let mut app = AppContext::<ShellRunner>::new(&cli.vault, cli.account)?;

    // Determine if we need eager CA loading.
    // "Init-like" commands skip CA retrieval because the CA may not exist yet.
    let needs_ca = !matches!(
        &cli.command,
        Commands::Ca(crate::CaArgs {
            action: crate::CaAction::Init { .. } | crate::CaAction::Import { .. },
        }) | Commands::Csr(_)
            | Commands::Database(crate::DatabaseArgs {
                action: crate::DatabaseAction::Rebuild { .. },
            })
            | Commands::Vault(_)
            | Commands::Aws(_)
    );

    if needs_ca {
        app.ensure_ca()?;
        ca::warn_ca_expiry(&app);
    }

    match cli.command {
        Commands::Aws(args) => aws::dispatch(args, &mut app),
        Commands::Ca(args) => ca::dispatch(args, &mut app),
        Commands::Cert(args) => cert::dispatch(args, &mut app),
        Commands::Crl(args) => crl::dispatch(args, &mut app),
        Commands::Csr(args) => csr::dispatch(args, &mut app),
        Commands::Database(args) => database::dispatch(args, &mut app),
        Commands::Dkim(args) => dkim::dispatch(args, &mut app),
        Commands::Openvpn(args) => openvpn::dispatch(args, &mut app),
        Commands::Vault(args) => vault::dispatch(args, &mut app),
    }
}
