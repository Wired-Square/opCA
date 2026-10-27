use opca_core::error::OpcaError;
use opca_core::op::{Runner, ShellRunner};
use opca_core::services::ca::subordinate::SignedSubordinate;

use crate::app::{AppContext, with_lock};
use crate::output;
use crate::{SubordinateAction, SubordinateArgs};

pub fn dispatch(args: SubordinateArgs, app: &mut AppContext<ShellRunner>) -> Result<(), OpcaError> {
    match args.action {
        SubordinateAction::Sign {
            csr_file,
            domains,
            days,
        } => handle_sign(app, csr_file, domains, days),
        SubordinateAction::Renew {
            id,
            csr_file,
            domains,
            change_domains,
            days,
        } => handle_renew(app, id, csr_file, domains, change_domains, days),
        SubordinateAction::Revoke { id } => handle_revoke(app, id),
        SubordinateAction::List => handle_list(app),
    }
}

fn handle_sign<R: Runner>(
    app: &mut AppContext<R>,
    csr_file: String,
    domains: Vec<String>,
    days: Option<u32>,
) -> Result<(), OpcaError> {
    output::title("Signing Subordinate CA");
    let csr = std::fs::read(csr_file)?;
    with_lock(app, "subordinate_sign", |app| {
        let ca = app.ca.as_mut().ok_or(OpcaError::CaNotFound)?;
        print_signed("Signed", &ca.sign_subordinate(&csr, &domains, days)?);
        Ok(())
    })
}

fn handle_renew<R: Runner>(
    app: &mut AppContext<R>,
    id: i64,
    csr_file: String,
    domains: Vec<String>,
    change_domains: bool,
    days: Option<u32>,
) -> Result<(), OpcaError> {
    output::title("Renewing Subordinate CA");
    let csr = std::fs::read(csr_file)?;
    let domains = (!domains.is_empty()).then_some(domains.as_slice());
    with_lock(app, "subordinate_renew", |app| {
        let ca = app.ca.as_mut().ok_or(OpcaError::CaNotFound)?;
        let signed = ca.renew_subordinate(id, &csr, domains, change_domains, days)?;
        print_signed("Renewed", &signed);
        Ok(())
    })
}

fn handle_revoke<R: Runner>(app: &mut AppContext<R>, id: i64) -> Result<(), OpcaError> {
    output::title("Revoking Subordinate CA");
    with_lock(app, "subordinate_revoke", |app| {
        let ca = app.ca.as_mut().ok_or(OpcaError::CaNotFound)?;
        let broker = ca.revoke_subordinate(id)?;
        output::print_result(
            &format!(
                "Revoke subordinate {id} (serial {})",
                broker.subordinate_serial
            ),
            true,
        );
        let crl_pem = ca.generate_crl()?;
        output::print_result("CRL regenerated", true);
        print!("{crl_pem}");
        Ok(())
    })
}

fn handle_list<R: Runner>(app: &mut AppContext<R>) -> Result<(), OpcaError> {
    output::title("Subordinate CAs");
    let ca = app.ca.as_ref().ok_or(OpcaError::CaNotFound)?;
    let brokers = ca.list_subordinates()?;
    let rows: Vec<Vec<String>> = brokers
        .iter()
        .map(|b| {
            vec![
                b.id.to_string(),
                b.subordinate_serial.clone(),
                b.cn.clone().unwrap_or_default(),
                b.permitted_domains.join(", "),
                b.state.as_str().to_string(),
                b.expiry_date.clone().unwrap_or_default(),
                b.url.clone().unwrap_or_else(|| "-".into()),
            ]
        })
        .collect();
    output::print_table(
        &["ID", "Serial", "CN", "Domains", "State", "Expiry", "Broker"],
        &rows,
    );
    println!();
    println!("  Total: {} subordinate(s)", rows.len());
    Ok(())
}

fn print_signed(verb: &str, signed: &SignedSubordinate) {
    let broker = &signed.broker;
    output::print_result(
        &format!(
            "{verb} subordinate {} (serial {}) for {}",
            broker.id,
            broker.subordinate_serial,
            broker.permitted_domains.join(", ")
        ),
        true,
    );
    println!();
    print!("{}", signed.cert_pem);
}
