use std::io::{self, BufRead, Write};

use chrono::Utc;
use opca_core::error::OpcaError;
use opca_core::op::{Runner, ShellRunner};
use opca_core::services::acme_broker::api::IssuerState;
use opca_core::services::acme_broker::{
    BrokerNotice, Endpoint, Renewal, concerns, fetch_offer, issuance, parse_pairing,
};

use crate::app::{AppContext, with_lock};
use crate::output;
use crate::{BrokerAction, BrokerArgs};

pub fn dispatch(args: BrokerArgs, app: &mut AppContext<ShellRunner>) -> Result<(), OpcaError> {
    match args.action {
        BrokerAction::Enrol {
            pairing,
            domains,
            yes,
        } => handle_enrol(app, &pairing, domains, yes),
        BrokerAction::List => handle_list(app),
        BrokerAction::Status { id } => handle_status(app, id),
        BrokerAction::Renew { all: true, .. } => handle_renew_all(app),
        BrokerAction::Renew {
            id, change_domains, ..
        } => handle_renew(
            app,
            id.expect("clap requires an id without --all"),
            change_domains,
        ),
        BrokerAction::Revoke { id } => handle_revoke(app, id),
    }
}

/// Whether the answer to `question` on `input` is yes.
fn confirmed(question: &str, input: impl BufRead) -> io::Result<bool> {
    print!("  {question} [y/N] ");
    io::stdout().flush()?;
    let answer = input.lines().next().transpose()?.unwrap_or_default();
    Ok(matches!(answer.trim(), "y" | "Y" | "yes"))
}

fn handle_enrol<R: Runner>(
    app: &mut AppContext<R>,
    pairing: &str,
    domains: Vec<String>,
    yes: bool,
) -> Result<(), OpcaError> {
    output::title("Enrolling ACME Broker");
    let pairing = parse_pairing(pairing)?;
    let endpoint = Endpoint::of_pairing(&pairing);
    let offer = fetch_offer(&pairing)?;
    output::info("Host", &offer.host);
    output::info("Address", &endpoint.url());
    output::info("Key (SHA-256)", &endpoint.pin().to_string());
    output::info(
        "Broker",
        &format!(
            "{}, step-ca {}",
            offer.versions.broker, offer.versions.step_ca
        ),
    );
    if offer.configured_domains.is_empty() {
        if domains.is_empty() {
            return Err(OpcaError::Other(
                "The broker has no domains configured; give them with --domain".into(),
            ));
        }
        output::info("Domains", &domains.join(", "));
    } else {
        output::info(
            "Domains",
            &format!(
                "{} (set on the broker)",
                offer.configured_domains.join(", ")
            ),
        );
    }
    println!();
    if !yes && !confirmed("Sign a subordinate CA for this broker?", io::stdin().lock())? {
        output::warning("Not enrolled");
        return Ok(());
    }
    with_lock(app, "broker_enrol", |app| {
        let ca = app.ca.as_mut().ok_or(OpcaError::CaNotFound)?;
        let operator = ca.operator()?;
        let enrolled = ca.enrol_broker(&operator, &pairing, &offer, issuance(domains))?;
        let broker = &enrolled.broker;
        output::print_result(
            &format!(
                "Enrol broker {} (serial {}) for {}",
                broker.id,
                broker.subordinate_serial,
                broker.permitted_domains.join(", ")
            ),
            true,
        );
        Ok(())
    })
}

fn handle_list<R: Runner>(app: &mut AppContext<R>) -> Result<(), OpcaError> {
    output::title("ACME Brokers");
    let ca = app.ca.as_ref().ok_or(OpcaError::CaNotFound)?;
    let now = Utc::now();
    let rows: Vec<Vec<String>> = ca
        .list_subordinates()?
        .iter()
        .filter(|b| b.url.is_some())
        .map(|b| {
            let attention: Vec<String> = concerns(b, now).iter().map(|c| c.to_string()).collect();
            let or_dash = |value: &Option<String>| value.clone().unwrap_or_else(|| "-".into());
            vec![
                b.id.to_string(),
                or_dash(&b.cn),
                b.permitted_domains.join(", "),
                b.state.as_str().to_string(),
                or_dash(&b.expiry_date),
                or_dash(&b.last_contact),
                if attention.is_empty() {
                    "-".into()
                } else {
                    attention.join(", ")
                },
            ]
        })
        .collect();
    output::print_table(
        &[
            "ID",
            "Broker",
            "Domains",
            "State",
            "Expiry",
            "Last contact",
            "Attention",
        ],
        &rows,
    );
    println!();
    println!("  Total: {} broker(s)", rows.len());
    Ok(())
}

fn handle_status<R: Runner>(app: &mut AppContext<R>, id: i64) -> Result<(), OpcaError> {
    output::title("ACME Broker Status");
    with_lock(app, "broker_status", |app| {
        let ca = app.ca.as_mut().ok_or(OpcaError::CaNotFound)?;
        let operator = ca.operator()?;
        let status = ca.broker_status(&operator, id)?;
        let state = match status.state {
            IssuerState::Issuing => "issuing",
            IssuerState::StepCaDown => "step-ca down",
            IssuerState::Revoked => "revoked",
        };
        output::info("State", state);
        output::info("Subordinate serial", &status.subordinate_serial);
        output::info("Subordinate expires", &status.subordinate_not_after);
        output::info("Domains", &status.config.permitted_domains.join(", "));
        output::info(
            "Leaf days",
            &format!(
                "{} (at most {})",
                status.config.leaf_days, status.config.leaf_max_days
            ),
        );
        output::info(
            "Versions",
            &format!(
                "broker {}, step-ca {}, API {}",
                status.versions.broker, status.versions.step_ca, status.versions.api
            ),
        );
        Ok(())
    })
}

fn print_renewal(id: i64, renewal: &Renewal) {
    output::print_result(&format!("Broker {id}: {renewal}"), renewal.is_renewed());
    if let Renewal::DomainsChanged { .. } = renewal {
        println!("  Run `opca broker renew {id} --change-domains` to confirm them.");
    }
}

fn handle_renew<R: Runner>(
    app: &mut AppContext<R>,
    id: i64,
    change_domains: bool,
) -> Result<(), OpcaError> {
    output::title("Renewing ACME Broker");
    with_lock(app, "broker_renew", |app| {
        let ca = app.ca.as_mut().ok_or(OpcaError::CaNotFound)?;
        let operator = ca.operator()?;
        let renewal = ca.renew_broker(&operator, id, change_domains)?;
        print_renewal(id, &renewal);
        if !renewal.is_renewed() {
            return Err(OpcaError::Other(format!("Broker {id} was not renewed")));
        }
        Ok(())
    })
}

fn handle_renew_all<R: Runner>(app: &mut AppContext<R>) -> Result<(), OpcaError> {
    output::title("Renewing All ACME Brokers");
    with_lock(app, "broker_renew_all", |app| {
        let ca = app.ca.as_mut().ok_or(OpcaError::CaNotFound)?;
        let operator = ca.operator()?;
        let renewals = ca.renew_all_brokers(&operator)?;
        for r in &renewals {
            print_renewal(r.id, &r.renewal);
        }
        let missed = renewals.iter().filter(|r| !r.renewal.is_renewed()).count();
        println!();
        println!(
            "  Total: {} broker(s), {missed} not renewed",
            renewals.len()
        );
        if missed > 0 {
            return Err(OpcaError::Other(format!(
                "{missed} of {} brokers were not renewed",
                renewals.len()
            )));
        }
        Ok(())
    })
}

fn handle_revoke<R: Runner>(app: &mut AppContext<R>, id: i64) -> Result<(), OpcaError> {
    output::title("Revoking ACME Broker");
    with_lock(app, "broker_revoke", |app| {
        let ca = app.ca.as_mut().ok_or(OpcaError::CaNotFound)?;
        let operator = ca.operator()?;
        let revocation = ca.revoke_broker(&operator, id)?;
        output::print_result(
            &format!(
                "Revoke broker {id} (serial {})",
                revocation.broker.subordinate_serial
            ),
            true,
        );
        let crl_pem = ca.generate_crl()?;
        output::print_result("CRL regenerated", true);
        match &revocation.notice {
            BrokerNotice::Told { .. } => output::print_result("Tell the broker", true),
            BrokerNotice::NotTold { error } => {
                output::print_result("Tell the broker", false);
                output::warning(&format!(
                    "The revocation stands, but the broker was not told ({error}); \
                     run `opca broker revoke {id}` again to tell it"
                ));
            }
        }
        print!("{crl_pem}");
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;
    use crate::{Cli, Commands};

    fn parse(args: &[&str]) -> Result<BrokerAction, clap::Error> {
        let cli = Cli::try_parse_from([&["opca", "-v", "CA"], args].concat())?;
        match cli.command {
            Commands::Broker(args) => Ok(args.action),
            _ => panic!("not a broker command"),
        }
    }

    #[test]
    fn renew_takes_one_id_or_all_but_not_both() {
        assert!(matches!(
            parse(&["broker", "renew", "3", "--change-domains"]),
            Ok(BrokerAction::Renew {
                id: Some(3),
                all: false,
                change_domains: true
            })
        ));
        assert!(matches!(
            parse(&["broker", "renew", "--all"]),
            Ok(BrokerAction::Renew {
                id: None,
                all: true,
                ..
            })
        ));
        for refused in [
            &["broker", "renew"][..],
            &["broker", "renew", "3", "--all"],
            &["broker", "renew", "--all", "--change-domains"],
        ] {
            assert!(parse(refused).is_err(), "{refused:?}");
        }
    }

    #[test]
    fn enrol_takes_the_pairing_string_and_repeated_domains() {
        let Ok(BrokerAction::Enrol {
            pairing,
            domains,
            yes,
        }) = parse(&[
            "broker",
            "enrol",
            "opca-enrol://acme.home.arpa:9443#pin=ab&code=CD",
            "-d",
            "home.arpa",
            "--domain",
            "lab.example",
            "--yes",
        ])
        else {
            panic!("enrol did not parse");
        };
        assert_eq!(pairing, "opca-enrol://acme.home.arpa:9443#pin=ab&code=CD");
        assert_eq!(domains, ["home.arpa", "lab.example"]);
        assert!(yes);
    }

    #[test]
    fn only_a_yes_confirms() {
        for yes in ["y\n", "Y\n", " yes \n"] {
            assert!(confirmed("Sign?", yes.as_bytes()).unwrap(), "{yes:?}");
        }
        for no in ["\n", "n\n", "no\n", "yep\n", ""] {
            assert!(!confirmed("Sign?", no.as_bytes()).unwrap(), "{no:?}");
        }
    }
}
