use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use opca_acme_broker::{CONFIG_PATH, Config, Error, cli};

const USAGE: &str = "usage: opca-acme [--config <path>] <command>

  pairing                 issue a new pairing code and print its URI, while enrolling
  status                  show the broker's state from its files
  enrol --reopen [--yes]  as root: drop the enrolment and pair again with a new key";

enum Command {
    Pairing,
    Status,
    Reopen { confirmed: bool },
}

fn main() -> ExitCode {
    let (path, command) = match parse(std::env::args().skip(1).collect()) {
        Some(parsed) => parsed,
        None => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match run(&path, command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("opca-acme: {error}");
            ExitCode::FAILURE
        }
    }
}

fn parse(mut args: Vec<String>) -> Option<(PathBuf, Command)> {
    let mut path = PathBuf::from(CONFIG_PATH);
    if let Some(at) = args.iter().position(|arg| arg == "--config") {
        path = args.get(at + 1)?.into();
        args.drain(at..=at + 1);
    }
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let command = match args[..] {
        ["pairing"] => Command::Pairing,
        ["status"] => Command::Status,
        ["enrol", "--reopen"] => Command::Reopen { confirmed: false },
        ["enrol", "--reopen", "--yes"] | ["enrol", "--yes", "--reopen"] => {
            Command::Reopen { confirmed: true }
        }
        _ => return None,
    };
    Some((path, command))
}

fn run(path: &Path, command: Command) -> Result<(), Error> {
    let config = Config::load(path)?;
    let state = &config.state_dir;
    cli::become_owner(state, matches!(command, Command::Reopen { .. }))?;
    match command {
        Command::Pairing => println!("{}", cli::pairing(&config)?.expose()),
        Command::Status => println!("{}", cli::status(&config)?),
        Command::Reopen { confirmed } => {
            if !confirmed && !confirm()? {
                return Err("not reopened".into());
            }
            let uri = cli::reopen(&config)?;
            if !cli::tell_daemon(state) {
                eprintln!("the broker isn't running; it reads the new state when it starts");
            }
            println!("{}", uri.expose());
        }
    }
    Ok(())
}

fn confirm() -> Result<bool, Error> {
    print!(
        "This archives the enrolment, deletes the subordinate key and stops step-ca until \
         opCA pairs again.\nType 'reopen' to continue: "
    );
    std::io::stdout().flush()?;
    let mut answer = String::new();
    std::io::stdin().lock().read_line(&mut answer)?;
    Ok(answer.trim() == "reopen")
}
