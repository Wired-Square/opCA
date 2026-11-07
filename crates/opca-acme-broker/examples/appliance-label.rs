//! Prints the image's `com.wiredsquare.appliance.manifest` label for one arch,
//! checked by the console's own validator.
//!
//! usage: appliance-label arm64|amd64

use std::process::ExitCode;

use opca_acme_broker::app::{ACME_PORT, API_PORT, DATA, NAME, PKI_PORT};
use wslib_appliance_types::manifest::{
    AppArch, AppImage, AppLabel, AppListener, AppManifest, AppOption, AppOptionKind, AppVolume,
    ListenerProtocol,
};

/// The console swaps in the loaded image; `validate` wants a well-formed one meanwhile.
const PLACEHOLDER_DIGEST: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

fn manifest(arch: AppArch) -> AppManifest {
    let image = AppImage {
        repository: "ghcr.io/wired-square/opca-acme".into(),
        digest: PLACEHOLDER_DIGEST.into(),
    };
    let mut manifest = AppManifest::new(NAME, env!("CARGO_PKG_VERSION"), image, vec![arch]);
    manifest.sockets.app = true;
    manifest.volumes = vec![AppVolume {
        name: "data".into(),
        at: DATA.into(),
    }];
    let listener = |name: &str, port| AppListener {
        name: name.into(),
        protocol: ListenerProtocol::Tcp,
        port,
        dns_sd: None,
        enabled: true,
    };
    manifest.listeners = vec![
        listener("api", API_PORT),
        listener("acme", ACME_PORT),
        listener("pki", PKI_PORT),
    ];
    manifest.health.start_timeout_s = Some(60);
    let mut host = AppOption::new("host", AppOptionKind::String);
    host.required = true;
    host.label = Some("Host".into());
    host.description = Some(
        "The name opCA dials and ACME clients reach the broker by. It must sit inside the \
         permitted domains."
            .into(),
    );
    let mut domains = AppOption::new("domains", AppOptionKind::Strings);
    domains.label = Some("Permitted domains".into());
    domains.description =
        Some("The domains to ask opCA for. Left empty, they're chosen in opCA.".into());
    manifest.options = vec![host, domains];
    manifest.schema = manifest.oldest_schema();
    manifest
}

/// The manifest as the label carries it: without its image.
fn label(manifest: &AppManifest) -> Result<String, String> {
    manifest.validate().map_err(|e| e.to_string())?;
    let mut value = serde_json::to_value(manifest).map_err(|e| e.to_string())?;
    value
        .as_object_mut()
        .and_then(|fields| fields.remove("image"))
        .ok_or("the manifest has no image")?;
    let text = value.to_string();
    serde_json::from_str::<AppLabel>(&text).map_err(|e| e.to_string())?;
    Ok(text)
}

fn arch(name: &str) -> Option<AppArch> {
    match name {
        "arm64" => Some(AppArch::Arm64),
        "amd64" => Some(AppArch::Amd64),
        _ => None,
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(arch) = (args.len() == 1).then(|| arch(&args[0])).flatten() else {
        eprintln!("usage: appliance-label arm64|amd64");
        return ExitCode::from(2);
    };
    match label(&manifest(arch)) {
        Ok(label) => {
            println!("{label}");
            ExitCode::SUCCESS
        }
        Err(refusal) => {
            eprintln!("the manifest is refused: {refusal}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_arch_label_validates_and_reads_back_as_the_console_reads_it() {
        for arch in [AppArch::Arm64, AppArch::Amd64] {
            let manifest = manifest(arch);
            let label: AppLabel = serde_json::from_str(&label(&manifest).unwrap()).unwrap();
            assert_eq!(
                AppManifest::from_label(label, manifest.image.clone()),
                manifest
            );
            assert_eq!(manifest.schema, 3);
        }
    }

    #[test]
    fn host_is_required_and_missing_until_set() {
        let manifest = manifest(AppArch::Arm64);
        let checked = manifest.check_options(&Default::default()).unwrap();
        assert_eq!(checked.missing, ["host"]);
        let given = serde_json::json!({"host": "acme.home.example", "domains": ["home.example"]});
        let checked = manifest.check_options(given.as_object().unwrap()).unwrap();
        assert!(checked.missing.is_empty() && checked.dropped.is_empty());
    }
}
