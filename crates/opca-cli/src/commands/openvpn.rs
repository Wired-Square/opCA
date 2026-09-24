use std::collections::HashMap;

use opca_core::constants::{DEFAULT_KEY_SIZE, DEFAULT_OP_CONF};
use opca_core::crypto::utils::{generate_dh_params, generate_ta_key, verify_dh_params, verify_ta_key};
use opca_core::error::OpcaError;
use opca_core::op::{CommandRunner, ShellRunner, StoreAction};

use crate::app::AppContext;
use crate::output;
use crate::{OpenvpnAction, OpenvpnArgs};

pub fn dispatch(args: OpenvpnArgs, app: &mut AppContext<ShellRunner>) -> Result<(), OpcaError> {
    match args.action {
        OpenvpnAction::Generate {
            dh,
            ta_key,
            profile,
            server,
            setup,
            dest,
            cn,
            file,
            template,
        } => handle_generate(app, dh, ta_key, profile, server, setup, dest, cn, file, template),
        OpenvpnAction::Get {
            dh,
            ta_key,
            template,
        } => handle_get(app, dh, ta_key, template),
        OpenvpnAction::Import {
            dh,
            ta_key,
            file,
            dh_file,
            ta_key_file,
        } => handle_import(app, dh, ta_key, file, dh_file, ta_key_file),
    }
}

fn resolve_store_action<R: CommandRunner>(op: &opca_core::op::Op<R>) -> StoreAction {
    if op.item_exists(DEFAULT_OP_CONF.openvpn_title) {
        StoreAction::Edit
    } else {
        StoreAction::Create
    }
}

fn build_template_boilerplate(vault: &str) -> String {
    let ovpn = DEFAULT_OP_CONF.openvpn_title;
    let ca_title = DEFAULT_OP_CONF.ca_title;
    let cert_item = DEFAULT_OP_CONF.cert_item;
    let key_item = DEFAULT_OP_CONF.key_item;
    let ta_path = DEFAULT_OP_CONF.ta_item.replace('.', "/");

    format!(
        r#"#
# Client - {{{{ op://{vault}/$OPCA_USER/cn }}}}
#

client
dev tun
proto udp
remote {{{{ op://{vault}/{ovpn}/server/hostname }}}} {{{{ op://{vault}/{ovpn}/server/port }}}}
resolv-retry infinite
nobind
persist-key
persist-tun
cipher {{{{ op://{vault}/{ovpn}/server/cipher }}}}
auth {{{{ op://{vault}/{ovpn}/server/auth }}}}
verb 3
key-direction 1
mssfix 1300
<ca>
{{{{ op://{vault}/{ca_title}/{cert_item} }}}}
</ca>
<cert>
{{{{ op://{vault}/$OPCA_USER/{cert_item} }}}}
</cert>
<key>
{{{{ op://{vault}/$OPCA_USER/{key_item} }}}}
</key>
<tls-auth>
{{{{ op://{vault}/{ovpn}/{ta_path} }}}}
</tls-auth>
"#
    )
}

#[allow(clippy::too_many_arguments)]
fn handle_generate<R: CommandRunner>(
    app: &mut AppContext<R>,
    dh: bool,
    ta_key: bool,
    profile: bool,
    _server: bool,
    setup: bool,
    dest: Option<String>,
    cn: Option<String>,
    file: Option<String>,
    template: Option<String>,
) -> Result<(), OpcaError> {
    if !dh && !ta_key && !profile && !_server && !setup {
        return Err(OpcaError::Other(
            "At least one of --dh, --ta-key, --profile, --server, or --setup is required".into(),
        ));
    }

    if setup {
        let template_name = template.as_deref().ok_or_else(|| {
            OpcaError::Other("--setup requires --template".into())
        })?;
        return handle_setup(app, template_name);
    }

    if dh {
        handle_generate_dh(app)?;
    }
    if ta_key {
        handle_generate_ta(app)?;
    }
    if profile {
        let template_name = template.as_deref().ok_or_else(|| {
            OpcaError::Other("--profile requires --template".into())
        })?;
        handle_generate_profiles(app, cn, file, template_name, dest.as_deref())?;
    }
    if _server {
        handle_generate_server(app)?;
    }

    Ok(())
}

fn handle_generate_dh<R: CommandRunner>(app: &mut AppContext<R>) -> Result<(), OpcaError> {
    output::title("Generating Diffie-Hellman Parameters");

    let dh_pem = generate_dh_params(DEFAULT_KEY_SIZE.dh)?;
    let dh_keysize = verify_dh_params(dh_pem.as_bytes())?;
    output::print_result(&format!("DH parameters generated ({dh_keysize} bits)"), true);

    let op = app.op()?;
    let action = resolve_store_action(op);
    let attrs: Vec<String> = vec![
        format!("{}={}", DEFAULT_OP_CONF.dh_item, dh_pem),
        format!("{}={}", DEFAULT_OP_CONF.dh_key_size_item, dh_keysize),
    ];
    let attr_refs: Vec<&str> = attrs.iter().map(|s| s.as_str()).collect();

    op.store_item(
        DEFAULT_OP_CONF.openvpn_title,
        Some(&attr_refs),
        action,
        DEFAULT_OP_CONF.category,
        None,
        None,
    )?;

    output::print_result("Stored in 1Password", true);
    println!();
    print!("{dh_pem}");

    Ok(())
}

fn handle_generate_ta<R: CommandRunner>(app: &mut AppContext<R>) -> Result<(), OpcaError> {
    output::title("Generating TLS Authentication Key");

    let ta_pem = generate_ta_key(DEFAULT_KEY_SIZE.ta)?;
    let ta_keysize = verify_ta_key(ta_pem.as_bytes())?;

    if ta_keysize < DEFAULT_KEY_SIZE.ta {
        return Err(OpcaError::Other(
            "Generated TA key does not meet minimum key size".into(),
        ));
    }

    output::print_result(&format!("TA key generated ({ta_keysize} bits)"), true);

    let op = app.op()?;
    let action = resolve_store_action(op);
    let attrs: Vec<String> = vec![
        format!("{}={}", DEFAULT_OP_CONF.ta_item, ta_pem),
        format!("{}={}", DEFAULT_OP_CONF.ta_key_size_item, ta_keysize),
    ];
    let attr_refs: Vec<&str> = attrs.iter().map(|s| s.as_str()).collect();

    op.store_item(
        DEFAULT_OP_CONF.openvpn_title,
        Some(&attr_refs),
        action,
        DEFAULT_OP_CONF.category,
        None,
        None,
    )?;

    output::print_result("Stored in 1Password", true);
    println!();
    print!("{ta_pem}");

    Ok(())
}

fn handle_generate_profiles<R: CommandRunner>(
    app: &mut AppContext<R>,
    cn: Option<String>,
    file: Option<String>,
    template_name: &str,
    dest_vault: Option<&str>,
) -> Result<(), OpcaError> {
    output::title("Generating VPN Profiles");

    let cn_list: Vec<String> = if let Some(file) = file {
        let content = std::fs::read_to_string(&file)?;
        content
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect()
    } else if let Some(cn) = cn {
        vec![cn]
    } else {
        return Err(OpcaError::Other(
            "--profile requires --cn or --file".into(),
        ));
    };

    let op = app.op()?;
    for profile_cn in &cn_list {
        // Read template
        let url = op.mk_url(
            DEFAULT_OP_CONF.openvpn_title,
            Some(&format!("template/{template_name}")),
        );
        let template_content = op.read_item(&url)?;

        // Inject with OPCA_USER env var
        let mut env_vars = HashMap::new();
        env_vars.insert("OPCA_USER".to_string(), profile_cn.clone());

        let profile_content = op.inject_item(&template_content, Some(&env_vars))?;

        // Store as document
        let item_title = format!("VPN_{profile_cn}");
        let filename = format!("{profile_cn}-{template_name}.ovpn");

        op.store_document(
            &item_title,
            &filename,
            &profile_content,
            StoreAction::Create,
            dest_vault,
        )?;

        output::print_result(&format!("Profile '{item_title}' stored"), true);
    }

    Ok(())
}

fn handle_generate_server<R: CommandRunner>(app: &mut AppContext<R>) -> Result<(), OpcaError> {
    output::title("Generating OpenVPN Server Configuration");

    let op = app.op()?;
    let action = resolve_store_action(op);

    let attrs: Vec<String> = vec![
        "server.hostname[text]=vpn.domain.com.au".to_string(),
        "server.port[text]=1194".to_string(),
        "server.cipher[text]=aes-256-gcm".to_string(),
        "server.auth[text]=sha256".to_string(),
    ];
    let attr_refs: Vec<&str> = attrs.iter().map(|s| s.as_str()).collect();

    op.store_item(
        DEFAULT_OP_CONF.openvpn_title,
        Some(&attr_refs),
        action,
        DEFAULT_OP_CONF.category,
        None,
        None,
    )?;

    output::print_result("Server configuration stored", true);
    Ok(())
}

fn handle_setup<R: CommandRunner>(
    app: &mut AppContext<R>,
    template_name: &str,
) -> Result<(), OpcaError> {
    output::title("OpenVPN Server Setup");

    let op = app.op()?;
    let item_exists = op.item_exists(DEFAULT_OP_CONF.openvpn_title);
    let mut attrs: Vec<String> = Vec::new();

    // Server defaults
    attrs.push("server.hostname[text]=vpn.domain.com.au".to_string());
    attrs.push("server.port[text]=1194".to_string());
    attrs.push("server.cipher[text]=aes-256-gcm".to_string());
    attrs.push("server.auth[text]=sha256".to_string());

    // Template
    let boilerplate = build_template_boilerplate(&op.vault);
    attrs.push(format!("template.{template_name}[text]={boilerplate}"));

    // DH parameters
    let dh_pem = generate_dh_params(DEFAULT_KEY_SIZE.dh)?;
    let dh_keysize = verify_dh_params(dh_pem.as_bytes())?;
    output::print_result(&format!("DH parameters generated ({dh_keysize} bits)"), true);
    attrs.push(format!("{}={}", DEFAULT_OP_CONF.dh_item, dh_pem));
    attrs.push(format!("{}={}", DEFAULT_OP_CONF.dh_key_size_item, dh_keysize));

    // TA key
    let ta_pem = generate_ta_key(DEFAULT_KEY_SIZE.ta)?;
    let ta_keysize = verify_ta_key(ta_pem.as_bytes())?;
    output::print_result(&format!("TA key generated ({ta_keysize} bits)"), true);
    attrs.push(format!("{}={}", DEFAULT_OP_CONF.ta_item, ta_pem));
    attrs.push(format!("{}={}", DEFAULT_OP_CONF.ta_key_size_item, ta_keysize));

    let action = if item_exists {
        StoreAction::Edit
    } else {
        StoreAction::Create
    };

    let attr_refs: Vec<&str> = attrs.iter().map(|s| s.as_str()).collect();
    let op = app.op()?;
    op.store_item(
        DEFAULT_OP_CONF.openvpn_title,
        Some(&attr_refs),
        action,
        DEFAULT_OP_CONF.category,
        None,
        None,
    )?;

    output::print_result("OpenVPN server setup complete", true);
    Ok(())
}

fn handle_get<R: CommandRunner>(
    app: &mut AppContext<R>,
    dh: bool,
    ta_key: bool,
    template: Option<String>,
) -> Result<(), OpcaError> {
    if !dh && !ta_key && template.is_none() {
        return Err(OpcaError::Other(
            "At least one of --dh, --ta-key, or --template is required".into(),
        ));
    }

    let op = app.op()?;

    if dh {
        let url = op.mk_url(
            DEFAULT_OP_CONF.openvpn_title,
            Some(&DEFAULT_OP_CONF.dh_item.replace('.', "/")),
        );
        let dh_pem = op.read_item(&url)?;
        let dh_keysize = verify_dh_params(dh_pem.trim().as_bytes())?;
        output::print_result(&format!("DH parameters ({dh_keysize} bits)"), true);
        println!();
        print!("{}", dh_pem.trim());
        println!();
    }

    if ta_key {
        let url = op.mk_url(
            DEFAULT_OP_CONF.openvpn_title,
            Some(&DEFAULT_OP_CONF.ta_item.replace('.', "/")),
        );
        let ta_pem = op.read_item(&url)?;
        let ta_keysize = verify_ta_key(ta_pem.trim().as_bytes())?;
        output::print_result(&format!("TA key ({ta_keysize} bits)"), true);
        println!();
        print!("{}", ta_pem.trim());
        println!();
    }

    if let Some(ref name) = template {
        let url = op.mk_url(
            DEFAULT_OP_CONF.openvpn_title,
            Some(&format!("template/{name}")),
        );
        let content = op.read_item(&url)?;
        println!("{}", content.trim());
    }

    Ok(())
}

fn handle_import<R: CommandRunner>(
    app: &mut AppContext<R>,
    dh: bool,
    ta_key: bool,
    file: Option<String>,
    dh_file: Option<String>,
    ta_key_file: Option<String>,
) -> Result<(), OpcaError> {
    if !dh && !ta_key {
        return Err(OpcaError::Other(
            "At least one of --dh or --ta-key is required".into(),
        ));
    }

    if dh {
        let path = dh_file.as_ref().or(file.as_ref()).ok_or_else(|| {
            OpcaError::Other("--dh requires --dh-file or --file".into())
        })?;
        output::title("Importing DH Parameters");

        let dh_pem = std::fs::read_to_string(path)?;
        let dh_keysize = verify_dh_params(dh_pem.trim().as_bytes())?;

        if dh_keysize < DEFAULT_KEY_SIZE.dh {
            return Err(OpcaError::Other(format!(
                "DH parameters key size ({dh_keysize}) is below minimum ({})",
                DEFAULT_KEY_SIZE.dh
            )));
        }

        output::print_result(&format!("DH parameters verified ({dh_keysize} bits)"), true);

        let op = app.op()?;
        let action = resolve_store_action(op);
        let attrs: Vec<String> = vec![
            format!("{}={}", DEFAULT_OP_CONF.dh_item, dh_pem.trim()),
            format!("{}={}", DEFAULT_OP_CONF.dh_key_size_item, dh_keysize),
        ];
        let attr_refs: Vec<&str> = attrs.iter().map(|s| s.as_str()).collect();

        op.store_item(
            DEFAULT_OP_CONF.openvpn_title,
            Some(&attr_refs),
            action,
            DEFAULT_OP_CONF.category,
            None,
            None,
        )?;

        output::print_result("Stored in 1Password", true);
    }

    if ta_key {
        let path = ta_key_file.as_ref().or(file.as_ref()).ok_or_else(|| {
            OpcaError::Other("--ta-key requires --ta-key-file or --file".into())
        })?;
        output::title("Importing TLS Authentication Key");

        let ta_pem = std::fs::read_to_string(path)?;
        let ta_keysize = verify_ta_key(ta_pem.trim().as_bytes())?;

        if ta_keysize < DEFAULT_KEY_SIZE.ta {
            return Err(OpcaError::Other(format!(
                "TA key size ({ta_keysize}) is below minimum ({})",
                DEFAULT_KEY_SIZE.ta
            )));
        }

        output::print_result(&format!("TA key verified ({ta_keysize} bits)"), true);

        let op = app.op()?;
        let action = resolve_store_action(op);
        let attrs: Vec<String> = vec![
            format!("{}={}", DEFAULT_OP_CONF.ta_item, ta_pem.trim()),
            format!("{}={}", DEFAULT_OP_CONF.ta_key_size_item, ta_keysize),
        ];
        let attr_refs: Vec<&str> = attrs.iter().map(|s| s.as_str()).collect();

        op.store_item(
            DEFAULT_OP_CONF.openvpn_title,
            Some(&attr_refs),
            action,
            DEFAULT_OP_CONF.category,
            None,
            None,
        )?;

        output::print_result("Stored in 1Password", true);
    }

    Ok(())
}
