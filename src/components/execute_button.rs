use super::save_certificate_files_to_zip;
use crate::CertGenApp;
use crate::cert_config::{CertConfig, ExportOptions, KeyAlgorithm, KeyEncoding};
use crate::internal_gen::generate_cert_request;
use eframe::egui;
use std::sync::mpsc;

/// Builds a best-effort OpenSSL CLI snippet that reproduces the request.
///
/// This is informational only — the app itself never shells out. Non-default
/// export options (DER encoding, passphrase encryption, PKCS#1) are summarized
/// in a trailing comment, since they are post-generation packaging choices.
pub fn build_recreate_command(
    key_algorithm: &KeyAlgorithm,
    name: &str,
    export: &ExportOptions,
) -> String {
    let outform = if export.encoding == KeyEncoding::Der {
        " -outform DER"
    } else {
        ""
    };
    let mut cmd = match key_algorithm {
        KeyAlgorithm::Rsa2048 | KeyAlgorithm::Rsa3072 | KeyAlgorithm::Rsa4096 => {
            format!("openssl req -new{outform} -out {name}.csr -config {name}.cnf")
        }
        KeyAlgorithm::EcdsaP256 => format!(
            "openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out {name}.key\nopenssl req -new{outform} -out {name}.csr -key {name}.key -config {name}.cnf"
        ),
        KeyAlgorithm::EcdsaP384 => format!(
            "openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out {name}.key\nopenssl req -new{outform} -out {name}.csr -key {name}.key -config {name}.cnf"
        ),
        KeyAlgorithm::Ed25519 => format!(
            "openssl genpkey -algorithm ED25519 -out {name}.key\nopenssl req -new{outform} -out {name}.csr -key {name}.key -config {name}.cnf"
        ),
    };

    let encrypted = export.passphrase.as_deref().is_some_and(|p| !p.is_empty());

    let mut notes: Vec<&str> = Vec::new();
    if export.encoding == KeyEncoding::Der {
        notes.push("binary DER output");
    }
    if encrypted {
        notes.push("encrypted key (scrypt + AES-256-CBC, PKCS#8)");
    } else if key_algorithm.is_rsa()
        && export.rsa_key_format == crate::cert_config::RsaKeyFormat::Pkcs1
    {
        notes.push("PKCS#1 key format");
    }
    if !notes.is_empty() {
        cmd.push_str(&format!("\n# Export options: {}", notes.join(", ")));
    }

    cmd
}

pub struct CertGenResult {
    pub messages: String,
}

pub fn render(ui: &mut egui::Ui, app: &mut CertGenApp) {
    // Poll background thread result
    let mut finished: Option<CertGenResult> = None;
    if let Some(rx) = &app.pending_cert {
        match rx.try_recv() {
            Ok(result) => finished = Some(result),
            Err(mpsc::TryRecvError::Disconnected) => {
                app.is_executing = false;
                app.pending_cert = None;
            }
            Err(mpsc::TryRecvError::Empty) => {}
        }
    }
    if let Some(result) = finished {
        app.output.push_str(&result.messages);
        app.is_executing = false;
        app.pending_cert = None;
    }

    if !app.config_output.is_empty() {
        let button = egui::Button::new(if app.is_executing {
            "Processing..."
        } else {
            "Generate Certificate Request"
        });
        if ui.add_enabled(!app.is_executing, button).clicked() {
            spawn_generation(app, ui.ctx().clone());
        }
    }
}

/// Spawns a background thread to generate the certificate request since RSA
/// generation is CPU intensive and would block the render thread, making the
/// application appear unresponsive.
fn spawn_generation(app: &mut CertGenApp, ctx: egui::Context) {
    let config = CertConfig::from(&*app);
    let config_output = app.config_output.clone();
    let file_common_name = if app.common_name.starts_with("*.") {
        app.common_name.replacen("*.", "wildcard.", 1)
    } else {
        app.common_name.clone()
    };

    let export = ExportOptions {
        encoding: app.key_encoding,
        rsa_key_format: app.rsa_key_format,
        passphrase: if app.passphrase.is_empty() {
            None
        } else {
            Some(app.passphrase.clone())
        },
    };

    // When reusing an existing key, the algorithm selector must match the
    // imported key; otherwise rcgen will reject the import.
    let existing_key = if app.use_existing_key && !app.existing_key_pem.trim().is_empty() {
        Some(app.existing_key_pem.clone())
    } else {
        None
    };

    let (tx, rx) = mpsc::channel();
    app.pending_cert = Some(rx);
    app.is_executing = true;

    std::thread::spawn(move || {
        log::debug!("Starting certificate request generation in background thread");
        let result = run_generation(
            config,
            config_output,
            file_common_name,
            export,
            existing_key,
        );
        log::debug!("Certificate request generation finished in background thread");
        let _ = tx.send(result);
        ctx.request_repaint();
    });
}

fn run_generation(
    config: CertConfig,
    config_output: String,
    file_common_name: String,
    export: ExportOptions,
    existing_key: Option<String>,
) -> CertGenResult {
    let mut messages = String::new();

    match generate_cert_request(&config, &export, existing_key.as_deref()) {
        Ok(cert) => {
            messages.push_str("Certificate request generated successfully!\n");
            let toml_config = match config.to_toml() {
                Ok(t) => t,
                Err(e) => {
                    log::error!("Failed to serialize config.toml: {}", e);
                    messages.push_str(&format!("Failed to serialize config.toml: {}\n", e));
                    String::new()
                }
            };
            let recreate_cmd =
                build_recreate_command(&config.key_algorithm, &file_common_name, &export);
            match save_certificate_files_to_zip(
                &config_output,
                &file_common_name,
                &cert.key_bytes,
                &cert.csr_bytes,
                &recreate_cmd,
                &toml_config,
            ) {
                Ok(_) => {
                    messages.push_str("Auto saved zip to downloads folder\n");
                    messages.push_str(&format!(
                        "Use this command to recreate the csr:\n{}\n",
                        recreate_cmd
                    ));
                }
                Err(err) => {
                    log::error!("{}", err);
                    if err.kind() == std::io::ErrorKind::Interrupted {
                        messages.push_str("Zip save cancelled.\n");
                    } else {
                        log::error!("{}", err);
                        messages.push_str(&format!("Failed to save generated zip: {}\n", err));
                    }
                }
            }
            CertGenResult { messages }
        }
        Err(err) => {
            log::error!("Failed to generate certificate: {}", err);
            messages.push_str(&format!("Failed to generate certificate: {}\n", err));
            CertGenResult { messages }
        }
    }
}
