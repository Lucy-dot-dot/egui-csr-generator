use std::sync::mpsc;
use eframe::egui;
use crate::CertGenApp;
use crate::cert_config::{CertConfig, KeyAlgorithm};
use crate::openssl_native::generate_cert_request;
use crate::components::generate_and_save;

pub fn build_recreate_command(key_algorithm: &KeyAlgorithm, name: &str) -> String {
    match key_algorithm {
        KeyAlgorithm::Rsa2048 | KeyAlgorithm::Rsa3072 | KeyAlgorithm::Rsa4096 => {
            format!("openssl req -new -out {}.csr -config {}.cnf", name, name)
        }
        KeyAlgorithm::EcdsaP256 => format!(
            "openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out {0}.key\nopenssl req -new -out {0}.csr -key {0}.key -config {0}.cnf",
            name
        ),
        KeyAlgorithm::EcdsaP384 => format!(
            "openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out {0}.key\nopenssl req -new -out {0}.csr -key {0}.key -config {0}.cnf",
            name
        ),
    }
}

pub struct CertGenResult {
    pub key_pem: String,
    pub csr_pem: String,
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
        app.key_content = result.key_pem;
        app.csr_content = result.csr_pem;
        app.openssl_output.push_str(&result.messages);
        app.is_executing = false;
        app.pending_cert = None;
    }

    if !app.config_output.is_empty() {
        let button = egui::Button::new(
            if app.is_executing { "Processing..." } else { "Generate Certificate Request" }
        );
        if ui.add_enabled(!app.is_executing, button).clicked() {
            spawn_generation(app, ui.ctx().clone());
        }
    }
}

fn spawn_generation(app: &mut CertGenApp, ctx: egui::Context) {
    let config = CertConfig::from(&*app);
    let config_output = app.config_output.clone();
    let file_common_name = if app.common_name.starts_with("*.") {
        app.common_name.replacen("*.", "wildcard.", 1)
    } else {
        app.common_name.clone()
    };

    let (tx, rx) = mpsc::channel();
    app.pending_cert = Some(rx);
    app.is_executing = true;

    std::thread::spawn(move || {
        let result = run_generation(config, config_output, file_common_name);
        let _ = tx.send(result);
        ctx.request_repaint();
    });
}

fn run_generation(config: CertConfig, config_output: String, file_common_name: String) -> CertGenResult {
    let mut messages = String::new();

    match generate_cert_request(&config) {
        Ok(cert) => {
            messages.push_str("Certificate request generated successfully!\n");
            if !cert.key_pem.is_empty() && !cert.csr_pem.is_empty() {
                let recreate_cmd = build_recreate_command(&config.key_algorithm, &file_common_name);
                match generate_and_save(&config_output, &file_common_name, &cert.key_pem, &cert.csr_pem, &recreate_cmd) {
                    Ok(_) => {
                        messages.push_str("Auto saved zip to downloads folder\n");
                        messages.push_str(&format!(
                            "Use this command to recreate the csr:\n{}\n",
                            recreate_cmd
                        ));
                    }
                    Err(err) => {
                        log::error!("{}", err);
                        messages.push_str(&format!("Failed to auto save generated zip: {}\n", err));
                    }
                }
            }
            CertGenResult { key_pem: cert.key_pem, csr_pem: cert.csr_pem, messages }
        }
        Err(err) => {
            log::error!("Failed to generate certificate: {}", err);
            messages.push_str(&format!("Failed to generate certificate: {}\n", err));
            CertGenResult { key_pem: String::new(), csr_pem: String::new(), messages }
        }
    }
}
