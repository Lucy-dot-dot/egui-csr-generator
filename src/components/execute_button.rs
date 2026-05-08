use eframe::egui;
use crate::CertGenApp;
use crate::cert_config::CertConfig;
use crate::openssl_native::generate_cert_request;
use crate::components::generate_and_save;

pub fn render(ui: &mut egui::Ui, app: &mut CertGenApp) {
    if !app.config_output.is_empty() {
        let button = egui::Button::new(
            if app.is_executing { "Processing..." } else { "Generate Certificate Request" }
        );
        if ui.add_enabled(!app.is_executing, button).clicked() {
            execute(app);
        }
    }
}

fn execute(app: &mut CertGenApp) {
    app.is_executing = true;

    let file_common_name = if app.common_name.starts_with("*.") {
        app.common_name.replacen("*.", "wildcard.", 1)
    } else {
        app.common_name.clone()
    };

    let config = CertConfig::from(&*app);

    match generate_cert_request(&config) {
        Ok(cert) => {
            app.key_content = cert.key_pem;
            app.csr_content = cert.csr_pem;
            app.openssl_output.push_str("Certificate request generated successfully!\n");

            if !app.key_content.is_empty() && !app.csr_content.is_empty() {
                match generate_and_save(
                    &app.config_output,
                    &file_common_name,
                    &app.key_content,
                    &app.csr_content,
                ) {
                    Ok(_) => {
                        app.openssl_output.push_str("Auto saved zip to downloads folder\n");
                        let openssl_for_zip = format!(
                            "openssl req -new -out {}.csr -config {}.cnf",
                            file_common_name, file_common_name
                        );
                        app.openssl_output.push_str(&format!("Use this command to recreate the csr: {}\n", openssl_for_zip));
                    }
                    Err(err) => {
                        log::error!("{}", err);
                        app.openssl_output.push_str(&format!("Failed to auto save generated zip: {}\n", err));
                    }
                }
            }
        }
        Err(err) => {
            log::error!("Failed to generate certificate: {}", err);
            app.openssl_output.push_str(&format!("Failed to generate certificate: {}\n", err));
        }
    }

    app.is_executing = false;
}
