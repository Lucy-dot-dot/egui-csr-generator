use eframe::egui;
use std::fs::File;
use std::io::Write;
use crate::CertGenApp;
use crate::openssl_cert_tools::execute_openssl_command;
use crate::components::generate_and_save;

pub fn render(ui: &mut egui::Ui, app: &mut CertGenApp) {
    if !app.config_output.is_empty() {
        let button = egui::Button::new(
            if app.is_executing {
                "Processing..."
            } else {
                "Execute OpenSSL Command"
            }
        );

        if ui.add_enabled(!app.is_executing, button).clicked() {
            execute(app);
        }
    }
}

fn execute(app: &mut CertGenApp) {
    app.is_executing = true;
    let temp_file = "./temp_openssl.cnf";
    app.openssl_output.push_str(&format!("Creating temp file: {}\n", temp_file));

    let mut file = match File::create(temp_file) {
        Ok(f) => f,
        Err(err) => {
            log::error!("Failed to create temp file: {}", err);
            app.openssl_output.push_str(&format!("Failed to create temp file: {}\n", err));
            app.is_executing = false;
            return;
        }
    };

    match file.write_all(app.config_output.as_bytes()) {
        Ok(_) => {}
        Err(err) => {
            log::error!("Failed to write into temp file: {}", err);
            app.openssl_output.push_str(&format!("Failed to write into temp file: {}\n", err));
            if let Err(e) = std::fs::remove_file(temp_file) {
                log::error!("Failed to delete temp file: {}", e);
                app.openssl_output.push_str(&format!("Failed to delete temp file: {}\n", e));
            }
            app.is_executing = false;
            return;
        }
    }

    let file_common_name = if app.common_name.starts_with("*.") {
        app.common_name.replacen("*.", "wildcard.", 1)
    } else {
        app.common_name.clone()
    };

    let openssl_command = format!("openssl req -new -out {}.csr -config {}", file_common_name, temp_file);
    log::info!("Executing: {}", openssl_command);

    match execute_openssl_command(&openssl_command) {
        Ok((stdout, stderr)) => {
            app.openssl_output.push_str(&stdout);
            app.openssl_output.push_str(&stderr);

            // Read the key file
            match std::fs::read_to_string(format!("{}.key", file_common_name)) {
                Ok(content) => {
                    app.key_content = content;
                    if let Err(err) = std::fs::remove_file(format!("{}.key", file_common_name)) {
                        log::error!("Error removing key file: {}", err);
                    }
                }
                Err(_) => app.key_content = "Error reading key file".to_string(),
            }

            // Read the CSR file
            match std::fs::read_to_string(format!("{}.csr", file_common_name)) {
                Ok(content) => {
                    app.csr_content = content;
                    if let Err(err) = std::fs::remove_file(format!("{}.csr", file_common_name)) {
                        log::error!("Error removing csr file: {}", err);
                    }
                }
                Err(_) => app.csr_content = "Error reading CSR file".to_string(),
            }

            // Auto-save if both files were read successfully
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
            log::error!("Failed execute openssl: {}", err);
            app.openssl_output.push_str(&format!("Failed execute openssl: {}\n", err));
        }
    }

    // Clean up temp file
    if let Err(err) = std::fs::remove_file(temp_file) {
        log::error!("Failed to delete temp file: {}", err);
        app.openssl_output.push_str(&format!("Failed to delete temp file: {}\n", err));
    }

    app.is_executing = false;
}
