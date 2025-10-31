use std::fs::File;
use std::io::Write;
use dioxus::logger::tracing;
use dioxus::prelude::*;
use crate::openssl_cert_tools::execute_openssl_command;
use crate::components::generate_and_save;

#[component]
pub fn ExecuteButton(mut is_executing: Signal<bool>,
                 mut openssl_state: Signal<String>,
                 mut config_output: Signal<String>,
                 common_name: Signal<String>,
                 mut key_content: Signal<String>,
                 mut csr_content: Signal<String>) -> Element {
    let execute = move |_| {
        is_executing.set(true);
        let temp_file = "./temp_openssl.cnf";
        openssl_state.write().push_str(&format!("Creating temp file: {}\n", temp_file));

        let mut file = match File::create(temp_file) {
            Ok(f) => f,
            Err(err) => {
                tracing::error!("Failed to create temp file: {}", err);
                openssl_state.write().push_str(&format!("Failed to create temp file: {}\n", err));
                is_executing.set(false);
                return;
            }
        };
        match file.write_all(config_output.read().as_bytes()) {
            Ok(_) => {}
            Err(err) => {
                eprintln!("Failed to write into temp file: {}", err);
                openssl_state.write().push_str(&format!("Failed to write into temp file: {}", err));
                match std::fs::remove_file(temp_file) {
                    Ok(_) => {},
                    Err(err) => {
                        eprintln!("Failed to delete temp file: {}", err);
                        openssl_state.write().push_str(&format!("Failed to delete temp file: {}", err));
                    }
                }
                is_executing.set(false);
                return;
            }
        }

        let file_common_name = if common_name.read().starts_with("*.") {
            common_name.read().replacen("*.", "wildcard.", 1)
        } else {
            common_name.read().to_string()
        };

        let openssl_command = format!("openssl req -new -out {}.csr -config {}", file_common_name, temp_file);
        tracing::info!("Executing: {}", openssl_command);
        match execute_openssl_command(&*openssl_command) {
            Ok((stdout, stderr)) => {
                openssl_state.write().push_str(&stdout);
                openssl_state.write().push_str(&stderr);
                // After execution, read the contents of the files
                match std::fs::read_to_string(format!("{}.key", file_common_name)) {
                    Ok(content) => {
                        key_content.set(content);

                        match std::fs::remove_file(format!("{}.key", file_common_name)) {
                            Ok(_) => {},
                            Err(err) => {
                                tracing::error!("Error removing key file: {}", err);
                            }
                        }
                    },
                    Err(_) => key_content.set("Error reading key file".to_string())
                }

                match std::fs::read_to_string(format!("{}.csr", file_common_name)) {
                    Ok(content) => {
                        csr_content.set(content);
                        match std::fs::remove_file(format!("{}.csr", file_common_name)) {
                            Ok(_) => {},
                            Err(err) => {
                                tracing::error!("Error removing csr file: {}", err);
                            }
                        }
                    },
                    Err(_) => csr_content.set("Error reading CSR file".to_string())
                }
                if !key_content.read().is_empty() && !csr_content.read().is_empty() {
                    let cnf = config_output.read().clone();
                    let key = key_content.read().clone();
                    let csr = csr_content.read().clone();
                    match generate_and_save(&cnf, &file_common_name, &key, &csr) {
                        Ok(_) => {
                            openssl_state.write().push_str("Auto saved zip to downloads folder");
                            let openssl_for_zip = format!("openssl req -new -out {}.csr -config {}.cnf", file_common_name, file_common_name);
                            openssl_state.write().push_str(&format!("Use this command to recreate the csr: {}", openssl_for_zip));
                        }
                        Err(err) => {
                            tracing::error!("{}", err);
                            openssl_state.write().push_str(&format!("Failed to auto save generated zip: {}", err))
                        }
                    }
                }
            }
            Err(err) => {
                tracing::error!("Failed execute openssl: {}", err);
                openssl_state.write().push_str(&format!("Failed execute openssl: {}", err));
            }
        }
        match std::fs::remove_file(temp_file) {
            Ok(_) => {},
            Err(err) => {
                tracing::error!("Failed to delete temp file: {}", err);
                openssl_state.write().push_str(&format!("Failed to delete temp file: {}", err));
            }
        }
        is_executing.set(false);
    };

    rsx! {
        if !config_output.read().is_empty() {
            button {
                class: "secondary",
                disabled: is_executing(),
                onclick: execute,
                if is_executing() {
                    span { class: "loading-spinner" }
                    "Processing..."
                } else {
                    "Execute OpenSSL Command"
                }
            }
        }
    }
}