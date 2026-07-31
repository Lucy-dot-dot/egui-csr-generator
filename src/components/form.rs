use crate::CertGenApp;
use crate::cert_config::{CertPurpose, KeyAlgorithm, KeyEncoding, RsaKeyFormat, sanitize};
use eframe::egui;

fn is_valid_san(san: &str) -> bool {
    if san.is_empty() {
        return false;
    }
    if san.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    // Strip optional wildcard prefix
    let check = san.strip_prefix("*.").unwrap_or(san);
    if check.is_empty() {
        return false;
    }
    // Valid chars for a DNS label sequence: letters, digits, hyphens, dots
    if !check
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    {
        return false;
    }
    if check.contains("..") {
        return false;
    }
    let first = check.chars().next().unwrap();
    let last = check.chars().last().unwrap();
    first != '.' && first != '-' && last != '.' && last != '-'
}

pub fn render(ui: &mut egui::Ui, app: &mut CertGenApp) {
    egui::Frame::group(ui.style())
        .inner_margin(10.0)
        .show(ui, |ui| {
            ui.set_max_width(ui.available_width());

            ui.add_space(5.0);

            // Country Code
            ui.horizontal(|ui| {
                ui.label("Country Code (2 letters):");
                ui.add(egui::TextEdit::singleline(&mut app.country)
                    .hint_text("DE")
                    .desired_width(200.0));
                if !app.country.is_empty() && (app.country.len() != 2 || !app.country.chars().all(|c| c.is_alphabetic())) {
                    ui.label(egui::RichText::new("Must be 2 letters").color(egui::Color32::RED));
                }
            });

            // State/Province
            ui.horizontal(|ui| {
                ui.label("State/Province:");
                ui.add(egui::TextEdit::singleline(&mut app.state)
                    .hint_text("Nordrhein-Westfalen")
                    .desired_width(200.0));
            });

            // Locality
            ui.horizontal(|ui| {
                ui.label("Locality (city):");
                ui.add(egui::TextEdit::singleline(&mut app.locality)
                    .hint_text("Münster")
                    .desired_width(200.0));
            });

            // Organization
            ui.horizontal(|ui| {
                ui.label("Organization:");
                ui.add(egui::TextEdit::singleline(&mut app.organization)
                    .hint_text("Test Inc.")
                    .desired_width(200.0));
            });

            // Optional fields section
            {
                ui.add_space(5.0);
                ui.label(egui::RichText::new("Optional Values").strong());
                ui.separator();

                // Organizational Unit
                ui.horizontal(|ui| {
                    ui.label("Organizational Unit (OU):");
                    ui.add(egui::TextEdit::singleline(&mut app.organizational_unit)
                        .hint_text("IT Department")
                        .desired_width(200.0));
                });

                // Email
                ui.horizontal(|ui| {
                    ui.label("Email Address:");
                    ui.add(egui::TextEdit::singleline(&mut app.email)
                        .hint_text("admin@example.com")
                        .desired_width(200.0));
                });

                // Street Address
                ui.horizontal(|ui| {
                    ui.label("Street Address:");
                    ui.add(egui::TextEdit::singleline(&mut app.street_address)
                        .hint_text("123 Main Street")
                        .desired_width(200.0));
                });

                // Postal Code
                ui.horizontal(|ui| {
                    ui.label("Postal Code:");
                    ui.add(egui::TextEdit::singleline(&mut app.postal_code)
                        .hint_text("12345")
                        .desired_width(200.0));
                });

                // Key Algorithm
                ui.horizontal(|ui| {
                    ui.label("Key Algorithm:");
                    let algo_label = match &app.key_algorithm {
                        KeyAlgorithm::Rsa2048 => "RSA 2048",
                        KeyAlgorithm::Rsa3072 => "RSA 3072",
                        KeyAlgorithm::Rsa4096 => "RSA 4096",
                        KeyAlgorithm::EcdsaP256 => "ECDSA P-256",
                        KeyAlgorithm::EcdsaP384 => "ECDSA P-384",
                        KeyAlgorithm::Ed25519 => "Ed25519",
                    };
                    egui::ComboBox::from_id_salt("key_algorithm")
                        .selected_text(algo_label)
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut app.key_algorithm, KeyAlgorithm::Rsa2048, "RSA 2048");
                            ui.selectable_value(&mut app.key_algorithm, KeyAlgorithm::Rsa3072, "RSA 3072");
                            ui.selectable_value(&mut app.key_algorithm, KeyAlgorithm::Rsa4096, "RSA 4096");
                            ui.selectable_value(&mut app.key_algorithm, KeyAlgorithm::EcdsaP256, "ECDSA P-256");
                            ui.selectable_value(&mut app.key_algorithm, KeyAlgorithm::EcdsaP384, "ECDSA P-384");
                            ui.selectable_value(&mut app.key_algorithm, KeyAlgorithm::Ed25519, "Ed25519");
                        });
                });

                // Hash Algorithm (RSA only — ECDSA hash is fixed by the curve)
                let is_rsa = matches!(app.key_algorithm, KeyAlgorithm::Rsa2048 | KeyAlgorithm::Rsa3072 | KeyAlgorithm::Rsa4096);
                if is_rsa {
                    ui.horizontal(|ui| {
                        ui.label("Hash Algorithm:");
                        egui::ComboBox::from_id_salt("hash_algo")
                            .selected_text(&app.hash_algorithm)
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut app.hash_algorithm, "sha256".to_string(), "SHA-256");
                                ui.selectable_value(&mut app.hash_algorithm, "sha384".to_string(), "SHA-384");
                                ui.selectable_value(&mut app.hash_algorithm, "sha512".to_string(), "SHA-512");
                            });
                    });
                }

                // Certificate Purpose
                ui.horizontal(|ui| {
                    ui.label("Certificate Purpose:");
                    let purpose_label = match &app.cert_purpose {
                        CertPurpose::TlsServer => "TLS Server",
                        CertPurpose::TlsClient => "TLS Client",
                    };
                    egui::ComboBox::from_id_salt("cert_purpose")
                        .selected_text(purpose_label)
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut app.cert_purpose, CertPurpose::TlsServer, "TLS Server");
                            ui.selectable_value(&mut app.cert_purpose, CertPurpose::TlsClient, "TLS Client");
                        });
                });

                // Export Options — packaging choices for the generated key/CSR.
                // These are never written to config.toml.
                ui.add_space(5.0);
                ui.label(egui::RichText::new("Export Options").strong());
                ui.separator();

                // Key Encoding (PEM / DER)
                ui.horizontal(|ui| {
                    ui.label("Key Encoding:");
                    let enc_label = match app.key_encoding {
                        KeyEncoding::Pem => "PEM (text)",
                        KeyEncoding::Der => "DER (binary)",
                    };
                    egui::ComboBox::from_id_salt("key_encoding")
                        .selected_text(enc_label)
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut app.key_encoding, KeyEncoding::Pem, "PEM (text)");
                            ui.selectable_value(&mut app.key_encoding, KeyEncoding::Der, "DER (binary)");
                        });
                });

                // RSA container format (PKCS#8 vs PKCS#1) — RSA only.
                let is_rsa = app.key_algorithm.is_rsa();
                if is_rsa {
                    ui.horizontal(|ui| {
                        ui.label("Key Format:");
                        let fmt_label = match app.rsa_key_format {
                            RsaKeyFormat::Pkcs8 => "PKCS#8",
                            RsaKeyFormat::Pkcs1 => "PKCS#1 (traditional)",
                        };
                        let combo = egui::ComboBox::from_id_salt("rsa_key_format")
                            .selected_text(fmt_label);
                        combo.show_ui(ui, |ui| {
                            if ui.selectable_value(&mut app.rsa_key_format, RsaKeyFormat::Pkcs8, "PKCS#8").clicked()
                                || ui.selectable_value(&mut app.rsa_key_format, RsaKeyFormat::Pkcs1, "PKCS#1 (traditional)").clicked()
                            {
                                // PKCS#1 has no passphrase container here; drop any
                                // passphrase when switching to it to keep behavior explicit.
                                if app.rsa_key_format == RsaKeyFormat::Pkcs1 {
                                    app.passphrase.clear();
                                }
                            }
                        });
                    });
                }

                // Passphrase (encrypted PKCS#8 export). Disabled for RSA+PKCS#1.
                let pkcs1_rsa = is_rsa && app.rsa_key_format == RsaKeyFormat::Pkcs1;
                ui.horizontal(|ui| {
                    ui.label("Passphrase:");
                    let edit = egui::TextEdit::singleline(&mut app.passphrase)
                        .hint_text("(none)")
                        .password(true)
                        .desired_width(200.0);
                    ui.add_enabled(!pkcs1_rsa, edit);
                    if pkcs1_rsa {
                        ui.label(
                            egui::RichText::new("PKCS#1 cannot be encrypted")
                                .color(egui::Color32::from_rgb(180, 180, 180)),
                        )
                        .on_hover_text("Switch to PKCS#8 to enable passphrase protection, or leave the key unencrypted.");
                    } else if !app.passphrase.is_empty() {
                        ui.label(egui::RichText::new("encrypted PKCS#8").color(egui::Color32::GREEN));
                    }
                });

                // Reuse an existing private key instead of generating a new one.
                ui.horizontal(|ui| {
                    if ui.checkbox(&mut app.use_existing_key, "Reuse existing key").clicked()
                        && !app.use_existing_key
                    {
                        app.existing_key_pem.clear();
                    }
                    ui.label(
                        egui::RichText::new("paste an unencrypted PKCS#8 PEM key")
                            .small()
                            .weak(),
                    );
                });
                if app.use_existing_key {
                    ui.horizontal(|ui| {
                        ui.label("Existing key (PEM):");
                        if ui.button("Load from file…").clicked()
                            && let Some(path) = rfd::FileDialog::new()
                                .add_filter("PEM key", &["pem", "key"])
                                .pick_file()
                        {
                            match std::fs::read_to_string(&path) {
                                Ok(text) => app.existing_key_pem = text,
                                Err(e) => {
                                    log::error!("Failed to read key file: {}", e);
                                    app.output =
                                        format!("Failed to read key file {}: {}\n", path.display(), e);
                                }
                            }
                        }
                    });
                    egui::TextEdit::multiline(&mut app.existing_key_pem)
                        .hint_text("-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----")
                        .desired_width(f32::INFINITY)
                        .desired_rows(4)
                        .code_editor()
                        .show(ui);
                    if !app.existing_key_pem.trim().is_empty()
                        && !app.existing_key_pem.contains("BEGIN")
                    {
                        ui.label(
                            egui::RichText::new("This does not look like a PEM key")
                                .color(egui::Color32::YELLOW),
                        );
                    }
                    if app.existing_key_pem.contains("ENCRYPTED") {
                        ui.label(
                            egui::RichText::new(
                                "Encrypted keys cannot be imported — decrypt first",
                            )
                            .color(egui::Color32::YELLOW),
                        );
                    }
                }

                ui.separator();
            };

            // Common Name
            ui.horizontal(|ui| {
                ui.label("Common Name:");
                let response = egui::TextEdit::singleline(&mut app.common_name)
                    .hint_text("mail.test.org")
                    .desired_width(200.0)
                    .show(ui);

                // Update or add CN as first SAN when it changes
                if response.response.changed() {
                    let cn_len = app.common_name.chars().count() as isize;
                    app.common_name = sanitize(&app.common_name);
                    let new_len = app.common_name.chars().count() as isize;
                    if cn_len != new_len {
                        let text_edit_id = response.response.id;

                        if let Some(mut state) = egui::TextEdit::load_state(ui.ctx(), text_edit_id) &&
                            let Some(cursor) = state.cursor.char_range() {

                            let new_pos = ((cursor.primary.index.0 as isize) + (new_len - cn_len)).max(0) as usize;
                            let ccursor = egui::text::CCursor::new(new_pos);
                            state
                                .cursor
                                .set_char_range(Some(egui::text::CCursorRange::one(ccursor)));
                            state.store(ui.ctx(), text_edit_id);
                            ui.memory_mut(|mem| mem.request_focus(text_edit_id)); // give focus back to the [`TextEdit`].
                        }
                    }

                    if !app.common_name.is_empty() {
                        if app.sans.is_empty() {
                            app.sans.push(app.common_name.clone());
                        } else {
                            app.sans.insert(0, app.common_name.clone());
                        }
                    } else if !app.sans.is_empty() {
                        app.sans.remove(0);
                    }
                }
            });

            ui.add_space(5.0);

            // Subject Alternative Names section
            ui.label(egui::RichText::new("Subject Alternative Names:").strong());

            ui.horizontal(|ui| {
                let response = ui.add(egui::TextEdit::singleline(&mut app.current_san)
                    .hint_text("Enter domain or IP (e.g. www.example.com)")
                    .desired_width(300.0));

                let san_valid = is_valid_san(&app.current_san) && !app.sans.contains(&app.current_san);

                if !app.current_san.is_empty() {
                    if app.current_san.parse::<std::net::IpAddr>().is_ok() {
                        ui.label(egui::RichText::new("IP").color(egui::Color32::GREEN));
                    } else if san_valid {
                        ui.label(egui::RichText::new("DNS").color(egui::Color32::GREEN));
                    } else {
                        if app.sans.contains(&app.current_san) {
                            ui.label(egui::RichText::new("SAN already exists").color(egui::Color32::YELLOW));
                        } else {
                            ui.label(egui::RichText::new("INVALID").color(egui::Color32::RED)).on_hover_text("Must be a valid DNS label or IP address");
                        }
                    }
                }

                // Handle Enter key
                if response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) && san_valid {
                    app.sans.push(app.current_san.clone());
                    app.current_san.clear();
                }

                if ui.add_enabled(san_valid, egui::Button::new("Add SAN")).clicked() {
                    app.sans.push(app.current_san.clone());
                    app.current_san.clear();
                }
            });

            // Display SAN list
            if !app.sans.is_empty() {
                ui.add_space(5.0);
                egui::Frame::new()
                    .inner_margin(5.0)
                    .show(ui, |ui| {
                        let mut to_remove = None;

                        for (i, san) in app.sans.iter().enumerate() {
                            ui.horizontal(|ui| {
                                // Icon based on type
                                let icon = if san.parse::<std::net::IpAddr>().is_ok() {
                                    "IP"
                                } else {
                                    "DNS"
                                };
                                ui.label(format!("[{}]", icon));
                                ui.label(san);

                                // Show badge for first SAN (CN)
                                if i == 0 {
                                    ui.label(egui::RichText::new("(from CN)").italics().weak());
                                } else {
                                    // Only allow removing SANs after the first one
                                    if ui.button("Remove").clicked() {
                                        to_remove = Some(i);
                                    }
                                }
                            });
                        }

                        if let Some(idx) = to_remove {
                            app.sans.remove(idx);
                        }
                    });
            } else {
                ui.label(egui::RichText::new("No alternative names added yet").weak().italics());
            }

            ui.add_space(10.0);

            // Clear button
            let button = egui::Button::new("Clear All Fields");
            if ui.add_enabled(!app.is_executing, button).clicked() {
                app.clear_form();
            }
        });
}
