use eframe::egui;
use crate::CertGenApp;
use crate::cert_config::{KeyAlgorithm, CertPurpose, sanitize};

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
    if !check.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.') {
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
                    };
                    egui::ComboBox::from_id_salt("key_algorithm")
                        .selected_text(algo_label)
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut app.key_algorithm, KeyAlgorithm::Rsa2048, "RSA 2048");
                            ui.selectable_value(&mut app.key_algorithm, KeyAlgorithm::Rsa3072, "RSA 3072");
                            ui.selectable_value(&mut app.key_algorithm, KeyAlgorithm::Rsa4096, "RSA 4096");
                            ui.selectable_value(&mut app.key_algorithm, KeyAlgorithm::EcdsaP256, "ECDSA P-256");
                            ui.selectable_value(&mut app.key_algorithm, KeyAlgorithm::EcdsaP384, "ECDSA P-384");
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

                ui.separator();
            };

            // Common Name
            ui.horizontal(|ui| {
                ui.label("Common Name:");
                let response = ui.add(egui::TextEdit::singleline(&mut app.common_name)
                    .hint_text("mail.test.org")
                    .desired_width(200.0));

                // Update or add CN as first SAN when it changes
                if response.changed() {
                    app.common_name = sanitize(&app.common_name);

                    if !app.common_name.is_empty() {
                        if app.sans.is_empty() {
                            app.sans.push(app.common_name.clone());
                        } else {
                            app.sans[0] = app.common_name.clone();
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
                            ui.label(egui::RichText::new("INVALID").color(egui::Color32::RED));
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
