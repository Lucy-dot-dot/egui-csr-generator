use eframe::egui;
use crate::CertGenApp;

pub fn render(ui: &mut egui::Ui, app: &mut CertGenApp) {
    egui::Frame::group(ui.style())
        .inner_margin(10.0)
        .show(ui, |ui| {
            ui.set_max_width(ui.available_width());

            // Advanced mode toggle in top right
            ui.horizontal(|ui| {
                ui.label("");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.checkbox(&mut app.advanced_mode, "Advanced");
                    #[cfg(feature = "openssl-native")]
                    if app.advanced_mode {
                        ui.checkbox(&mut app.internal_generate, "Internal Generate");
                    }
                });
            });

            ui.separator();
            ui.add_space(5.0);

            // Country Code
            ui.horizontal(|ui| {
                ui.label("Country Code (2 letters):");
                ui.add(egui::TextEdit::singleline(&mut app.country)
                    .hint_text("DE")
                    .desired_width(200.0));
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

            // Advanced mode fields
            if app.advanced_mode {
                ui.add_space(5.0);
                ui.label(egui::RichText::new("Advanced Options").strong());
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

                // Key Size
                ui.horizontal(|ui| {
                    ui.label("Key Size:");
                    egui::ComboBox::from_id_salt("key_size")
                        .selected_text(&app.key_size)
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut app.key_size, "2048".to_string(), "2048 bits");
                            ui.selectable_value(&mut app.key_size, "4096".to_string(), "4096 bits");
                        });
                });

                // Hash Algorithm
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

                ui.separator();
            }

            // Common Name
            ui.horizontal(|ui| {
                ui.label("Common Name:");
                let response = ui.add(egui::TextEdit::singleline(&mut app.common_name)
                    .hint_text("mail.test.org")
                    .desired_width(200.0));

                // Update or add CN as first SAN when it changes
                if response.changed() {
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

                // Handle Enter key
                if response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    if !app.current_san.is_empty() {
                        app.sans.push(app.current_san.clone());
                        app.current_san.clear();
                    }
                }

                if ui.button("Add SAN").clicked() && !app.current_san.is_empty() {
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
            if ui.button("Clear All Fields").clicked() {
                app.clear_form();
            }
        });
}
