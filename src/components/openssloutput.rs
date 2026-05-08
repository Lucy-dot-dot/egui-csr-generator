use eframe::egui;

pub fn render(ui: &mut egui::Ui, config_preview: &str, command_output: &str) {
    let has_command_output = !command_output.is_empty();
    let has_error = command_output.to_lowercase().contains("error");

    ui.add_space(10.0);
    ui.separator();

    if !config_preview.is_empty() {
        ui.label(egui::RichText::new("Config Preview").strong());
        egui::Frame::group(ui.style())
            .inner_margin(10.0)
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .max_height(300.0)
                    .id_salt("config_preview_scroll")
                    .show(ui, |ui| {
                        ui.add(
                            egui::TextEdit::multiline(&mut config_preview.to_string())
                                .font(egui::TextStyle::Monospace)
                                .desired_width(f32::INFINITY)
                                .interactive(true),
                        );
                    });
            });
        ui.add_space(10.0);
    }

    if has_command_output {
        let heading = if has_error {
            egui::RichText::new("OpenSSL Command Failed").strong().color(egui::Color32::RED)
        } else {
            egui::RichText::new("OpenSSL Command Output")
        };

        ui.heading(heading);

        egui::Frame::group(ui.style())
            .inner_margin(10.0)
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .max_height(800.0)
                    .show(ui, |ui| {
                        ui.add(
                            egui::TextEdit::multiline(&mut command_output.to_string())
                                .font(egui::TextStyle::Monospace)
                                .desired_width(f32::INFINITY)
                                .interactive(true),
                        );
                    });
            });
    } else if config_preview.is_empty() {
        ui.label(egui::RichText::new("Fill in the required fields to see the config preview").weak().italics());
    }
}
