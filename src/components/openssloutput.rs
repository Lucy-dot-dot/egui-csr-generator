use eframe::egui;

pub fn render(ui: &mut egui::Ui, output: &str) {
    let has_output = !output.is_empty();
    let has_error = output.to_lowercase().contains("error");

    ui.add_space(10.0);
    ui.separator();

    if has_output {
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
                            egui::TextEdit::multiline(&mut output.to_string())
                                .font(egui::TextStyle::Monospace)
                                .desired_width(f32::INFINITY)
                                .interactive(true),
                        );
                    });
            });
    } else {
        ui.label(egui::RichText::new("No output available").weak().italics());
    }
}
