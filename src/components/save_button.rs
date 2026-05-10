use eframe::egui;
use crate::CertGenApp;
use super::generate_and_save;
use super::execute_button::build_recreate_command;

pub fn render(ui: &mut egui::Ui, app: &mut CertGenApp) {
    let button_text = "Save Certificate Files";

    if ui.button(button_text).clicked() {
        // Get file contents
        let cnf = app.config_output.clone();
        let file_common_name = if app.common_name.starts_with("*.") {
            app.common_name.replacen("*.", "wildcard.", 1)
        } else {
            app.common_name.clone()
        };
        let key = app.key_content.clone();
        let csr = app.csr_content.clone();

        let recreate_cmd = build_recreate_command(&app.key_algorithm, &file_common_name);
        match generate_and_save(&cnf, &file_common_name, &key, &csr, &recreate_cmd) {
            Ok(_) => {
                app.output.push_str("Certificate files saved successfully\n");
                log::info!("Certificate files saved successfully");
            }
            Err(err) => {
                app.output.push_str(&format!("Failed to save certificate files: {}", err));
                log::error!("Failed to save certificate files: {}", err);
            }
        }
    }
}
