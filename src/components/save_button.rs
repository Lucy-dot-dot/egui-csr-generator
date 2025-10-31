use eframe::egui;
use crate::CertGenApp;
use super::generate_and_save;

pub fn render(ui: &mut egui::Ui, app: &mut CertGenApp) {
    let button_text = "Save Certificate Files";

    if ui.button(button_text).clicked() {
        // Get file contents
        let cnf = app.config_output.clone();
        let name = app.common_name.clone();
        let key = app.key_content.clone();
        let csr = app.csr_content.clone();

        match generate_and_save(&cnf, &name, &key, &csr) {
            Ok(_) => {
                log::info!("Certificate files saved successfully");
            }
            Err(err) => {
                log::error!("Failed to save certificate files: {}", err);
            }
        }
    }
}
