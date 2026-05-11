#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::Arc;
use eframe::{egui, CreationContext, Frame};
use egui::Ui;
#[cfg(debug_assertions)]
use fake::Fake;
#[cfg(debug_assertions)]
use fake::RngExt;
use log::LevelFilter;
use cert_config::{CertConfig, KeyAlgorithm, CertPurpose};

mod components;
mod cert_config;
mod internal_gen;

use components::form;
use components::output;
use components::execute_button;
#[cfg(debug_assertions)]
use crate::cert_config::sanitize;

fn setup_logger() {
    let current_time = time::OffsetDateTime::now_local().unwrap_or(time::OffsetDateTime::now_utc());

    #[cfg(not(debug_assertions))]
    let mut log_dir = dirs::data_local_dir()
        .map(|p| p.join("certificate-request-generator"))
        .filter(|p| std::fs::create_dir_all(p).is_ok())
        .unwrap_or_else(|| PathBuf::from("."));

    #[cfg(debug_assertions)]
    let mut log_dir = PathBuf::from(".");

    log_dir.push(format!("{}.log", current_time.unix_timestamp()));

    let target = match File::create(log_dir) {
        Ok(file) => Some(env_logger::Target::Pipe(Box::new(BufWriter::new(file)))),
        Err(_) => None,
    };

    let mut builder = env_logger::Builder::new();

    let builder = match target {
        None => { &mut builder }
        Some(target) => { builder.target(target) }
    };

    builder
        .filter(None, LevelFilter::Debug)
        .format(|buf, record| {
            let now = time::OffsetDateTime::now_local().unwrap_or(time::OffsetDateTime::now_utc());
            let format = time::macros::format_description!("[year]-[month]-[day] [hour]:[minute]:[second].[subsecond digits:3]");
            writeln!(
                buf,
                "[{} {} {}:{}] {}",
                now.format(&format).unwrap_or_else(|_| "unknown".to_string()),
                record.level(),
                record.file().unwrap_or("unknown"),
                record.line().unwrap_or(0),
                record.args()
            )
        })
        .init();

}

fn main() -> eframe::Result {
    setup_logger();

    let icon = Arc::new(eframe::icon_data::from_png_bytes(include_bytes!("../icon.png")).expect("Failed to load icon"));
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_min_inner_size([800.0, 700.0])
            .with_inner_size([800.0, 1100.0])
            .with_title("X.509 Certificate Request Generator")
            .with_icon(icon),
        ..Default::default()
    };

    eframe::run_native(
        "X.509 Certificate Request Generator",
        options,
        Box::new(|cc| Ok(Box::new(CertGenApp::new(cc)))),
    )
}

pub struct CertGenApp {
    // Form fields
    pub country: String,
    pub state: String,
    pub locality: String,
    pub organization: String,
    pub common_name: String,
    pub sans: Vec<String>,
    pub current_san: String,

    // Optional fields
    pub organizational_unit: String,
    pub email: String,
    pub street_address: String,
    pub postal_code: String,
    pub key_algorithm: KeyAlgorithm,
    pub hash_algorithm: String,
    pub cert_purpose: CertPurpose,

    // Output state
    pub output: String,
    pub config_output: String,
    pub key_content: String,
    pub csr_content: String,
    pub is_executing: bool,
    pub pending_cert: Option<std::sync::mpsc::Receiver<execute_button::CertGenResult>>,
}

impl CertGenApp {
    fn new(cc: &CreationContext) -> Self {
        log::debug!("Initializing app, creating font");
        let mut fonts = egui::FontDefinitions::default();
        fonts.font_data.insert("JetBrainsMono".to_owned(), Arc::from(egui::FontData::from_static(include_bytes!("../assets/JetBrainsMono-Regular.ttf"))));

        fonts.families.insert(egui::FontFamily::Name("JetBrainsMono".into()), vec!["JetBrainsMono".to_owned()]);

        fonts.families.get_mut(&egui::FontFamily::Proportional).expect("egui default font families missing")
            .insert(0, "JetBrainsMono".to_owned());

        fonts.families.get_mut(&egui::FontFamily::Monospace).expect("egui default font families missing")
            .insert(0, "JetBrainsMono".to_owned());
        cc.egui_ctx.set_fonts(fonts);
        log::debug!("Initializing app, done");
        Self {
            country: String::new(),
            state: String::new(),
            locality: String::new(),
            organization: String::new(),
            common_name: String::new(),
            sans: Vec::new(),
            current_san: String::new(),
            organizational_unit: String::new(),
            email: String::new(),
            street_address: String::new(),
            postal_code: String::new(),
            key_algorithm: KeyAlgorithm::Rsa2048,
            hash_algorithm: "sha256".to_string(),
            cert_purpose: CertPurpose::TlsServer,
            output: String::new(),
            config_output: String::new(),
            key_content: String::new(),
            csr_content: String::new(),
            is_executing: false,
            pending_cert: None,
        }
    }

    fn update_config_preview(&mut self) {
        let required_ok = self.country.len() == 2
            && self.country.chars().all(|c| c.is_alphabetic())
            && !self.common_name.trim().is_empty()
            && !self.organization.trim().is_empty()
            && !self.locality.trim().is_empty()
            && !self.state.trim().is_empty();

        if required_ok {
            match CertConfig::from(&*self).generate_config() {
                Ok(text) => self.config_output = text,
                Err(_) => self.config_output.clear(),
            }
        } else {
            self.config_output.clear();
        }
    }

    fn clear_form(&mut self) {
        log::debug!("Clearing form");
        self.country.clear();
        self.state.clear();
        self.locality.clear();
        self.organization.clear();
        self.common_name.clear();
        self.sans.clear();
        self.current_san.clear();
        self.organizational_unit.clear();
        self.email.clear();
        self.street_address.clear();
        self.postal_code.clear();
        self.key_algorithm = KeyAlgorithm::Rsa2048;
        self.hash_algorithm = "sha256".to_string();
        self.cert_purpose = CertPurpose::TlsServer;
        self.output.clear();
        self.config_output.clear();
        self.key_content.clear();
        self.csr_content.clear();
        self.is_executing = false;
        self.pending_cert = None;
        log::debug!("Form cleared");
    }

    #[cfg(debug_assertions)]
    fn fake_input(&mut self) {
        use fake::faker::name::de_de::{FirstName, LastName};
        use fake::faker::name::en::LastName as enLastName;
        use fake::faker::job::de_de::Title;
        use fake::faker::address::de_de::{StreetName, BuildingNumber, ZipCode};
        use fake::faker::internet::de_de::{DomainSuffix, IP};

        let fake_company: String = fake::faker::company::de_de::CompanyName().fake();
        let fake_domain = format!(
            "{}.{}",
            sanitize(enLastName().fake::<&str>()).to_ascii_lowercase(),
            DomainSuffix().fake::<&str>()
        );
        let fake_state: String = fake::faker::address::de_de::StateName().fake();
        let fake_locality: String = fake::faker::address::de_de::CityName().fake();

        // Generate email with firstname.lastname@domain
        let first_name: String = sanitize(FirstName().fake());
        let last_name: String = sanitize(LastName().fake());
        let fake_email = format!(
            "{}.{}@{}",
            first_name.to_ascii_lowercase(),
            last_name.to_ascii_lowercase(),
            fake_domain.clone()
        );

        let san_amount = fake::rand::rng().random::<u8>() % 5;
        let mut san_list: Vec<String> = Vec::with_capacity(san_amount as usize + 1);
        san_list.push(fake_domain.clone());
        for _ in 0..san_amount {
            if rand::random_bool(0.2) {
                san_list.push(IP().fake::<String>());
            } else {
                let subdomain = sanitize(fake::faker::company::en::BsNoun().fake::<&str>()).to_ascii_lowercase();
                san_list.push(format!("{}.{}", subdomain, fake_domain));

            }
        }

        // Generate organizational unit (job title)
        let fake_ou: String = Title().fake();

        // Generate street address
        let street_name: String = StreetName().fake();
        let building_number: String = BuildingNumber().fake();
        let fake_street = format!("{} {}", street_name, building_number);

        // Generate postal code
        let fake_postal: String = ZipCode().fake();

        log::debug!("Faking input with: \n\tCompany: {}\n\tDomain: {}\n\tState: {}\n\tLocality: {}\n\tEmail: {}\n\tStreet: {}\n\tPostal: {}\n\tOU: {}\n", fake_company, fake_domain, fake_state, fake_locality, fake_email, fake_street, fake_postal, fake_ou);

        self.organizational_unit = fake_ou;
        self.email = fake_email;
        self.street_address = fake_street;
        self.postal_code = fake_postal;

        self.country = "DE".to_string();
        self.state = fake_state;
        self.locality = fake_locality;
        self.organization = fake_company;
        self.common_name = fake_domain.clone();
        self.sans = san_list;

    }
}

impl eframe::App for CertGenApp {
    fn ui(&mut self, ui: &mut Ui, _frame: &mut Frame) {
        egui::CentralPanel::default().show_inside(ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.heading("X.509 Certificate Request Generator");
            });

            ui.add_space(10.0);

            egui::ScrollArea::vertical().show(ui, |ui| {
                // Form component
                form::render(ui, self);

                ui.add_space(10.0);

                self.update_config_preview();

                // Buttons
                ui.horizontal(|ui| {
                    #[cfg(debug_assertions)]
                    if ui.button("Fake input").clicked() {
                        self.fake_input();
                    }

                    // Execute button component
                    execute_button::render(ui, self);
                });

                ui.add_space(10.0);

                // Output component
                output::render(ui, &self.config_output, &self.output);
            });
        });
    }
}
