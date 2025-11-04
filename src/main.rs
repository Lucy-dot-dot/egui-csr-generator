#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::fs::File;
use std::io::{BufWriter, Write};
use std::sync::Arc;
use eframe::{egui, CreationContext};
#[cfg(debug_assertions)]
use fake::{Fake, Rng};
use log::LevelFilter;
use openssl_cert_tools::CertConfig;

mod components;
mod openssl_cert_tools;

use components::form;
use components::openssloutput;
use components::execute_button;
use components::save_button;

fn setup_logger() {
    let current_time = time::OffsetDateTime::now_local().unwrap_or(time::OffsetDateTime::now_utc());
    let target = Box::new(BufWriter::new(File::create(format!("{}.log", current_time.unix_timestamp())).expect("Can't create file")));

    env_logger::Builder::new()
        .target(env_logger::Target::Pipe(target))
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

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([800.0, 700.0])
            .with_title("OpenSSL Certificate Request Generator"),
        ..Default::default()
    };

    eframe::run_native(
        "OpenSSL Certificate Generator",
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

    // Advanced mode fields
    pub advanced_mode: bool,
    pub organizational_unit: String,
    pub email: String,
    pub street_address: String,
    pub postal_code: String,
    pub key_size: String,
    pub hash_algorithm: String,

    // Output state
    pub openssl_output: String,
    pub config_output: String,
    pub key_content: String,
    pub csr_content: String,
    pub is_executing: bool,
}

impl CertGenApp {
    fn new(cc: &CreationContext) -> Self {
        log::debug!("Initializing app, creating font");
        let mut fonts = egui::FontDefinitions::default();
        fonts.font_data.insert("JetBrainsMono".to_owned(), Arc::from(egui::FontData::from_static(include_bytes!("../assets/JetBrainsMono-Regular.ttf"))));

        fonts.families.insert(egui::FontFamily::Name("JetBrainsMono".into()), vec!["JetBrainsMono".to_owned()]);

        fonts.families.get_mut(&egui::FontFamily::Proportional).unwrap() //it works
            .insert(0, "JetBrainsMono".to_owned());

        fonts.families.get_mut(&egui::FontFamily::Monospace).unwrap()
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
            advanced_mode: false,
            organizational_unit: String::new(),
            email: String::new(),
            street_address: String::new(),
            postal_code: String::new(),
            key_size: "2048".to_string(),
            hash_algorithm: "sha256".to_string(),
            openssl_output: String::new(),
            config_output: String::new(),
            key_content: String::new(),
            csr_content: String::new(),
            is_executing: false,
        }
    }

    fn generate_config(&mut self) {
        log::debug!("Generating config");
        // Clear previous output
        self.openssl_output.clear();

        log::debug!("Input: Country: {}, State: {}, Locality: {}, Organization: {}, Common Name: {}, SAN: {:?}, Key Size: {}, Hash Algorithm: {}", self.country, self.state, self.locality, self.organization, self.common_name, self.sans, self.key_size, self.hash_algorithm);

        // Validate country code
        if self.country.len() != 2 {
            self.openssl_output.push_str("Error: Country code must be exactly 2 letters\n");
            return;
        }
        if !self.country.chars().all(|c| c.is_alphabetic()) {
            self.openssl_output.push_str("Error: Country code must contain only letters\n");
            return;
        }

        // Validate required fields
        if self.common_name.trim().is_empty() {
            self.openssl_output.push_str("Error: Common Name is required\n");
            return;
        }
        if self.organization.trim().is_empty() {
            self.openssl_output.push_str("Error: Organization is required\n");
            return;
        }
        if self.locality.trim().is_empty() {
            self.openssl_output.push_str("Error: Locality (city) is required\n");
            return;
        }
        if self.state.trim().is_empty() {
            self.openssl_output.push_str("Error: State/Province is required\n");
            return;
        }

        let ou_opt = if self.organizational_unit.trim().is_empty() {
            None
        } else {
            Some(self.organizational_unit.as_str())
        };

        let email_opt = if self.email.trim().is_empty() {
            None
        } else {
            Some(self.email.as_str())
        };

        let street_opt = if self.street_address.trim().is_empty() {
            None
        } else {
            Some(self.street_address.as_str())
        };

        let postal_opt = if self.postal_code.trim().is_empty() {
            None
        } else {
            Some(self.postal_code.as_str())
        };

        let config = CertConfig {
            country: &self.country,
            state: &self.state,
            locality: &self.locality,
            organization: &self.organization,
            organizational_unit: ou_opt,
            email: email_opt,
            street_address: street_opt,
            postal_code: postal_opt,
            common_name: &self.common_name,
            san: &self.sans,
            key_size: &self.key_size,
            hash_algorithm: &self.hash_algorithm,
        }
        .generate_config();

        match config {
            Ok(config_text) => {
                log::debug!("Generated config:\n\n{}\n", config_text);
                self.openssl_output.push_str("------------------- Openssl config begin ----------------------\n");
                self.openssl_output.push_str(&config_text);
                self.openssl_output.push_str("------------------- Openssl config end ----------------------\n");
                self.config_output = config_text;
            }
            Err(err) => {
                log::error!("Error generating config: {}\n", err);
                self.openssl_output.push_str(&format!("Error generating config: {}\n", err));
            }
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
        self.key_size = "2048".to_string();
        self.hash_algorithm = "sha256".to_string();
        self.openssl_output.clear();
        self.config_output.clear();
        self.key_content.clear();
        self.csr_content.clear();
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
            enLastName()
                .fake::<String>()
                .replace(" ", "_")
                .replace("'", "_")
                .to_ascii_lowercase(),
            DomainSuffix().fake::<&str>()
        );
        let fake_state: String = fake::faker::address::de_de::StateName().fake();
        let fake_locality: String = fake::faker::address::de_de::CityName().fake();

        // Generate email with firstname.lastname@domain
        let first_name: String = FirstName().fake();
        let last_name: String = LastName().fake();
        let fake_email = format!(
            "{}.{}@{}",
            first_name.replace(" ", "").replace("ß", "ss").to_ascii_lowercase(),
            last_name.replace(" ", "").replace("ß", "ss").to_ascii_lowercase(),
            fake_domain.clone()
        );

        self.advanced_mode = fake::rand::random_bool(0.5);
        let san_amount = fake::rand::rng().random::<u8>() % 5;
        let mut san_list: Vec<String> = Vec::with_capacity(san_amount as usize + 1);
        san_list.push(fake_domain.clone());
        for _ in 0..san_amount {
            if fake::rand::random_bool(0.2) {
                san_list.push(format!("{}", IP().fake::<String>()));
            } else {
                let subdomain = fake::faker::company::en::BsNoun().fake::<String>().replace(" ", "_");
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

        if self.advanced_mode {
            self.organizational_unit = fake_ou;
            self.email = fake_email;
            self.street_address = fake_street;
            self.postal_code = fake_postal;
        }

        self.country = "DE".to_string();
        self.state = fake_state;
        self.locality = fake_locality;
        self.organization = fake_company;
        self.common_name = fake_domain.clone();
        self.sans = san_list;
    }
}

impl eframe::App for CertGenApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.heading("OpenSSL Certificate Request Generator");
            });

            ui.add_space(10.0);

            egui::ScrollArea::vertical().show(ui, |ui| {
                // Form component
                form::render(ui, self);

                ui.add_space(10.0);

                // Buttons
                ui.horizontal(|ui| {
                    #[cfg(debug_assertions)]
                    {
                        if ui.button("Fake input").clicked() {
                            self.fake_input();
                        }
                    }

                    if ui.button("Generate Configuration").clicked() {
                        self.generate_config();
                    }

                    // Execute button component
                    execute_button::render(ui, self);

                    // Save button component (only show if we have key and csr)
                    if !self.key_content.is_empty() && !self.csr_content.is_empty() {
                        save_button::render(ui, self);
                    }
                });

                ui.add_space(10.0);

                // Output component
                openssloutput::render(ui, &self.openssl_output);
            });
        });
    }
}
