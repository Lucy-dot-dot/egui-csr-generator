#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use dioxus::desktop::{use_window, LogicalSize};
use dioxus::desktop::wry::dpi::Size;
use fake;
use dioxus::prelude::*;
use fake::Fake;
use openssl_cert_tools::CertConfig;

mod components;
mod openssl_cert_tools;
use components::form::Form;
use components::openssloutput::OpenSSLOutput;
use components::execute_button::ExecuteButton;
use crate::components::save_button::SaveButton;

const FAVICON: Asset = asset!("/assets/favicon.ico");
const MAIN_CSS: Asset = asset!("/assets/styling/main.css");
const OPENSSL_OUTPUT_CSS: Asset = asset!("/assets/styling/openssl_output.css");
const DOWNLOAD_BUTTON_CSS: Asset = asset!("/assets/styling/download_button.css");
const JETBRAINS_FONT: Asset = asset!("/assets/JetBrainsMono-Regular.woff2");

fn main() {
    launch(App);
}

#[component]
fn App() -> Element {
    // Build cool things ✌️
    let mut country = use_signal(|| String::new());
    let mut state = use_signal(|| String::new());
    let mut locality = use_signal(|| String::new());
    let mut organization = use_signal(|| String::new());
    let mut common_name = use_signal(|| String::new());
    let mut sans = use_signal(|| Vec::<String>::new());
    let mut current_san = use_signal(|| String::new());

    // Advanced mode fields
    let advanced_mode = use_signal(|| false);
    let mut organizational_unit = use_signal(|| String::new());
    let mut email = use_signal(|| String::new());
    let mut key_size = use_signal(|| "2048".to_string());
    let mut hash_algorithm = use_signal(|| "sha256".to_string());

    let mut openssl_state = use_signal(|| String::new());
    let mut config_output = use_signal(|| String::new());
    let mut key_content = use_signal(|| String::new());
    let mut csr_content = use_signal(|| String::new());
    let is_executing = use_signal(|| false);
    let generate = move |_| {
        // Clear previous output
        openssl_state.set(String::new());

        // Validate country code
        if country.read().len() != 2 {
            openssl_state.write().push_str("Error: Country code must be exactly 2 letters\n");
            return;
        }
        if !country.read().chars().all(|c| c.is_alphabetic()) {
            openssl_state.write().push_str("Error: Country code must contain only letters\n");
            return;
        }

        // Validate required fields
        if common_name.read().trim().is_empty() {
            openssl_state.write().push_str("Error: Common Name is required\n");
            return;
        }
        if organization.read().trim().is_empty() {
            openssl_state.write().push_str("Error: Organization is required\n");
            return;
        }
        if locality.read().trim().is_empty() {
            openssl_state.write().push_str("Error: Locality (city) is required\n");
            return;
        }
        if state.read().trim().is_empty() {
            openssl_state.write().push_str("Error: State/Province is required\n");
            return;
        }

        let ou_value = organizational_unit.read();
        let email_value = email.read();
        let ou_opt = if ou_value.trim().is_empty() { None } else { Some(ou_value.as_str()) };
        let email_opt = if email_value.trim().is_empty() { None } else { Some(email_value.as_str()) };

        let config = CertConfig {
            country: country.read().as_str(),
            state: state.read().as_str(),
            locality: locality.read().as_str(),
            organization: organization.read().as_str(),
            organizational_unit: ou_opt,
            email: email_opt,
            common_name: common_name.read().as_str(),
            san: sans.read().as_ref(),
            key_size: key_size.read().as_str(),
            hash_algorithm: hash_algorithm.read().as_str(),
        }.generate_config();

        match config {
            Ok(config_text) => {
                openssl_state.write().push_str("------------------- Openssl config begin ----------------------\n");
                openssl_state.write().push_str(&config_text);
                openssl_state.write().push_str("------------------- Openssl config end ----------------------\n");
                config_output.set(config_text);
            }
            Err(err) => {
                openssl_state.write().push_str(&format!("Error generating config: {}\n", err));
            }
        }
    };

    use_window().set_inner_size(Size::Logical(LogicalSize::new(800.0, 700.0)));

    let clear_form = move |_| {
        country.set(String::new());
        state.set(String::new());
        locality.set(String::new());
        organization.set(String::new());
        common_name.set(String::new());
        sans.set(Vec::new());
        current_san.set(String::new());
        organizational_unit.set(String::new());
        email.set(String::new());
        key_size.set("2048".to_string());
        hash_algorithm.set("sha256".to_string());
        openssl_state.set(String::new());
        config_output.set(String::new());
        key_content.set(String::new());
        csr_content.set(String::new());
    };

    let fake_input = move |_| {
        let fake_company: String = fake::faker::company::de_de::CompanyName().fake();
        let fake_domain = format!("{}.{}", fake::faker::name::de_de::LastName().fake::<String>().replace(" ", "_").replace("ß", "ss").to_ascii_lowercase(), fake::faker::internet::de_de::DomainSuffix().fake::<&str>());
        let fake_state: String = fake::faker::address::de_de::StateName().fake();
        let fake_locality: String = fake::faker::address::de_de::CityName().fake();
        let fake_country: String = String::from("DE");

        country.set(fake_country);
        state.set(fake_state);
        locality.set(fake_locality);
        organization.set(fake_company);
        common_name.set(fake_domain.clone());
        // Initialize SANs with CN as first entry
        sans.set(vec![fake_domain]);
    };

    let ret = document::create_element_in_head("style", &[], Some(r#"@font-face {
    font-family: 'JetBrains Mono';
    src: url('TOKEN') format('woff2');
    font-weight: 400;
    font-style: normal;
    font-display: swap;
}
"#.to_string().replace("TOKEN", JETBRAINS_FONT.resolve().to_str().unwrap())));
    document::eval(&ret);

    rsx! {
        // Global app resources
        document::Link { rel: "icon", href: FAVICON }
        document::Link { rel: "stylesheet", href: MAIN_CSS }
        document::Link { rel: "stylesheet", href: OPENSSL_OUTPUT_CSS }
        document::Link { rel: "stylesheet", href: DOWNLOAD_BUTTON_CSS }
        document::Link { rel: "preload", href: JETBRAINS_FONT, type: "font/woff2", crossorigin: "anonymous", as: "font" }

        div {
            class: "container",
            h1 { class: "title", "OpenSSL Certificate Request Generator" }

            Form {
                common_name: common_name,
                organization: organization,
                sans: sans,
                current_san: current_san,
                state: state,
                locality: locality,
                country: country,
                on_clear: clear_form,
                advanced_mode: advanced_mode,
                organizational_unit: organizational_unit,
                email: email,
                key_size: key_size,
                hash_algorithm: hash_algorithm
            }

            div {
                class: "button-container",
                if cfg!(debug_assertions) {
                    button {
                        class: "primary",
                        onclick: fake_input,
                        "Fake input"
                    }
                }
                button {
                    class: "primary",
                    onclick: generate,
                    "Generate Configuration"
                }

                ExecuteButton {
                    csr_content: csr_content,
                    key_content: key_content,
                    openssl_state: openssl_state,
                    config_output: config_output,
                    is_executing: is_executing,
                    common_name: common_name,
                }

                if !key_content.read().is_empty() && !csr_content.read().is_empty() {
                    SaveButton {
                        config_content: config_output,
                        common_name: common_name,
                        key_content: key_content,
                        csr_content: csr_content
                    }
                }
            }
            OpenSSLOutput { output: openssl_state }
        }
    }
}
