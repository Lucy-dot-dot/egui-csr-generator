use dioxus::prelude::*;

#[component]
pub fn Form(
    mut country: Signal<String>,
    mut state: Signal<String>,
    mut locality: Signal<String>,
    mut organization: Signal<String>,
    mut common_name: Signal<String>,
    mut current_san: Signal<String>,
    mut sans: Signal<Vec<String>>,
    on_clear: EventHandler<()>,
    mut advanced_mode: Signal<bool>,
    mut organizational_unit: Signal<String>,
    mut email: Signal<String>,
    mut key_size: Signal<String>,
    mut hash_algorithm: Signal<String>,
) -> Element {
    let mut add_san = move || {
        if !current_san.read().is_empty() {
            sans.write().push(current_san.read().clone());
            current_san.set(String::new());
        }
    };

    rsx! {
        div {
            class: "form",
            style: "position: relative;",

            // Advanced mode toggle in top right corner
            div {
                style: "position: absolute; top: .2rem; right: .75rem; z-index: 10;",
                label {
                    style: "display: flex; align-items: center; gap: 0.5rem; font-size: 0.85rem; color: #6b7280; cursor: pointer; user-select: none;",
                    input {
                        type: "checkbox",
                        checked: advanced_mode(),
                        onchange: move |evt| advanced_mode.set(evt.checked()),
                        style: "cursor: pointer;"
                    }
                    "Advanced"
                }
            }

            div {
                class: "form-group",

                label { "Country Code (2 letters):" }
                input {
                    placeholder: "DE",
                    value: "{country}",
                    oninput: move |evt| country.set(evt.value())
                }
            }

            div { class: "form-group",
                label { "State/Province:" }
                input {
                    placeholder: "Nordrhein-Westfalen",
                    value: "{state}",
                    oninput: move |evt| state.set(evt.value())
                }
            }

            div { class: "form-group",
                label { "Locality (city):" }
                input {
                    placeholder: "Münster",
                    value: "{locality}",
                    oninput: move |evt| locality.set(evt.value())
                }
            }

            div { class: "form-group",
                label { "Organization:" }
                input {
                    placeholder: "Test Inc.",
                    value: "{organization}",
                    oninput: move |evt| organization.set(evt.value())
                }
            }

            // Advanced mode fields
            if advanced_mode() {
                div { class: "form-group",
                    label { "Organizational Unit (OU):" }
                    input {
                        placeholder: "IT Department",
                        value: "{organizational_unit}",
                        oninput: move |evt| organizational_unit.set(evt.value())
                    }
                }

                div { class: "form-group",
                    label { "Email Address:" }
                    input {
                        type: "email",
                        placeholder: "admin@example.com",
                        value: "{email}",
                        oninput: move |evt| email.set(evt.value())
                    }
                }

                div { class: "form-group",
                    label { "Key Size:" }
                    select {
                        value: key_size,
                        onchange: move |evt| key_size.set(evt.value()),
                        option { value: "2048", "2048 bits" }
                        option { value: "4096", "4096 bits" }
                    }
                }

                div { class: "form-group",
                    label { "Hash Algorithm:" }
                    select {
                        value: hash_algorithm,
                        onchange: move |evt| hash_algorithm.set(evt.value()),
                        option { value: "sha256", "SHA-256" }
                        option { value: "sha384", "SHA-384" }
                        option { value: "sha512", "SHA-512" }
                    }
                }
            }

            div { class: "form-group",
                label { "Common Name:" }
                input {
                    placeholder: "mail.test.org",
                    value: "{common_name}",
                    oninput: move |evt| {
                        let new_cn = evt.value();

                        // Update or add CN as first SAN
                        let mut sans_vec = sans.read().clone();
                        if !new_cn.is_empty() {
                            if sans_vec.is_empty() {
                                sans_vec.push(new_cn.clone());
                            } else {
                                sans_vec[0] = new_cn.clone();
                            }
                        } else if !sans_vec.is_empty() {
                            // If CN is cleared, remove first SAN
                            sans_vec.remove(0);
                        }
                        sans.set(sans_vec);

                        common_name.set(new_cn);
                    }
                }
            }

            // Subject Alternative Names section
            div { class: "form-group",
                label { "Subject Alternative Names:" }
                div { class: "san-entry",
                    input {
                        placeholder: "Enter domain or IP (e.g. www.example.com)",
                        value: "{current_san}",
                        onkeypress: move |evt| {
                            if evt.key() == "Enter".parse().unwrap() && !current_san.read().is_empty() {
                                add_san();
                            }
                        },
                        oninput: move |evt| current_san.set(evt.value())
                    }
                    button {
                        class: "add-san-button",
                        onclick: move |_| add_san(),
                        "Add SAN"
                    }
                }
            }

            // SAN list (shown only if there are SANs)
            if !sans.read().is_empty() {
                div { class: "sans-list",
                    ul {
                        for (i, san) in sans.read().iter().enumerate() {
                            li {
                                if san.parse::<std::net::IpAddr>().is_ok() {
                                    span { class: "sans-list-icon", "🌐" }
                                } else {
                                    span { class: "sans-list-icon", "🔗" }
                                }
                                "{san}"
                                // Show label for first SAN (which matches CN)
                                if i == 0 {
                                    span { class: "san-badge", "(from CN)" }
                                } else {
                                    // Only allow removing SANs after the first one
                                    button {
                                        class: "remove-san-button",
                                        onclick: move |_| {
                                            let mut sans_vec = sans.read().clone();
                                            sans_vec.remove(i);
                                            sans.set(sans_vec);
                                        },
                                        "Remove"
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                // Show a message when no SANs are added
                div { class: "sans-list-empty",
                    "No alternative names added yet"
                }
            }

            // Clear button - spans both columns
            div { style: "width: 100%; margin-left: 1rem",
                button {
                    class: "secondary",
                    style: "width: 100%;",
                    onclick: move |_| on_clear.call(()),
                    "Clear All Fields"
                }
            }
        }
    }
}
