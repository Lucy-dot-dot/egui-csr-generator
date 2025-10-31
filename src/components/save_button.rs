use dioxus::prelude::*;
use super::generate_and_save;

#[component]
pub fn SaveButton(
    config_content: Signal<String>,
    common_name: Signal<String>,
    key_content: Signal<String>,
    csr_content: Signal<String>,
) -> Element {
    let mut is_generating = use_signal(|| false);

    let generate_and_save_callback = move |_| {
        is_generating.set(true);

        // Get file contents
        let cnf = config_content.read().clone();
        let name = common_name.read().clone();
        let key = key_content.read().clone();
        let csr = csr_content.read().clone();
        match generate_and_save(&cnf, &name, &key, &csr) {
            Ok(_) => {}
            Err(err) => {
                eprintln!("{}", err);
            }
        }
        
        is_generating.set(false);
    };

    rsx! {
        button {
            class: "save-button",
            class: "secondary",
            disabled: is_generating(),
            onclick: generate_and_save_callback,

            if is_generating() {
                span { class: "save-spinner" }
                "Generating files..."
            } else {
                span { class: "save-icon", "💾" }
                "Save Certificate Files"
            }
        }
    }
}