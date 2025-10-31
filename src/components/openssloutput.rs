use dioxus::prelude::*;

// Component for displaying OpenSSL command output
#[component]
pub fn OpenSSLOutput(output: Signal<String>) -> Element {
    // Check if output is empty
    let has_output = !output.read().is_empty();

    // Parse the output to identify errors vs normal output
    let has_error = output.read().to_lowercase().contains("error");

    // Keep output alive for rendering
    let _longer_living = output.read();

    rsx! {
        div { class: "openssl-output-container",
            // Only show if there's actual output
            if has_output {
                div {
                    class: "openssl-output",
                    class: if has_error {
                        "openssl-output-error"
                    } else {
                        "openssl-output-success"
                    },

                    div { class: "openssl-output-header",
                        h3 {
                            if has_error {
                                span { class: "openssl-output-icon error", "✖" }
                                "OpenSSL Command Failed"
                            } else {
                                span { class: "openssl-output-icon success", "✓" }
                                "Output"
                            }
                        }
                    }

                    div { class: "openssl-output-content",
                        pre {
                            code {
                                class: "openssl-output-line",
                                {output}
                            }
                        }
                    }
                }
            } else {
                div { class: "openssl-output-empty",
                    "No output available"
                }

            }
        }
    }
}