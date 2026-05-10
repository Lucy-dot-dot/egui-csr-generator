# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an egui/eframe desktop application that generates certificate signing requests (CSRs). It provides an immediate-mode GUI for creating certificate configurations, generating key pairs and CSRs natively (via `rcgen` and `rsa`), and saving certificate files as a zip package to the downloads folder. It does not invoke the OpenSSL CLI.

## Build and Development Commands

### Running the Application

```bash
cargo run
```

For optimized development builds:

```bash
cargo run --release
```

### Building for Release

```bash
cargo build --release
```

Binary name: `certificate-request-generator` (defined in Cargo.toml)

## Architecture

### Core Modules

- **main.rs**: Entry point containing:
  - `CertGenApp` struct: Holds all application state including form fields (country, state, locality, organization, common name, SANs), advanced fields (organizational_unit, email, street_address, postal_code, key_algorithm, hash_algorithm, cert_purpose), and output state (openssl_output, config_output, key_content, csr_content, is_executing, pending_cert)
  - `update_config_preview()`: Called every frame; validates input (2-char country code, non-empty required fields) and regenerates the config preview string
  - `clear_form()`: Resets all form fields and output state
  - `fake_input()`: Debug-only function for populating the form with German locale test data
  - `setup_logger()`: Initializes file-based logging with timestamps
  - Font loading: Embeds and configures JetBrainsMono font for the UI

- **cert_config.rs**: Certificate configuration module containing:
  - `CertConfig` struct: Holds certificate metadata; implements `From<&CertGenApp>`
  - `KeyAlgorithm` enum: `Rsa2048`, `Rsa3072`, `Rsa4096`, `EcdsaP256`, `EcdsaP384`
  - `CertPurpose` enum: `TlsServer`, `TlsClient`
  - `CertConfig::generate_config()`: Creates a formatted OpenSSL-compatible `.cnf` string (used for the config preview and included in the zip); not used to invoke the CLI
  - `sanitize()`: Debug-only; converts special characters to ASCII equivalents, spaces to hyphens — for filenames
  - `sanitize_for_cert_field()`: Same conversion but preserves spaces — for Distinguished Name fields

- **openssl_native.rs**: Native certificate generation module containing:
  - `GeneratedCert` struct: Holds `key_pem` and `csr_pem` strings
  - `generate_cert_request()`: Generates key pairs and CSRs in-process using `rcgen` and `rsa`. Supports RSA (2048/3072/4096) and ECDSA (P-256/P-384). No external process is spawned.

- **components/**: Helper modules for rendering UI sections with egui (not components in the React/Dioxus sense, but modular render functions)
  - `form.rs`: Contains `render()` function that displays the input form for certificate details, including advanced mode toggle
  - `execute_button.rs`: Contains `render()` function for the "Generate Certificate Request" button; spawns a background thread via `mpsc` to call `openssl_native::generate_cert_request()`, then auto-saves the zip via `generate_and_save()`
  - `save_button.rs`: Contains `render()` function for the "Save Certificate Files" button; allows manual re-saving if key and CSR are already generated
  - `openssloutput.rs`: Contains `render()` function for displaying the config preview and generation output in scrollable text areas
  - `mod.rs`: Module exports and contains `generate_and_save()` which creates a zip file in memory containing `.cnf`, `.key`, `.csr`, and `recreate_command.txt`, then writes it to the downloads folder

### Key Application Flow

1. User fills in certificate details through the form UI rendered by `form::render()`
2. `update_config_preview()` is called every frame; when all required fields are valid it populates `config_output` with the `.cnf` content via `CertConfig::generate_config()`
3. When `config_output` is non-empty, the "Generate Certificate Request" button appears (rendered by `execute_button::render()`); clicking it spawns a background thread that calls `openssl_native::generate_cert_request()` and then `generate_and_save()` to auto-save a zip to the downloads folder
4. The optional "Save Certificate Files" button (rendered by `save_button::render()`) is shown only when `key_content` and `csr_content` are non-empty, allowing manual re-saving
5. The config preview and generation messages appear in the output area rendered by `openssloutput::render()`

### Dependencies

- **egui 0.34.2**: Immediate mode GUI framework
- **eframe 0.34.2**: Framework for running egui applications natively
- **rcgen 0.14.7**: Native CSR/certificate generation (no OpenSSL CLI required)
- **rsa 0.9.10**: RSA key pair generation
- **zip 8.6.0**: Creates compressed certificate file bundles
- **dirs 6.0.0**: Locates user's downloads directory
- **fake 5.1.0**: Generates test data (German locale) - only used in debug mode
- **log 0.4.29** & **env_logger 0.11.10**: Logging infrastructure (logs to timestamped files)
- **time 0.3.4**: Time handling and formatting for log timestamps

### Special Handling

- **Wildcard certificates**: CN starting with `*.` is converted to `wildcard.` for filenames (e.g., `*.example.com` becomes `wildcard.example.com.key`); handled in `execute_button::spawn_generation()`
- **Special characters**: `sanitize_for_cert_field()` converts umlauts and accented characters to ASCII equivalents while preserving spaces, used when building Distinguished Name fields
- **SAN auto-detection**: Automatically distinguishes between IP addresses and DNS names in Subject Alternative Names
- **Debug mode**: Includes a "Fake input" button using German locale fake data for testing; `fake_input()` and `sanitize()` are compiled out in release builds
- **Advanced mode**: Toggle in the UI that reveals additional certificate fields (organizational unit, email, street address, postal code, key algorithm, hash algorithm, cert purpose)
- **Logging**: All operations are logged to timestamped .log files in the working directory
- **Background generation**: Key/CSR generation runs on a separate thread (RSA-4096 can be slow); the UI polls via `mpsc::Receiver` and shows "Processing..." while running

### Configuration Files

- **Cargo.toml**: Defines dependencies and build configuration. Binary name is set to `certificate-request-generator`. Release profile enables LTO and strip for smaller binaries.
- **Assets**: Located in `/assets/` directory, contains only JetBrainsMono-Regular.ttf font which is embedded into the binary using `include_bytes!`

### UI Framework Notes

This application uses **egui**, an immediate mode GUI framework. This means:
- No separate component lifecycle - UI is re-rendered every frame based on current state
- All state lives in the `CertGenApp` struct
- Component modules (`form.rs`, `execute_button.rs`, etc.) are just helper functions that take `&mut egui::Ui` and `&mut CertGenApp` parameters
- No CSS or styling files - all styling is done programmatically through egui's API
