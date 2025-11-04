# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an egui/eframe desktop application that generates OpenSSL certificate signing requests (CSRs). It provides an immediate-mode GUI for creating certificate configurations, executing OpenSSL commands, and saving certificate files as a zip package to the downloads folder.

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

Binary name: `openssl-certificate-request-generator` (defined in Cargo.toml)

## Architecture

### Core Modules

- **main.rs**: Entry point containing:
  - `CertGenApp` struct: Holds all application state including form fields (country, state, locality, organization, common name, SANs), advanced mode fields (organizational_unit, email, street_address, postal_code, key_size, hash_algorithm), and output state (openssl_output, config_output, key_content, csr_content)
  - `generate_config()`: Method that validates input (especially 2-char country code) and creates OpenSSL config string
  - `fake_input()`: Debug mode function for generating test data using German locale
  - `setup_logger()`: Initializes file-based logging with timestamps
  - Font loading: Embeds and configures JetBrainsMono font for the UI

- **openssl_cert_tools.rs**: Core certificate logic module containing:
  - `CertConfig` struct: Holds certificate metadata and generates OpenSSL configuration files
  - `generate_config()`: Creates properly formatted OpenSSL .cnf files with support for SANs (DNS/IP detection)
  - `execute_openssl_command()`: Wrapper for executing OpenSSL CLI commands via `std::process::Command`
  - `sanitize()`: Handles German umlauts (ä, ü, ö) in certificate fields

- **components/**: Helper modules for rendering UI sections with egui (not components in the React/Dioxus sense, but modular render functions)
  - `form.rs`: Contains `render()` function that displays the input form for certificate details, including advanced mode toggle
  - `execute_button.rs`: Contains `render()` function for the execute button and handles OpenSSL command execution flow - creates temp config file, runs `openssl req -new`, reads generated .key/.csr files, auto-saves zip, cleans up temp files
  - `save_button.rs`: Contains `render()` function for manual save functionality
  - `openssloutput.rs`: Contains `render()` function for displaying OpenSSL command output in a scrollable text area
  - `mod.rs`: Module exports and contains `generate_and_save()` function that creates a zip file with .cnf, .key, .csr, and a recreate_command.txt file

### Key Application Flow

1. User fills in certificate details through the form UI rendered by `form::render()`
2. Clicking "Generate Configuration" calls `CertGenApp::generate_config()` which validates input and creates OpenSSL config string
3. "Execute OpenSSL Command" button (rendered by `execute_button::render()`) writes temp config file, executes `openssl req -new`, captures output, reads generated key/csr files, auto-saves zip to downloads folder, then cleans up temp files
4. Optional "Save Certificate Files" button (rendered by `save_button::render()`) allows manual re-saving if needed
5. All output appears in the output area rendered by `openssloutput::render()`

### Dependencies

- **egui 0.33.0**: Immediate mode GUI framework
- **eframe 0.33.0**: Framework for running egui applications natively
- **zip 6.0.0**: Creates compressed certificate file bundles
- **dirs 6.0.0**: Locates user's downloads directory
- **fake 4.0.0**: Generates test data (German locale) - only used in debug mode
- **log 0.4.28** & **env_logger 0.11.8**: Logging infrastructure (logs to timestamped files)
- **time 0.3.44**: Time handling and formatting for log timestamps

### Special Handling

- **Wildcard certificates**: CN starting with `*.` is converted to `wildcard.` for filenames (e.g., `*.example.com` becomes `wildcard.example.com.key`)
- **German characters**: Umlauts are sanitized to ASCII equivalents (ä→ae, ü→ue, ö→oe)
- **SAN auto-detection**: Automatically distinguishes between DNS names and IP addresses in Subject Alternative Names
- **Debug mode**: Includes a "Fake input" button using German locale fake data for testing
- **Advanced mode**: Toggle in the UI that reveals additional certificate fields (organizational unit, email, street address, postal code, key size, hash algorithm)
- **Logging**: All operations are logged to timestamped .log files in the working directory

### Configuration Files

- **Cargo.toml**: Defines dependencies and build configuration. Binary name is set to `openssl-certificate-request-generator`. Release profile enables LTO and strip for smaller binaries.
- **Assets**: Located in `/assets/` directory, contains only JetBrainsMono-Regular.ttf font which is embedded into the binary using `include_bytes!`

### UI Framework Notes

This application uses **egui**, an immediate mode GUI framework. This means:
- No separate component lifecycle - UI is re-rendered every frame based on current state
- All state lives in the `CertGenApp` struct
- Component modules (`form.rs`, `execute_button.rs`, etc.) are just helper functions that take `&mut egui::Ui` and `&mut CertGenApp` parameters
- No CSS or styling files - all styling is done programmatically through egui's API
