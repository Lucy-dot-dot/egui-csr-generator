# OpenSSL Certificate Generator

A desktop application built with egui/eframe that provides a graphical interface for generating OpenSSL certificate signing requests (CSRs). The application simplifies the process of creating certificate configurations, generating keys and CSRs natively (no external OpenSSL required), and packaging certificate files.

## AI Disclaimer

This project made heavy use of Claude. If you do not trust AI generated code for generating sensitive things like Certificates, do not use this project.

## Features

- User-friendly GUI for certificate request generation
- Live OpenSSL configuration preview that updates as you type
- Support for Subject Alternative Names (SANs) with auto-detection of DNS names and IP addresses
- Optional fields: Organizational Unit, Email, Street Address, Postal Code, Key Size, Hash Algorithm
- Wildcard certificate support
- International character handling (German umlauts, French accents, Polish/Czech characters, etc.)
- Automatic zip packaging of certificate files (.cnf, .key, .csr)
- Auto-save to downloads folder
- Includes recreate command for reference
- No external OpenSSL installation required — certificate generation is handled natively
- Debug mode with test data generation (German locale)

## Requirements

- Rust (latest stable version)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd egui-csr-generator
```

2. Build the project:
```bash
cargo build --release
```

## Usage

### Running the Application

Run the application in development mode:
```bash
cargo run
```

Or run the release build:
```bash
cargo run --release
```

### Creating a Certificate Request

1. Fill in the required certificate details:
   - **Country**: 2-character country code (e.g. `DE`)
   - **State/Province**: Full state or province name
   - **Locality**: City name
   - **Organization**: Company or organization name
   - **Common Name**: Domain name or service identifier
   - **SANs**: Subject Alternative Names (DNS names or IP addresses)

2. Optionally fill in **Optional Values**:
   - Organizational Unit, Email Address, Street Address, Postal Code
   - Key Size (2048 or 4096 bits)
   - Hash Algorithm (SHA-256, SHA-384, SHA-512)

3. The **Config Preview** in the output area updates live as you type. Once all required fields are valid, the **Generate Certificate Request** button appears.

4. Click **Generate Certificate Request** to:
   - Generate the private key and CSR
   - Save all files as a zip package to your downloads folder
   - Display the command output

5. Optional: Use **Save Certificate Files** to manually re-save if needed.

### Special Features

- **Wildcard Certificates**: CN starting with `*.` is automatically converted for filenames (e.g., `*.example.com` becomes `wildcard.example.com.key`)
- **Debug Mode**: In debug builds, a "Fake input" button generates test data using German locale

## Development

### Building for Release

```bash
cargo build --release
```

The compiled binary will be available in `target/release/certificate-request-generator.exe`

## Project Structure

```
egui-csr-generator/
├── src/
│   ├── main.rs                        # Entry point, app state, egui App implementation
│   ├── cert_config.rs                 # CertConfig struct and OpenSSL .cnf generation
│   ├── openssl_native.rs              # Native key/CSR generation via rcgen + rsa
│   └── components/
│       ├── mod.rs                     # Module exports and zip save logic
│       ├── form.rs                    # Certificate details form
│       ├── execute_button.rs          # Generate Certificate Request button
│       ├── save_button.rs             # Manual save button
│       └── openssloutput.rs           # Config preview and command output display
├── assets/
│   └── JetBrainsMono-Regular.ttf      # Embedded font
├── Cargo.toml
└── README.md
```

## Technical Details

### Core Modules

- **main.rs**: Entry point containing the `CertGenApp` struct (all form state), font setup, and the egui `App` implementation. Config preview is regenerated every frame via `update_config_preview()`.
- **cert_config.rs**: `CertConfig` struct with `generate_config()` that produces a properly formatted OpenSSL `.cnf` file including SAN support. Also contains `sanitize_for_cert_field()` for international character handling.
- **openssl_native.rs**: Native certificate generation using `rcgen` and `rsa` — no external OpenSSL binary required.
- **components/**: Modular egui render functions that take `&mut egui::Ui` and `&mut CertGenApp`.

### Key Dependencies

- **egui**: Immediate mode GUI framework
- **eframe**: egui framework for native applications
- **rcgen**: Native certificate and CSR generation
- **rsa**: RSA key generation
- **rand**: Random number generation
- **zip**: Certificate file bundling
- **dirs**: Downloads directory location
- **fake**: Test data generation (debug mode only)
- **log** & **env_logger**: Logging to timestamped files
- **time**: Time handling and formatting

### Application Flow

1. User fills in certificate details through the egui form
2. Config preview updates live in the output area as fields change — the execute button appears once all required fields are valid
3. Clicking **Generate Certificate Request** generates the private key and CSR natively, saves a zip to the downloads folder, and displays the result
4. Output is shown in the output area below the config preview

## License

The project is dual licensed under the Unlicense and under GNU GENERAL PUBLIC LICENSE version 3
