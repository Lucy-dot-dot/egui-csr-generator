# OpenSSL Certificate Generator

A desktop application built with egui/eframe that provides a graphical interface for generating OpenSSL certificate signing requests (CSRs). The application simplifies the process of creating certificate configurations, executing OpenSSL commands, and packaging certificate files.

## Features

- User-friendly GUI for certificate request generation
- Automatic OpenSSL configuration file generation
- Support for Subject Alternative Names (SANs) with auto-detection of DNS names and IP addresses
- Wildcard certificate support
- German umlaut handling (ä, ü, ö)
- Automatic zip packaging of certificate files (.cnf, .key, .csr)
- Auto-save to downloads folder
- Includes recreate command for reference
- Debug mode with test data generation (German locale)

## Requirements

- Rust (latest stable version)
- OpenSSL installed and available in system PATH

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd openssl-cert-dioxius
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

1. Fill in the certificate details:
   - **Country**: 2-character country code (required)
   - **State/Province**: Full state or province name
   - **Locality**: City name
   - **Organization**: Company or organization name
   - **Common Name**: Domain name or service identifier
   - **SANs**: Subject Alternative Names (DNS names or IP addresses)

2. Click **Generate Configuration** to validate input and create the OpenSSL config

3. Click **Execute OpenSSL Command** to:
   - Generate the private key and CSR
   - Save all files as a zip package to your downloads folder
   - Display the OpenSSL output

4. Optional: Use **Save Certificate Files** to manually re-save if needed

### Special Features

- **Wildcard Certificates**: CN starting with `*.` is automatically converted for filenames (e.g., `*.example.com` becomes `wildcard.example.com.key`)
- **Debug Mode**: In debug builds, a "Fake input" button generates test data using German locale

## Development

### Building for Release

```bash
cargo build --release
```

The compiled binary will be available in `target/release/openssl-certificate-request-generator` (or `.exe` on Windows)

## Project Structure

```
openssl-cert-dioxius/
├── src/
│   ├── main.rs                    # Entry point and egui App implementation
│   └── openssl_cert_tools.rs      # Core certificate logic and OpenSSL integration
├── Cargo.toml                     # Rust dependencies
└── README.md
```

## Technical Details

### Core Modules

- **main.rs**: Entry point containing egui UI implementation, form state management, and event handlers
- **openssl_cert_tools.rs**: Certificate logic including:
  - `CertConfig`: Certificate metadata and config file generation
  - `generate_config()`: Creates OpenSSL .cnf files with SAN support
  - `execute_openssl_command()`: Executes OpenSSL CLI commands
  - `sanitize()`: Handles German umlauts

### Key Dependencies

- **egui 0.33.0**: Immediate mode GUI framework
- **eframe 0.33.0**: egui framework for native applications
- **zip 6.0.0**: Certificate file bundling
- **dirs 6.0.0**: Downloads directory location
- **fake 4.0.0**: Test data generation (debug mode only)
- **log 0.4.28** & **env_logger 0.11.8**: Logging infrastructure
- **time 0.3.44**: Time handling and formatting

### Application Flow

1. User fills in certificate details through the egui form interface
2. "Generate Configuration" validates input (especially 2-char country code) and creates OpenSSL config string
3. "Execute OpenSSL Command" writes temp config file, executes `openssl req -new`, captures output, saves zip to downloads folder, and cleans up temp files
4. Output is displayed in the application's output area

## License

The project is dual licensed under the Unlicense and under GNU GENERAL PUBLIC LICENSE version 3

