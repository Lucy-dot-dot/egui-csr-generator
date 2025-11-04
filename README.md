# OpenSSL Certificate Generator

A desktop application built with Dioxus that provides a graphical interface for generating OpenSSL certificate signing requests (CSRs). The application simplifies the process of creating certificate configurations, executing OpenSSL commands, and packaging certificate files.

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
- Dioxus CLI (`dx`)
- Node.js and npm (optional, for Tailwind CSS development)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd openssl-cert-dioxius
```

2. Install Dioxus CLI if not already installed:
```bash
cargo install dioxus-cli
```

3. Build the project:
```bash
cargo build --release
```

## Usage

### Running the Application

Start the development server:
```bash
dx serve --platform desktop
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

The compiled binary will be available in `target/release/`

## Project Structure

```
openssl-cert-dioxius/
├── src/
│   ├── main.rs                    # Entry point and main App component
│   ├── openssl_cert_tools.rs      # Core certificate logic and OpenSSL integration
│   └── components/
│       ├── mod.rs                 # Module exports and zip generation
│       ├── form.rs                # Input form component
│       ├── execute_button.rs      # OpenSSL execution handler
│       ├── save_button.rs         # Manual save functionality
│       └── openssloutput.rs       # Output display component
├── assets/                        # CSS and font files
├── Cargo.toml                     # Rust dependencies and features
├── Dioxus.toml                    # Dioxus configuration
└── README.md
```

## Technical Details

### Core Modules

- **main.rs**: Entry point containing UI layout, form state management, and primary event handlers
- **openssl_cert_tools.rs**: Certificate logic including:
  - `CertConfig`: Certificate metadata and config file generation
  - `generate_config()`: Creates OpenSSL .cnf files with SAN support
  - `execute_openssl_command()`: Executes OpenSSL CLI commands
  - `sanitize()`: Handles German umlauts

### Key Dependencies

- **dioxus 0.6.3**: Desktop UI framework
- **fake**: Test data generation (debug mode only)
- **zip**: Certificate file bundling
- **dirs**: Downloads directory location

### Application Flow

1. User fills in certificate details through the Form component
2. "Generate Configuration" validates input and creates OpenSSL config string
3. "Execute OpenSSL Command" writes temp config file, executes `openssl req -new`, captures output, saves zip to downloads folder, and cleans up temp files
4. Output is displayed in the OpenSSLOutput component

## License

The project is dual licensed under the Unlicense and under GNU GENERAL PUBLIC LICENSE version 3

