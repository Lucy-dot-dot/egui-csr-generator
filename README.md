# OpenSSL Certificate Generator

A desktop application built with egui/eframe that provides a graphical interface for generating certificate signing requests (CSRs). It simplifies the process of creating certificate configurations, generating key pairs and CSRs natively (no external OpenSSL installation required), and packaging the resulting files into a single zip.

## AI Disclaimer

This project made heavy use of Claude & GLM 5.2. If you do not trust AI generated code for generating sensitive things like Certificates, do not use this project.

## Features

- User-friendly GUI for certificate request generation
- Live configuration preview that updates as you type
- Support for Subject Alternative Names (SANs) with automatic detection of DNS names and IP addresses
- Optional fields: Organizational Unit, Email, Street Address, Postal Code, Certificate Purpose (TLS Server / TLS Client)
- Multiple key algorithms:
  - RSA 2048 / 3072 / 4096 (with selectable hash: SHA-256 / SHA-384 / SHA-512)
  - ECDSA P-256 and P-384
  - Ed25519
- Flexible export options:
  - PEM (text) or DER (binary) encoding
  - RSA keys can be exported as PKCS#8 or traditional PKCS#1
  - Optional passphrase to protect the private key (encrypted PKCS#8, scrypt + AES-256-CBC) — available for all key types
- Reuse an existing private key (paste an unencrypted PEM key or load it from a file) to generate a new CSR without generating a new key
- Import a previous configuration from a `config.toml` file or from a previously saved zip
- Wildcard certificate support
- International character handling (German umlauts, French accents, Polish/Czech characters, etc.) — automatically transliterated to ASCII for certificate fields
- Automatic zip packaging of certificate files (`.cnf`, `.key`, `.csr`, `config.toml`, `recreate_command.txt`)
- Native save dialog — you choose where the zip is written
- Includes an OpenSSL `recreate_command.txt` snippet for reference
- Debug mode with test data generation (German locale)

## Intentionally Not Supported

These are deliberate design decisions, not missing features:

- **No Certificate Authority (CA) support.** This tool generates certificate signing requests (CSRs) only. It does not create, sign, or issue certificates, and it cannot act as a CA. If you need a CA, use a dedicated CA tool.
- **No copy-to-clipboard for the key or CSR.** Generated files are written exclusively to a zip package. Clipboard access is intentionally omitted because people are prone to generating twice and then mismatching a key with its CSR, or losing the key entirely. By forcing everything through a single bundled zip, the key, CSR, and associated files can never get confused or separated.

## Requirements

- Rust (latest stable version)

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

The compiled binary will be available in `target/release/certificate-request-generator.exe` (on Windows).

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

2. Optionally fill in **Optional Values**:
   - Organizational Unit, Email Address, Street Address, Postal Code
   - Key Algorithm (RSA 2048 / 3072 / 4096, ECDSA P-256 / P-384, Ed25519)
   - Hash Algorithm (SHA-256 / SHA-384 / SHA-512 — RSA only; ECDSA and Ed25519 hashes are fixed by the key)
   - Certificate Purpose (TLS Server or TLS Client)

3. Optionally configure **Export Options**:
   - **Key Encoding**: PEM (text) or DER (binary)
   - **Key Format** (RSA only): PKCS#8 or PKCS#1
   - **Passphrase**: protects the private key as encrypted PKCS#8 (disabled for PKCS#1, which cannot be encrypted)
   - **Reuse existing key**: paste an unencrypted PEM key, or load one from a file, to skip key generation

4. Add **Subject Alternative Names (SANs)** — additional DNS names or IP addresses. The Common Name is automatically added as the first SAN.

5. The **Config Preview** updates live as you type. Once all required fields are valid, the **Generate Certificate Request** button appears.

6. Click **Generate Certificate Request** to generate the key and CSR and save them — along with the `.cnf`, `config.toml`, and `recreate_command.txt` — as a zip package through a native save dialog.

### Importing a Previous Configuration

Click **Import config** and select either a `config.toml` file or a previously generated zip (which contains one). The form is populated from the imported identity; export options are reset, since they are not part of the saved identity.

### Special Features

- **Wildcard Certificates**: a Common Name starting with `*.` is automatically converted for filenames (e.g. `*.example.com` becomes `wildcard.example.com.key`)
- **Debug Mode**: in debug builds, a "Fake input" button generates test data using a German locale

## License

The project is dual licensed under the Unlicense and under GNU GENERAL PUBLIC LICENSE version 3
