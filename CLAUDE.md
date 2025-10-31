# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Dioxus desktop application that generates OpenSSL certificate signing requests (CSRs). It provides a GUI for creating certificate configurations, executing OpenSSL commands, and saving certificate files as a zip package to the downloads folder.

## Build and Development Commands

### Running the Application

```bash
dx serve --platform desktop
```

This starts the Dioxus development server and launches the desktop application.

### Building for Release

```bash
cargo build --release
```

### Optional: Tailwind CSS Development

If working with Tailwind CSS styling:

```bash
npx tailwindcss -i ./input.css -o ./assets/tailwind.css --watch
```

## Architecture

### Core Modules

- **main.rs**: Entry point and main App component. Contains the UI layout, form state management (country, state, locality, organization, common name, SANs), and primary event handlers (`generate` for config creation, `fake_input` for test data in debug mode).

- **openssl_cert_tools.rs**: Core certificate logic module containing:
  - `CertConfig` struct: Holds certificate metadata and generates OpenSSL configuration files
  - `generate_config()`: Creates properly formatted OpenSSL .cnf files with support for SANs (DNS/IP detection)
  - `execute_openssl_command()`: Wrapper for executing OpenSSL CLI commands via `std::process::Command`
  - `sanitize()`: Handles German umlauts (ä, ü, ö) in certificate fields

- **components/**: Reusable UI components built with Dioxus
  - `form.rs`: Main input form for certificate details
  - `execute_button.rs`: Handles OpenSSL command execution flow - creates temp config file, runs `openssl req -new`, reads generated .key/.csr files, auto-saves zip, cleans up temp files
  - `save_button.rs`: Manual save functionality for certificate files
  - `openssloutput.rs`: Display area for OpenSSL command output
  - `mod.rs`: Module exports and contains `generate_and_save()` function that creates a zip file with .cnf, .key, .csr, and a recreate_command.txt file

### Key Application Flow

1. User fills in certificate details through the Form component
2. Clicking "Generate Configuration" validates input (especially 2-char country code) and creates OpenSSL config string
3. "Execute OpenSSL Command" button writes temp config file, executes `openssl req -new`, captures output, reads generated key/csr files, auto-saves zip to downloads folder, then cleans up temp files
4. Optional "Save Certificate Files" button allows manual re-saving if needed
5. All output appears in the OpenSSLOutput component

### Dependencies

- **dioxus 0.6.3**: Desktop UI framework
- **fake**: Generates test data (German locale) - only used in debug mode
- **zip**: Creates compressed certificate file bundles
- **dirs**: Locates user's downloads directory

### Special Handling

- **Wildcard certificates**: CN starting with `*.` is converted to `wildcard.` for filenames (e.g., `*.example.com` becomes `wildcard.example.com.key`)
- **German characters**: Umlauts are sanitized to ASCII equivalents (ä→ae, ü→ue, ö→oe)
- **SAN auto-detection**: Automatically distinguishes between DNS names and IP addresses in Subject Alternative Names
- **Debug mode**: Includes a "Fake input" button using German locale fake data for testing

### Configuration Files

- **Cargo.toml**: Defines features for different platforms (desktop, web, mobile). Default feature is desktop.
- **Dioxus.toml**: Dioxus-specific configuration including bundle identifier and publisher info
- **Assets**: Located in `/assets/` directory, includes CSS files and fonts (JetBrains Mono font is loaded dynamically)