# AGENTS.md

This file provides guidance to AI coding agents working in this repository.

## Project Overview

This is an egui/eframe (0.35) desktop application that generates certificate signing requests (CSRs). It provides an immediate-mode GUI for creating certificate configurations, generating key pairs and CSRs natively (via `rcgen`, `rsa`, and `pkcs8` — no external OpenSSL binary is invoked), and packaging the resulting files (`.cnf`, `.key`, `.csr`, `config.toml`, `recreate_command.txt`) into a zip that the user saves through a native file dialog.

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

Binary name: `certificate-request-generator` (declared via `[[bin]]` in `Cargo.toml`; the crate/package name is `cert-egui`). The release profile enables LTO and symbol stripping.

### Checks

- `cargo fmt` / `cargo fmt --check` — formatting
- `cargo clippy --all-targets -D warnings` — lint (the project enforces this clean)
- `cargo test` — unit tests in `cert_config.rs`, `internal_gen.rs`, and `components/mod.rs`

## Architecture

### Core Modules

- **main.rs**: Entry point. Contains:
  - `CertGenApp` struct: all application state (see *State* below).
  - `setup_logger()`: initializes `env_logger` writing to a timestamped `.log` file named `{unix_timestamp}.log`. In **release** builds it logs to `dirs::data_local_dir().join("certificate-request-generator")`; in **debug** builds it logs to the current working directory. If the log file cannot be created it falls back to the default target rather than panicking.
  - `update_config_preview()` (`main.rs`): called every frame from `eframe::App::logic()`; validates input (2-letter alphabetic country code, non-empty `common_name`/`organization`/`locality`/`state`) and, when valid, regenerates `config_output` via `CertConfig::from(&*self).generate_config()`.
  - `clear_form()`: resets all form fields and output/export state.
  - `apply_config(CertConfig)`: applies an imported config to app state, resetting output and export options (export options are not part of an imported identity).
  - `fake_input()`: **debug-only**; fills the form with German-locale test data. Compiled out in release builds.
  - Window/icon setup: loads `icon.png` as the eframe window icon; viewport min size `[800, 700]`, default inner size `[800, 1100]`, title `"X.509 Certificate Request Generator"`.
  - Font loading: embeds `assets/JetBrainsMono-Regular.ttf` and installs it as the first font for `Proportional` and `Monospace` families.
  - `eframe::App` is implemented with the 0.35 split API: `logic()` (state updates) and `ui()` (rendering).

- **cert_config.rs**: Certificate identity (serializable) and sanitization:
  - `CertConfig` struct — the serializable certificate identity. Implements `From<&CertGenApp>` and `to_toml()`/`from_toml()` for round-tripping through `config.toml`.
  - `KeyAlgorithm` enum: `Rsa2048`, `Rsa3072`, `Rsa4096`, `EcdsaP256`, `EcdsaP384`, `Ed25519`. Has helpers `is_rsa()` and `has_fixed_hash()` (true for ECDSA/Ed25519, whose hash is determined by the key).
  - `CertPurpose` enum: `TlsServer`, `TlsClient`.
  - `KeyEncoding` enum (`Pem` [default], `Der`) and `RsaKeyFormat` enum (`Pkcs8` [default], `Pkcs1`) — output packaging choices.
  - `ExportOptions` struct (`encoding`, `rsa_key_format`, `passphrase: Option<String>`). **Deliberately does NOT implement `Serialize`** — it describes the current generation's packaging, not the certificate's identity; the passphrase in particular must never be persisted.
  - `generate_config()` (`cert_config.rs`): builds an OpenSSL-compatible `.cnf` string used for the live preview and included in the zip. Branches on key algorithm for `default_bits`/`default_md` (Ed25519 emits only a comment, since its digest is fixed by the key); emits `basicConstraints = critical, CA:FALSE`, `keyUsage`, `extendedKeyUsage`, and a `[alt_names]` SAN section. Not used to invoke any CLI.
  - `sanitize()` / `sanitize_for_cert_field()` (both delegate to `sanitize_internal()`): transliterate non-ASCII (German/French/Scandinavian/Polish/Czech/…) to ASCII. `sanitize()` converts spaces to hyphens and is used for filenames/CN-on-keystroke; `sanitize_for_cert_field()` preserves spaces and is used for Distinguished Name fields.

- **internal_gen.rs** (formerly `openssl_native.rs` — renamed because OpenSSL is not used): native certificate generation:
  - `GeneratedCert` struct: `{ key_bytes: Vec<u8>, csr_bytes: Vec<u8> }`. The bytes are PEM (UTF-8) or DER (binary) depending on `KeyEncoding`.
  - `generate_cert_request(config, export: &ExportOptions, existing_key_pem: Option<&str>) -> io::Result<GeneratedCert>`: builds the `DistinguishedName` (applying `sanitize_for_cert_field` to most fields), pushes SANs (IP vs DNS auto-detected), sets `key_usages` (ECDSA/Ed25519 → `digitalSignature` only; RSA server → `digitalSignature, keyEncipherment`), `extended_key_usages` (`ServerAuth`/`ClientAuth`), `is_ca = IsCa::ExplicitNoCa`, signs the CSR via `params.serialize_request(&key_pair)`, then formats the key and encodes the CSR.
  - `format_key(kp, export, key_algo)`: passphrase set → encrypted PKCS#8 (`scrypt`+`AES-256-CBC`, all key types; the passphrase always wins over a PKCS#1 request); RSA + PKCS#1 → traditional unencrypted RSA key; otherwise unencrypted PKCS#8.
  - `build_key_pair(config, existing)`: if `existing_key_pem` is `Some`, imports it (RSA via `from_pem_and_sign_algo` honoring the chosen hash; EC/Ed via `from_pem`); otherwise generates. **RSA generation goes through the standalone `rsa` crate** then loaded into rcgen via `from_pkcs8_pem_and_sign_algo`, because rcgen's default ring backend cannot generate RSA keys. ECDSA/Ed25519 are generated via `KeyPair::generate_for`.
  - `rsa_sign_algo(hash)`: maps `sha256`/`sha384`/`sha512` to the rcgen `PKCS_RSA_*` constant (default sha256).
  - Import requires `config.key_algorithm` to match the actual key type; rcgen rejects a mismatch (covered by `test_import_wrong_key_type_fails`).

- **components/**: helper modules for rendering UI sections (plain functions taking `&mut egui::Ui` and `&mut CertGenApp` — not OOP components):
  - `form.rs`: `render()` displays the input form (required fields, optional fields, key/hash/purpose selectors, the **Export Options** section, the existing-key import area, CN with live sanitization, and the SAN list). See *Key Application Flow* and *Special Handling*.
  - `execute_button.rs`: `render()` for the "Generate Certificate Request" button; polls the background `mpsc::Receiver` and, on click, calls `spawn_generation()` which moves the config + export options into a worker thread that runs `generate_cert_request()` and then `save_certificate_files_to_zip()`. Also contains `build_recreate_command(key_algorithm, name, export)` and `CertGenResult { messages }`.
  - `output.rs`: `render(ui, config_preview, command_output)` — shows the live `.cnf` **Config Preview** and the **Process Output**/error area in scrollable monospace text edits.
  - `mod.rs`: `pub mod` exports plus `save_certificate_files_to_zip(cnf, name, key: &[u8], csr: &[u8], recreate_cmd, toml_config)` and `read_config_toml(path)` (reads `config.toml` from either a plain file or a zip archive, used by Import).

### State (`CertGenApp` fields)

- Form: `country`, `state`, `locality`, `organization`, `common_name`, `sans: Vec<String>`, `current_san`.
- Optional identity: `organizational_unit`, `email`, `street_address`, `postal_code`, `key_algorithm`, `hash_algorithm` (a `String`), `cert_purpose`.
- Export options (app-only, never serialized): `key_encoding`, `rsa_key_format`, `passphrase`, `use_existing_key`, `existing_key_pem`.
- Output state: `output` (status/error messages — note the field is `output`, not `openssl_output`), `config_output` (the live `.cnf` preview), `is_executing`, `pending_cert: Option<mpsc::Receiver<CertGenResult>>`.

## Key Application Flow

1. The form is rendered by `form::render()`. Every frame `eframe::App::logic()` calls `update_config_preview()`; when all required fields are valid it populates `config_output` with the `.cnf` content via `CertConfig::generate_config()`.
2. When `config_output` is non-empty, the "Generate Certificate Request" button appears (`execute_button::render()`). Clicking it spawns a background thread (RSA-4096 is slow) that calls `generate_cert_request()` and then `save_certificate_files_to_zip()`, which builds the zip in memory (uncompressed — files are tiny) and offers it through a native **rfd save dialog** (default suggestion `{name}_certificate_files.zip`). The success message historically reads "Auto saved zip to downloads folder", but the destination is actually chosen by the user via the dialog; cancellation is reported as `ErrorKind::Interrupted` and surfaced as "Zip save cancelled."
3. The worker thread sends back a `CertGenResult { messages }` via `mpsc`; the UI polls it each frame and appends to `app.output`. The key/CSR bytes are consumed inside the thread (written into the zip there) — they are not retained in app state.
4. **Import config**: an "Import config" button opens an rfd dialog for a `.toml` or `.zip` file; `read_config_toml()` extracts the TOML text, `CertConfig::from_toml()` parses it, and `apply_config()` loads it into the form (export options are reset, not imported).

## Dependencies

From `Cargo.toml` (versions verified):

- **eframe 0.35.0** (`default-features = false`, features `glow`, `default_fonts`) — native egui app runtime.
- **egui 0.35.0** (`default-features = false`, features `default_fonts`) — immediate-mode GUI.
- **rcgen 0.14.8** (`pem`) — native CSR/certificate generation. Default backend is **ring** (this is why P-521 is unavailable — see *Intentionally Not Supported*).
- **rsa 0.9.10** (`sha2`) — RSA key generation and PKCS#1/PKCS#8 encoding.
- **pkcs8 0.10** (`encryption`, `pem`, `alloc`) — added directly to force the `encryption` feature (pulled transitively by `rsa` without it). Used for encrypted PKCS#8 export (`scrypt`+`AES-256-CBC`). **Pinned to 0.10 by `rsa` 0.9.10**; 0.11 cannot be used without upgrading `rsa`, because `RsaPrivateKey` implements the encoding traits only for pkcs8 0.10.
- **rand 0.10.2** — RNG (uses `rsa::rand_core::OsRng` for key generation/encryption).
- **zip 8.6.0** — creates the certificate file bundle (stored, no compression).
- **rfd 0.17.2** — native save/open file dialogs (zip destination, key import, config import).
- **toml 1.1.4** + **serde 1.0.228** (`derive`) — `CertConfig` (de)serialization to `config.toml`.
- **dirs 6.0.0** — used **only** to locate the local app-data directory for log files (release). It is no longer used for a downloads folder.
- **fake 5.1.0** (`url`, `http`) — debug-only test data (German locale).
- **log 0.4.33** & **env_logger 0.11.11** — logging.
- **time 0.3.54** (`local-offset`, `formatting`, `macros`) — log timestamps.
- **winresource 0.1.27** (build-dependency) — embeds `icon.ico` as the Windows executable resource (see `build.rs`).

## Special Handling

- **Wildcard certificates**: a CN starting with `*.` is converted to `wildcard.` for filenames (e.g. `*.example.com` → `wildcard.example.com.key`), handled in `execute_button.rs` (`spawn_generation`) and in `cert_config.rs` (`generate_config`).
- **CN sanitization**: `sanitize()` is applied to the CN field on every keystroke (`form.rs`), rewriting the buffer in place and fixing the cursor position; the CN is also kept mirrored as the first SAN (badge `(from CN)`, not removable while present).
- **Special characters**: `sanitize_for_cert_field()` converts umlauts and accented characters to ASCII while preserving spaces, applied when building Distinguished Name fields (state, locality, organization, OU, street).
- **SAN validation & auto-detection**: `is_valid_san()` validates DNS labels (incl. optional leading `*.` wildcard) and IP addresses; entries are classified and badged `DNS`/`IP`/`INVALID`. Adding an already-present SAN is blocked with a yellow "SAN already exists" label.
- **Export Options** (form.rs, under "Optional Values"): Key Encoding (PEM/DER); RSA-only Key Format (PKCS#8/PKCS#1 — switching to PKCS#1 clears the passphrase); Passphrase field (`.password(true)`, disabled for RSA+PKCS#1 with a "PKCS#1 cannot be encrypted" hint). Passphrase enables encrypted PKCS#8 export for **all** key types.
- **Reuse existing key**: a checkbox reveals a multiline PEM paste area plus a "Load from file…" button; yellow warnings appear for non-PEM content or encrypted keys (encrypted keys cannot be imported — they must be decrypted first).
- **Hash algorithm selector**: shown only for RSA (ECDSA/Ed25519 hashes are fixed by the curve/key).
- **Background generation**: key/CSR generation runs on a separate thread; the UI polls `mpsc` and shows "Processing..." while `is_executing`.
- **Debug mode**: a "Fake input" button (debug builds only) populates the form with German-locale fake data.
- **Logging**: operations are logged; release logs go to local app-data, debug logs to the CWD.

## Configuration Files & Assets

- **Cargo.toml**: crate name `cert-egui`; binary `certificate-request-generator`; `edition = "2024"`; release profile enables LTO + `strip`.
- **build.rs**: on Windows, compiles `icon.ico` into the executable via `winresource` (no-op on other platforms).
- **Assets**: `assets/JetBrainsMono-Regular.ttf` (embedded font, via `include_bytes!`); `icon.png` (runtime window icon); `icon.ico` (Windows executable icon).

## Intentionally Not Supported

- **No Certificate Authority (CA) support.** Generates CSRs only — never signs/issues certificates. `is_ca = IsCa::ExplicitNoCa` and `basicConstraints = critical, CA:FALSE` are always set.
- **No copy-to-clipboard for key/CSR.** Output is written exclusively into the zip package, to prevent key/CSR mismatches or lost keys.
- **No ECDSA P-521.** rcgen's default ring backend exposes P-521 sign algorithms only behind the `aws_lc_rs` feature (heavy native build deps on Windows); the project intentionally stays on ring.

## UI Framework Notes

This application uses **egui**, an immediate-mode GUI framework:

- No separate component lifecycle — the UI is re-rendered every frame from current state.
- All state lives in the `CertGenApp` struct.
- `components/*` modules are plain render functions taking `&mut egui::Ui` and `&mut CertGenApp`.
- No CSS/styling files — all styling is programmatic via the egui API.
