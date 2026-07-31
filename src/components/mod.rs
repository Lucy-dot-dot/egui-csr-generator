use std::fs;
use std::io::{Read, Write, Cursor};
use zip::{ZipWriter, ZipArchive, write::SimpleFileOptions};
use rfd::FileDialog;

pub mod form;
pub mod output;
pub mod execute_button;

/// The generated zip file does not use compression, the files are not even 5kb big.
pub fn save_certificate_files_to_zip(cnf: &str, name: &str, key: &str, csr: &str, recreate_cmd: &str, toml_config: &str) -> std::io::Result<()> {
    log::debug!("Generating and saving files to zip");
    log::debug!("Contents: \n{name}.cnf = {cnf}\n\n{name}.key = {key}\n\n{name}.csr = {csr}\n\ncommand: {recreate_cmd}\n\nconfig.toml = {toml_config}");
    // Create zip file in memory
    let mut zip_buffer = Cursor::new(Vec::new());
    let mut zip = ZipWriter::new(&mut zip_buffer);
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);

    // Add files to zip
    zip.start_file(format!("{}.cnf", name), options)?;
    zip.write_all(cnf.as_bytes())?;

    zip.start_file(format!("{}.key", name), options)?;
    zip.write_all(key.as_bytes())?;

    zip.start_file(format!("{}.csr", name), options)?;
    zip.write_all(csr.as_bytes())?;

    zip.start_file("config.toml", options)?;
    zip.write_all(toml_config.as_bytes())?;

    zip.start_file("recreate_command.txt", options)?;
    zip.write_all(recreate_cmd.as_bytes())?;

    // Finalize the zip
    zip.finish()?;

    // Get the zip data
    let zip_data = zip_buffer.into_inner();

    let default_name = format!("{}_certificate_files.zip", name);

    if let Some(target_path) = FileDialog::new()
        .set_file_name(&default_name)
        .add_filter("ZIP Archive", &["zip"])
        .save_file()
    {
        log::info!("Writing zip to {}", target_path.display());
        fs::write(target_path, zip_data)?;
        Ok(())
    } else {
        log::info!("User cancelled the save dialog");
        // Return an interrupted error so the UI knows it wasn't a real failure
        Err(std::io::Error::new(std::io::ErrorKind::Interrupted, "Save cancelled by user"))
    }
}

/// Reads `config.toml` out of either a zip archive (any `.zip` file containing a
/// `config.toml` entry) or a plain `config.toml` file. Returns the raw TOML text.
///
/// Detection is based on the file extension: `.zip` is treated as an archive,
/// everything else is read verbatim as a TOML file.
pub fn read_config_toml(path: &std::path::Path) -> std::io::Result<String> {
    let is_zip = path.extension()
        .map(|ext| ext.eq_ignore_ascii_case("zip"))
        .unwrap_or(false);

    if is_zip {
        log::debug!("Reading config.toml from zip archive at {}", path.display());
        let file = fs::File::open(path)?;
        let mut archive = ZipArchive::new(file)
            .map_err(|e| std::io::Error::other(format!("Failed to read zip archive: {}", e)))?;

        for i in 0..archive.len() {
            let mut entry = archive.by_index(i)
                .map_err(|e| std::io::Error::other(format!("Failed to read zip entry: {}", e)))?;
            // Match "config.toml" regardless of any contained directory prefix
            let name_matches = entry.name().eq_ignore_ascii_case("config.toml")
                || entry.name().ends_with("/config.toml");
            if name_matches {
                let mut content = String::new();
                entry.read_to_string(&mut content)?;
                log::debug!("Found config.toml ({} bytes) in zip entry {}", content.len(), i);
                return Ok(content);
            }
        }
        Err(std::io::Error::new(std::io::ErrorKind::NotFound, "No config.toml found inside the zip archive"))
    } else {
        log::debug!("Reading config.toml directly from {}", path.display());
        fs::read_to_string(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Write, Cursor};
    use zip::{ZipWriter, write::SimpleFileOptions};

    fn sample_toml() -> &'static str {
        r#"country = "DE"
state = "Nordrhein-Westfalen"
locality = "Muenster"
organization = "Test GmbH"
common_name = "mail.example.com"
san = ["mail.example.com", "www.example.com"]
key_algorithm = "EcdsaP384"
hash_algorithm = "sha384"
cert_purpose = "TlsClient"
"#
    }

    #[test]
    fn test_read_config_toml_from_plain_file() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("cert_test_{}.toml", std::process::id()));
        std::fs::write(&path, sample_toml()).unwrap();

        let content = read_config_toml(&path).expect("reading plain toml should succeed");
        assert!(content.contains("common_name = \"mail.example.com\""));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_read_config_toml_from_zip() {
        let mut buffer = Cursor::new(Vec::new());
        {
            let mut zip = ZipWriter::new(&mut buffer);
            let options = SimpleFileOptions::default();
            zip.start_file("config.toml", options).unwrap();
            zip.write_all(sample_toml().as_bytes()).unwrap();
            // also add a decoy file to ensure we locate config.toml among entries
            zip.start_file("readme.txt", options).unwrap();
            zip.write_all(b"ignore me").unwrap();
            zip.finish().unwrap();
        }

        let dir = std::env::temp_dir();
        let path = dir.join(format!("cert_test_{}.zip", std::process::id()));
        std::fs::write(&path, buffer.into_inner()).unwrap();

        let content = read_config_toml(&path).expect("reading config from zip should succeed");
        assert!(content.contains("cert_purpose = \"TlsClient\""));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_read_config_toml_zip_without_config_returns_error() {
        let mut buffer = Cursor::new(Vec::new());
        {
            let mut zip = ZipWriter::new(&mut buffer);
            let options = SimpleFileOptions::default();
            zip.start_file("other.txt", options).unwrap();
            zip.write_all(b"no config here").unwrap();
            zip.finish().unwrap();
        }

        let dir = std::env::temp_dir();
        let path = dir.join(format!("cert_test_empty_{}.zip", std::process::id()));
        std::fs::write(&path, buffer.into_inner()).unwrap();

        let result = read_config_toml(&path);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::NotFound);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_roundtrip_export_then_import_via_zip() {
        use crate::cert_config::CertConfig;
        let original = CertConfig {
            country: "US".to_string(),
            state: "California".to_string(),
            locality: "San Francisco".to_string(),
            organization: "Acme Corp".to_string(),
            organizational_unit: Some("Eng".to_string()),
            email: None,
            street_address: None,
            postal_code: Some("94105".to_string()),
            common_name: "acme.test".to_string(),
            san: vec!["acme.test".to_string()],
            key_algorithm: crate::cert_config::KeyAlgorithm::Rsa2048,
            hash_algorithm: "sha256".to_string(),
            cert_purpose: crate::cert_config::CertPurpose::TlsServer,
        };

        let toml_text = original.to_toml().unwrap();

        // Write that toml into a zip the same way the app does
        let mut buffer = Cursor::new(Vec::new());
        {
            let mut zip = ZipWriter::new(&mut buffer);
            let options = SimpleFileOptions::default();
            zip.start_file("config.toml", options).unwrap();
            zip.write_all(toml_text.as_bytes()).unwrap();
            zip.finish().unwrap();
        }
        let dir = std::env::temp_dir();
        let path = dir.join(format!("cert_test_roundtrip_{}.zip", std::process::id()));
        std::fs::write(&path, buffer.into_inner()).unwrap();

        let read_toml = read_config_toml(&path).unwrap();
        let restored = CertConfig::from_toml(&read_toml).unwrap();
        assert_eq!(original, restored);

        let _ = std::fs::remove_file(&path);
    }
}

