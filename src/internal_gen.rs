use crate::cert_config::{
    CertConfig, CertPurpose, ExportOptions, KeyAlgorithm, KeyEncoding, RsaKeyFormat,
    sanitize_for_cert_field,
};
use pkcs8::der::pem::PemLabel;
use pkcs8::{
    DecodePrivateKey, EncodePrivateKey, EncryptedPrivateKeyInfo, LineEnding, PrivateKeyInfo,
};
use rcgen::{CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, SanType};
use rcgen::{ExtendedKeyUsagePurpose, KeyUsagePurpose, SignatureAlgorithm};
use rcgen::{PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, PKCS_ED25519};
use rcgen::{PKCS_RSA_SHA256, PKCS_RSA_SHA384, PKCS_RSA_SHA512};
use rsa::RsaPrivateKey;
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::rand_core::OsRng;
use std::io;

/// The generated output: key and CSR as raw bytes.
///
/// The bytes are PEM text (UTF-8) or DER (binary) depending on the requested
/// [`KeyEncoding`]. Callers that need to display them should interpret
/// accordingly.
pub struct GeneratedCert {
    pub key_bytes: Vec<u8>,
    pub csr_bytes: Vec<u8>,
}

/// Picks the rcgen RSA signature algorithm for the chosen hash.
fn rsa_sign_algo(hash: &str) -> &'static SignatureAlgorithm {
    match hash {
        "sha384" => &PKCS_RSA_SHA384,
        "sha512" => &PKCS_RSA_SHA512,
        _ => &PKCS_RSA_SHA256,
    }
}

/// Formats the private key bytes according to the export options.
///
/// - Passphrase set  → encrypted PKCS#8 (scrypt + AES-256-CBC), all key types.
/// - RSA + PKCS#1    → traditional unencrypted RSA key.
/// - Otherwise       → unencrypted PKCS#8.
fn format_key(
    kp: &KeyPair,
    export: &ExportOptions,
    key_algo: &KeyAlgorithm,
) -> io::Result<Vec<u8>> {
    let want_pem = export.encoding == KeyEncoding::Pem;
    let pass = export.passphrase.as_deref().filter(|p| !p.is_empty());

    if let Some(password) = pass {
        // Encrypted PKCS#8 path. PKCS#1 has no standard passphrase container
        // here, so the passphrase always wins over a PKCS#1 request (the UI
        // prevents that combination anyway).
        let der = kp.serialize_der();
        let pki = PrivateKeyInfo::try_from(der.as_slice())
            .map_err(|e| io::Error::other(format!("Failed to parse PKCS#8 key: {}", e)))?;
        let doc = pki
            .encrypt(&mut OsRng, password)
            .map_err(|e| io::Error::other(format!("Failed to encrypt private key: {}", e)))?;
        if want_pem {
            let pem = doc
                .to_pem(EncryptedPrivateKeyInfo::PEM_LABEL, LineEnding::LF)
                .map_err(|e| {
                    io::Error::other(format!("Failed to PEM-encode encrypted key: {}", e))
                })?;
            Ok(pem.as_bytes().to_vec())
        } else {
            Ok(doc.as_bytes().to_vec())
        }
    } else if key_algo.is_rsa() && export.rsa_key_format == RsaKeyFormat::Pkcs1 {
        // Traditional RSA PKCS#1 (unencrypted only).
        let der = kp.serialize_der();
        let rsa_key = RsaPrivateKey::from_pkcs8_der(&der)
            .map_err(|e| io::Error::other(format!("Failed to reconstruct RSA key: {}", e)))?;
        if want_pem {
            let pem = rsa_key
                .to_pkcs1_pem(LineEnding::LF)
                .map_err(|e| io::Error::other(format!("Failed to encode PKCS#1 PEM: {}", e)))?;
            Ok(pem.as_bytes().to_vec())
        } else {
            Ok(rsa_key
                .to_pkcs1_der()
                .map_err(|e| io::Error::other(format!("Failed to encode PKCS#1 DER: {}", e)))?
                .as_bytes()
                .to_vec())
        }
    } else {
        // Unencrypted PKCS#8.
        if want_pem {
            Ok(kp.serialize_pem().into_bytes())
        } else {
            Ok(kp.serialize_der())
        }
    }
}

/// Generates the certificate request based on the provided configuration.
///
/// `existing_key_pem` — when `Some`, an unencrypted PKCS#8 PEM private key is
/// imported and reused instead of generating a fresh key. Its type must match
/// `config.key_algorithm` (RSA imports also honor `config.hash_algorithm` for
/// the CSR signature). Sanitization is applied to most DN fields.
pub fn generate_cert_request(
    config: &CertConfig,
    export: &ExportOptions,
    existing_key_pem: Option<&str>,
) -> io::Result<GeneratedCert> {
    let key_pair = build_key_pair(config, existing_key_pem)?;

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CountryName, &config.country);
    dn.push(
        DnType::StateOrProvinceName,
        sanitize_for_cert_field(&config.state),
    );
    dn.push(
        DnType::LocalityName,
        sanitize_for_cert_field(&config.locality),
    );
    dn.push(
        DnType::OrganizationName,
        sanitize_for_cert_field(&config.organization),
    );

    if let Some(street) = &config.street_address
        && !street.trim().is_empty()
    {
        dn.push(
            DnType::CustomDnType(vec![2, 5, 4, 9]),
            sanitize_for_cert_field(street),
        );
    }

    if let Some(postal) = &config.postal_code
        && !postal.trim().is_empty()
    {
        dn.push(DnType::CustomDnType(vec![2, 5, 4, 17]), postal.as_str());
    }

    if let Some(ou) = &config.organizational_unit
        && !ou.trim().is_empty()
    {
        dn.push(DnType::OrganizationalUnitName, sanitize_for_cert_field(ou));
    }

    dn.push(DnType::CommonName, &config.common_name);

    if let Some(email) = &config.email
        && !email.trim().is_empty()
    {
        dn.push(
            DnType::CustomDnType(vec![1, 2, 840, 113549, 1, 9, 1]),
            email.as_str(),
        );
    }

    let mut params = CertificateParams::default();
    params.distinguished_name = dn;

    for san in config.san.iter() {
        if let Ok(ip) = san.parse::<std::net::IpAddr>() {
            params.subject_alt_names.push(SanType::IpAddress(ip));
        } else {
            let parsed_san = san
                .parse()
                .map_err(|e| io::Error::other(format!("SAN parsing failed: {}", e)))?;
            params.subject_alt_names.push(SanType::DnsName(parsed_san));
        }
    }

    // ECDSA and Ed25519 can only perform digital signatures; RSA additionally
    // supports key encipherment (needed for TLS server key exchange in
    // non-(EC)DHE cipher suites).
    params.key_usages = if config.key_algorithm.has_fixed_hash() {
        vec![KeyUsagePurpose::DigitalSignature]
    } else if config.cert_purpose == CertPurpose::TlsServer {
        vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ]
    } else {
        vec![KeyUsagePurpose::DigitalSignature]
    };

    params.extended_key_usages = match &config.cert_purpose {
        CertPurpose::TlsServer => vec![ExtendedKeyUsagePurpose::ServerAuth],
        CertPurpose::TlsClient => vec![ExtendedKeyUsagePurpose::ClientAuth],
    };

    // We don't generate CA certificates in this application
    params.is_ca = IsCa::ExplicitNoCa;

    log::debug!("Using params: {:?}", params);

    log::debug!("Generating CSR");
    let cert = params
        .serialize_request(&key_pair)
        .map_err(|e| io::Error::other(format!("Certificate creation failed: {}", e)))?;

    let key_bytes = format_key(&key_pair, export, &config.key_algorithm)?;

    let csr_bytes = if export.encoding == KeyEncoding::Pem {
        log::debug!("Converting CSR to PEM format");
        cert.pem()
            .map_err(|e| io::Error::other(format!("CSR PEM export failed: {}", e)))?
            .into_bytes()
    } else {
        log::debug!("Exporting CSR as DER");
        cert.der().as_ref().to_vec()
    };

    let encrypted = export.passphrase.as_deref().is_some_and(|p| !p.is_empty());
    log::info!(
        "Generated certificate request for {} with {} SANs (encoding={:?}, encrypted={})",
        config.common_name,
        config.san.len(),
        export.encoding,
        encrypted
    );

    Ok(GeneratedCert {
        key_bytes,
        csr_bytes,
    })
}

/// Creates the rcgen [`KeyPair`], either by importing an existing PEM key or by
/// generating a new one. RSA generation goes through the standalone `rsa`
/// crate because rcgen's ring backend cannot generate RSA keys.
fn build_key_pair(config: &CertConfig, existing_key_pem: Option<&str>) -> io::Result<KeyPair> {
    if let Some(pem) = existing_key_pem {
        log::debug!("Importing existing key (type={:?})", config.key_algorithm);
        return match &config.key_algorithm {
            KeyAlgorithm::Rsa2048 | KeyAlgorithm::Rsa3072 | KeyAlgorithm::Rsa4096 => {
                let sign_algo = rsa_sign_algo(&config.hash_algorithm);
                KeyPair::from_pem_and_sign_algo(pem, sign_algo)
                    .map_err(|e| io::Error::other(format!("Failed to import RSA key: {}", e)))
            }
            KeyAlgorithm::EcdsaP256 | KeyAlgorithm::EcdsaP384 | KeyAlgorithm::Ed25519 => {
                KeyPair::from_pem(pem)
                    .map_err(|e| io::Error::other(format!("Failed to import key: {}", e)))
            }
        };
    }

    match &config.key_algorithm {
        KeyAlgorithm::Rsa2048 | KeyAlgorithm::Rsa3072 | KeyAlgorithm::Rsa4096 => {
            let bits = match &config.key_algorithm {
                KeyAlgorithm::Rsa2048 => 2048,
                KeyAlgorithm::Rsa3072 => 3072,
                KeyAlgorithm::Rsa4096 => 4096,
                _ => unreachable!(),
            };
            log::debug!("Generating RSA {} key", bits);
            let private_key = RsaPrivateKey::new(&mut OsRng, bits)
                .map_err(|e| io::Error::other(format!("RSA key generation failed: {}", e)))?;
            let pem = private_key
                .to_pkcs8_pem(LineEnding::LF)
                .map_err(|e| io::Error::other(format!("Key PEM export failed: {}", e)))?;
            let sign_algo = rsa_sign_algo(&config.hash_algorithm);
            log::debug!("Using hash algorithm {}", config.hash_algorithm);
            KeyPair::from_pkcs8_pem_and_sign_algo(pem.as_str(), sign_algo)
                .map_err(|e| io::Error::other(format!("Key pair creation failed: {}", e)))
        }
        KeyAlgorithm::EcdsaP256 => {
            log::debug!("Generating ECDSA P-256 key");
            KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
                .map_err(|e| io::Error::other(format!("ECDSA P-256 key generation failed: {}", e)))
        }
        KeyAlgorithm::EcdsaP384 => {
            log::debug!("Generating ECDSA P-384 key");
            KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384)
                .map_err(|e| io::Error::other(format!("ECDSA P-384 key generation failed: {}", e)))
        }
        KeyAlgorithm::Ed25519 => {
            log::debug!("Generating Ed25519 key");
            KeyPair::generate_for(&PKCS_ED25519)
                .map_err(|e| io::Error::other(format!("Ed25519 key generation failed: {}", e)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(san: Vec<String>) -> CertConfig {
        CertConfig {
            country: "DE".to_string(),
            state: "Nordrhein-Westfalen".to_string(),
            locality: "Muenster".to_string(),
            organization: "Test GmbH".to_string(),
            organizational_unit: None,
            email: None,
            street_address: None,
            postal_code: None,
            common_name: "test.example.com".to_string(),
            san,
            key_algorithm: KeyAlgorithm::Rsa2048,
            hash_algorithm: "sha256".to_string(),
            cert_purpose: CertPurpose::TlsServer,
        }
    }

    #[test]
    fn test_basic_generation_produces_valid_pem() {
        let config = test_config(vec!["test.example.com".to_string()]);
        let result = generate_cert_request(&config, &ExportOptions::default(), None).unwrap();
        let key = String::from_utf8_lossy(&result.key_bytes);
        let csr = String::from_utf8_lossy(&result.csr_bytes);
        assert!(key.contains("BEGIN PRIVATE KEY"));
        assert!(key.contains("END PRIVATE KEY"));
        assert!(csr.contains("BEGIN CERTIFICATE REQUEST"));
        assert!(csr.contains("END CERTIFICATE REQUEST"));
    }

    #[test]
    fn test_multiple_dns_sans() {
        let config = test_config(vec![
            "example.com".to_string(),
            "www.example.com".to_string(),
            "mail.example.com".to_string(),
        ]);
        assert!(generate_cert_request(&config, &ExportOptions::default(), None).is_ok());
    }

    #[test]
    fn test_ip_san() {
        let config = test_config(vec!["example.com".to_string(), "192.168.1.1".to_string()]);
        assert!(generate_cert_request(&config, &ExportOptions::default(), None).is_ok());
    }

    #[test]
    fn test_no_sans() {
        let config = test_config(vec![]);
        assert!(generate_cert_request(&config, &ExportOptions::default(), None).is_ok());
    }

    #[test]
    fn test_wildcard_cn() {
        let config = CertConfig {
            common_name: "*.example.com".to_string(),
            san: vec!["*.example.com".to_string()],
            ..test_config(vec![])
        };
        assert!(generate_cert_request(&config, &ExportOptions::default(), None).is_ok());
    }

    #[test]
    fn test_sha384() {
        let config = CertConfig {
            hash_algorithm: "sha384".to_string(),
            ..test_config(vec!["test.example.com".to_string()])
        };
        assert!(generate_cert_request(&config, &ExportOptions::default(), None).is_ok());
    }

    #[test]
    fn test_sha512() {
        let config = CertConfig {
            hash_algorithm: "sha512".to_string(),
            ..test_config(vec!["test.example.com".to_string()])
        };
        assert!(generate_cert_request(&config, &ExportOptions::default(), None).is_ok());
    }

    #[test]
    fn test_unknown_hash_algorithm_falls_back_to_sha256() {
        let config = CertConfig {
            hash_algorithm: "md5".to_string(),
            ..test_config(vec!["test.example.com".to_string()])
        };
        assert!(generate_cert_request(&config, &ExportOptions::default(), None).is_ok());
    }

    #[test]
    fn test_all_optional_dn_fields() {
        let config = CertConfig {
            country: "DE".to_string(),
            state: "Hessen".to_string(),
            locality: "Frankfurt".to_string(),
            organization: "Test AG".to_string(),
            organizational_unit: Some("IT Abteilung".to_string()),
            email: Some("admin@example.de".to_string()),
            street_address: Some("Hauptstrasse 1".to_string()),
            postal_code: Some("60313".to_string()),
            common_name: "corp.example.de".to_string(),
            san: vec!["corp.example.de".to_string()],
            key_algorithm: KeyAlgorithm::Rsa2048,
            hash_algorithm: "sha256".to_string(),
            cert_purpose: CertPurpose::TlsServer,
        };
        assert!(generate_cert_request(&config, &ExportOptions::default(), None).is_ok());
    }

    #[test]
    fn test_empty_optional_fields_are_skipped() {
        let config = CertConfig {
            organizational_unit: Some("".to_string()),
            email: Some("   ".to_string()),
            street_address: Some("".to_string()),
            postal_code: Some("".to_string()),
            ..test_config(vec!["test.example.com".to_string()])
        };
        assert!(generate_cert_request(&config, &ExportOptions::default(), None).is_ok());
    }

    #[test]
    fn test_german_characters_in_fields() {
        let config = CertConfig {
            state: "Thüringen".to_string(),
            locality: "Mühlhausen".to_string(),
            organization: "Bäckerei Müller & Söhne GmbH".to_string(),
            ..test_config(vec!["test.example.de".to_string()])
        };
        assert!(generate_cert_request(&config, &ExportOptions::default(), None).is_ok());
    }

    #[test]
    fn test_tls_client_cert() {
        let config = CertConfig {
            cert_purpose: CertPurpose::TlsClient,
            ..test_config(vec!["test.example.com".to_string()])
        };
        assert!(generate_cert_request(&config, &ExportOptions::default(), None).is_ok());
    }

    #[test]
    fn test_ecdsa_p256() {
        let config = CertConfig {
            key_algorithm: KeyAlgorithm::EcdsaP256,
            ..test_config(vec!["test.example.com".to_string()])
        };
        let result = generate_cert_request(&config, &ExportOptions::default(), None).unwrap();
        let key = String::from_utf8_lossy(&result.key_bytes);
        let csr = String::from_utf8_lossy(&result.csr_bytes);
        assert!(key.contains("BEGIN PRIVATE KEY"));
        assert!(csr.contains("BEGIN CERTIFICATE REQUEST"));
    }

    #[test]
    fn test_ecdsa_p384() {
        let config = CertConfig {
            key_algorithm: KeyAlgorithm::EcdsaP384,
            ..test_config(vec!["test.example.com".to_string()])
        };
        assert!(generate_cert_request(&config, &ExportOptions::default(), None).is_ok());
    }

    #[test]
    fn test_rsa_3072() {
        let config = CertConfig {
            key_algorithm: KeyAlgorithm::Rsa3072,
            ..test_config(vec!["test.example.com".to_string()])
        };
        assert!(generate_cert_request(&config, &ExportOptions::default(), None).is_ok());
    }

    #[test]
    fn test_rsa_4096() {
        let config = CertConfig {
            key_algorithm: KeyAlgorithm::Rsa4096,
            ..test_config(vec!["test.example.com".to_string()])
        };
        assert!(generate_cert_request(&config, &ExportOptions::default(), None).is_ok());
    }

    #[test]
    fn test_ed25519() {
        let config = CertConfig {
            key_algorithm: KeyAlgorithm::Ed25519,
            ..test_config(vec!["test.example.com".to_string()])
        };
        let result = generate_cert_request(&config, &ExportOptions::default(), None).unwrap();
        let key = String::from_utf8_lossy(&result.key_bytes);
        let csr = String::from_utf8_lossy(&result.csr_bytes);
        assert!(key.contains("BEGIN PRIVATE KEY"));
        assert!(csr.contains("BEGIN CERTIFICATE REQUEST"));
    }

    #[test]
    fn test_der_encoding() {
        let config = test_config(vec!["test.example.com".to_string()]);
        let export = ExportOptions {
            encoding: KeyEncoding::Der,
            ..ExportOptions::default()
        };
        let result = generate_cert_request(&config, &export, None).unwrap();
        // DER CSR starts with a SEQUENCE tag (0x30).
        assert_eq!(&result.csr_bytes[0..1], &[0x30]);
        // DER output must not contain PEM text.
        assert!(
            String::from_utf8_lossy(&result.key_bytes)
                .lines()
                .all(|l| !l.contains("BEGIN"))
        );
    }

    #[test]
    fn test_encrypted_key_export() {
        let config = test_config(vec!["test.example.com".to_string()]);
        let export = ExportOptions {
            passphrase: Some("correct horse battery staple".to_string()),
            ..ExportOptions::default()
        };
        let result = generate_cert_request(&config, &export, None).unwrap();
        let key = String::from_utf8_lossy(&result.key_bytes);
        assert!(key.contains("BEGIN ENCRYPTED PRIVATE KEY"));
        assert!(key.contains("END ENCRYPTED PRIVATE KEY"));
        // A plain (unencrypted) private key must not leak.
        assert!(!key.contains("BEGIN PRIVATE KEY") || key.contains("ENCRYPTED"));
    }

    #[test]
    fn test_encrypted_key_export_ecdsa() {
        let config = CertConfig {
            key_algorithm: KeyAlgorithm::EcdsaP256,
            ..test_config(vec!["test.example.com".to_string()])
        };
        let export = ExportOptions {
            passphrase: Some("s3cret".to_string()),
            ..ExportOptions::default()
        };
        let result = generate_cert_request(&config, &export, None).unwrap();
        let key = String::from_utf8_lossy(&result.key_bytes);
        assert!(key.contains("BEGIN ENCRYPTED PRIVATE KEY"));
    }

    #[test]
    fn test_pkcs1_rsa_export() {
        let config = test_config(vec!["test.example.com".to_string()]);
        let export = ExportOptions {
            rsa_key_format: RsaKeyFormat::Pkcs1,
            ..ExportOptions::default()
        };
        let result = generate_cert_request(&config, &export, None).unwrap();
        let key = String::from_utf8_lossy(&result.key_bytes);
        assert!(key.contains("BEGIN RSA PRIVATE KEY"));
    }

    #[test]
    fn test_pkcs1_rsa_der_export() {
        let config = test_config(vec!["test.example.com".to_string()]);
        let export = ExportOptions {
            encoding: KeyEncoding::Der,
            rsa_key_format: RsaKeyFormat::Pkcs1,
            ..ExportOptions::default()
        };
        let result = generate_cert_request(&config, &export, None).unwrap();
        // PKCS#1 DER RSA key starts with a SEQUENCE tag too.
        assert_eq!(&result.key_bytes[0..1], &[0x30]);
    }

    #[test]
    fn test_import_existing_rsa_key() {
        // Generate a key, then re-run importing it (no new keygen).
        let config = test_config(vec!["test.example.com".to_string()]);
        let first = generate_cert_request(&config, &ExportOptions::default(), None).unwrap();
        let pem = String::from_utf8(first.key_bytes).unwrap();

        let second = generate_cert_request(&config, &ExportOptions::default(), Some(&pem)).unwrap();
        // The imported key round-trips as the same PKCS#8 PEM (same private key).
        assert_eq!(pem, String::from_utf8(second.key_bytes).unwrap());
    }

    #[test]
    fn test_import_existing_ed25519_key() {
        let config = CertConfig {
            key_algorithm: KeyAlgorithm::Ed25519,
            ..test_config(vec!["test.example.com".to_string()])
        };
        let first = generate_cert_request(&config, &ExportOptions::default(), None).unwrap();
        let pem = String::from_utf8(first.key_bytes).unwrap();
        // Re-importing must succeed and yield the same key bytes.
        let second = generate_cert_request(&config, &ExportOptions::default(), Some(&pem)).unwrap();
        assert_eq!(pem, String::from_utf8(second.key_bytes).unwrap());
    }

    #[test]
    fn test_import_wrong_key_type_fails() {
        // Import an Ed25519 key while claiming it is RSA → must error.
        let ed_config = CertConfig {
            key_algorithm: KeyAlgorithm::Ed25519,
            ..test_config(vec!["test.example.com".to_string()])
        };
        let ed_pem = String::from_utf8(
            generate_cert_request(&ed_config, &ExportOptions::default(), None)
                .unwrap()
                .key_bytes,
        )
        .unwrap();

        let rsa_config = test_config(vec!["test.example.com".to_string()]);
        assert!(
            generate_cert_request(&rsa_config, &ExportOptions::default(), Some(&ed_pem)).is_err()
        );
    }
}
