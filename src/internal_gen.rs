use std::io;
use rsa::RsaPrivateKey;
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use rcgen::{CertificateParams, DistinguishedName, DnType, SanType, KeyPair, IsCa};
use rcgen::{PKCS_RSA_SHA256, PKCS_RSA_SHA384, PKCS_RSA_SHA512};
use rcgen::{PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384};
use rcgen::{KeyUsagePurpose, ExtendedKeyUsagePurpose};
use rsa::rand_core::OsRng;
use crate::cert_config::{CertConfig, KeyAlgorithm, CertPurpose, sanitize_for_cert_field};

pub struct GeneratedCert {
    pub key_pem: String,
    pub csr_pem: String,
}

/// Generates the certificate request based on the provided configuration, sanitization is provided for most fields
pub fn generate_cert_request(config: &CertConfig) -> io::Result<GeneratedCert> {
    let (key_pair, key_pem) = match &config.key_algorithm {
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
            let pem = private_key.to_pkcs8_pem(LineEnding::LF)
                .map_err(|e| io::Error::other(format!("Key PEM export failed: {}", e)))?;
            let sign_algo = match config.hash_algorithm.as_str() {
                "sha384" => &PKCS_RSA_SHA384,
                "sha512" => &PKCS_RSA_SHA512,
                _ => &PKCS_RSA_SHA256,
            };
            log::debug!("Using hash algorithm {}", config.hash_algorithm);
            let kp = KeyPair::from_pkcs8_pem_and_sign_algo(pem.as_str(), sign_algo)
                .map_err(|e| io::Error::other(format!("Key pair creation failed: {}", e)))?;
            (kp, pem.to_string())
        }
        KeyAlgorithm::EcdsaP256 => {
            log::debug!("Generating ECDSA P-256 key");
            let kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
                .map_err(|e| io::Error::other(format!("ECDSA P-256 key generation failed: {}", e)))?;
            let pem = kp.serialize_pem();
            (kp, pem)
        }
        KeyAlgorithm::EcdsaP384 => {
            log::debug!("Generating ECDSA P-384 key");
            let kp = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384)
                .map_err(|e| io::Error::other(format!("ECDSA P-384 key generation failed: {}", e)))?;
            let pem = kp.serialize_pem();
            (kp, pem)
        }
    };

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CountryName, &config.country);
    dn.push(DnType::StateOrProvinceName, sanitize_for_cert_field(&config.state));
    dn.push(DnType::LocalityName, sanitize_for_cert_field(&config.locality));
    dn.push(DnType::OrganizationName, sanitize_for_cert_field(&config.organization));

    if let Some(street) = &config.street_address && !street.trim().is_empty() {
        dn.push(DnType::CustomDnType(vec![2, 5, 4, 9]), sanitize_for_cert_field(street));
    }

    if let Some(postal) = &config.postal_code && !postal.trim().is_empty() {
        dn.push(DnType::CustomDnType(vec![2, 5, 4, 17]), postal.as_str());
    }

    if let Some(ou) = &config.organizational_unit && !ou.trim().is_empty() {
        dn.push(DnType::OrganizationalUnitName, sanitize_for_cert_field(ou));
    }

    dn.push(DnType::CommonName, &config.common_name);

    if let Some(email) = &config.email && !email.trim().is_empty() {
        dn.push(DnType::CustomDnType(vec![1, 2, 840, 113549, 1, 9, 1]), email.as_str());
    }

    let mut params = CertificateParams::default();
    params.distinguished_name = dn;

    for san in config.san.iter() {
        if let Ok(ip) = san.parse::<std::net::IpAddr>() {
            params.subject_alt_names.push(SanType::IpAddress(ip));
        } else {
            let parsed_san = san.parse().map_err(|e| io::Error::other(format!("SAN parsing failed: {}", e)))?;
            params.subject_alt_names.push(SanType::DnsName(parsed_san));
        }
    }

    params.key_usages = match (&config.key_algorithm, &config.cert_purpose) {
        (KeyAlgorithm::EcdsaP256 | KeyAlgorithm::EcdsaP384, _) => {
            vec![KeyUsagePurpose::DigitalSignature]
        }
        (_, CertPurpose::TlsServer) => {
            vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment]
        }
        (_, CertPurpose::TlsClient) => {
            vec![KeyUsagePurpose::DigitalSignature]
        }
    };

    params.extended_key_usages = match &config.cert_purpose {
        CertPurpose::TlsServer => vec![ExtendedKeyUsagePurpose::ServerAuth],
        CertPurpose::TlsClient => vec![ExtendedKeyUsagePurpose::ClientAuth],
    };

    // We don't generate CA certificates in this application
    params.is_ca = IsCa::ExplicitNoCa;

    log::debug!("Using params: {:?}", params);

    log::debug!("Generating CSR");
    let cert = params.serialize_request(&key_pair)
        .map_err(|e| io::Error::other(format!("Certificate creation failed: {}", e)))?;

    log::debug!("Converting CSR to PEM format");
    let csr_pem = cert.pem()
        .map_err(|e| io::Error::other(format!("CSR PEM export failed: {}", e)))?;

    log::info!("Generated certificate request for {} with {} SANs", config.common_name, config.san.len());
    Ok(GeneratedCert {
        key_pem: key_pem.to_string(),
        csr_pem,
    })
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
        let result = generate_cert_request(&config).unwrap();
        assert!(result.key_pem.contains("BEGIN PRIVATE KEY"));
        assert!(result.key_pem.contains("END PRIVATE KEY"));
        assert!(result.csr_pem.contains("BEGIN CERTIFICATE REQUEST"));
        assert!(result.csr_pem.contains("END CERTIFICATE REQUEST"));
    }

    #[test]
    fn test_multiple_dns_sans() {
        let config = test_config(vec![
            "example.com".to_string(),
            "www.example.com".to_string(),
            "mail.example.com".to_string(),
        ]);
        assert!(generate_cert_request(&config).is_ok());
    }

    #[test]
    fn test_ip_san() {
        let config = test_config(vec!["example.com".to_string(), "192.168.1.1".to_string()]);
        assert!(generate_cert_request(&config).is_ok());
    }

    #[test]
    fn test_no_sans() {
        let config = test_config(vec![]);
        assert!(generate_cert_request(&config).is_ok());
    }

    #[test]
    fn test_wildcard_cn() {
        let config = CertConfig {
            common_name: "*.example.com".to_string(),
            san: vec!["*.example.com".to_string()],
            ..test_config(vec![])
        };
        assert!(generate_cert_request(&config).is_ok());
    }

    #[test]
    fn test_sha384() {
        let config = CertConfig {
            hash_algorithm: "sha384".to_string(),
            ..test_config(vec!["test.example.com".to_string()])
        };
        assert!(generate_cert_request(&config).is_ok());
    }

    #[test]
    fn test_sha512() {
        let config = CertConfig {
            hash_algorithm: "sha512".to_string(),
            ..test_config(vec!["test.example.com".to_string()])
        };
        assert!(generate_cert_request(&config).is_ok());
    }

    #[test]
    fn test_unknown_hash_algorithm_falls_back_to_sha256() {
        let config = CertConfig {
            hash_algorithm: "md5".to_string(),
            ..test_config(vec!["test.example.com".to_string()])
        };
        assert!(generate_cert_request(&config).is_ok());
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
        assert!(generate_cert_request(&config).is_ok());
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
        assert!(generate_cert_request(&config).is_ok());
    }

    #[test]
    fn test_german_characters_in_fields() {
        let config = CertConfig {
            state: "Thüringen".to_string(),
            locality: "Mühlhausen".to_string(),
            organization: "Bäckerei Müller & Söhne GmbH".to_string(),
            ..test_config(vec!["test.example.de".to_string()])
        };
        assert!(generate_cert_request(&config).is_ok());
    }

    #[test]
    fn test_tls_client_cert() {
        let config = CertConfig {
            cert_purpose: CertPurpose::TlsClient,
            ..test_config(vec!["test.example.com".to_string()])
        };
        assert!(generate_cert_request(&config).is_ok());
    }

    #[test]
    fn test_ecdsa_p256() {
        let config = CertConfig {
            key_algorithm: KeyAlgorithm::EcdsaP256,
            ..test_config(vec!["test.example.com".to_string()])
        };
        let result = generate_cert_request(&config).unwrap();
        assert!(result.key_pem.contains("BEGIN PRIVATE KEY"));
        assert!(result.csr_pem.contains("BEGIN CERTIFICATE REQUEST"));
    }

    #[test]
    fn test_ecdsa_p384() {
        let config = CertConfig {
            key_algorithm: KeyAlgorithm::EcdsaP384,
            ..test_config(vec!["test.example.com".to_string()])
        };
        assert!(generate_cert_request(&config).is_ok());
    }

    #[test]
    fn test_rsa_3072() {
        let config = CertConfig {
            key_algorithm: KeyAlgorithm::Rsa3072,
            ..test_config(vec!["test.example.com".to_string()])
        };
        assert!(generate_cert_request(&config).is_ok());
    }

    #[test]
    fn test_rsa_4096() {
        let config = CertConfig {
            key_algorithm: KeyAlgorithm::Rsa4096,
            ..test_config(vec!["test.example.com".to_string()])
        };
        assert!(generate_cert_request(&config).is_ok());
    }
}
