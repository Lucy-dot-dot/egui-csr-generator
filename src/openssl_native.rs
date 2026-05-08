use std::io;
use rsa::RsaPrivateKey;
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use rcgen::{CertificateParams, DistinguishedName, DnType, SanType, KeyPair};
use rcgen::{PKCS_RSA_SHA256, PKCS_RSA_SHA384, PKCS_RSA_SHA512};
use rsa::rand_core::OsRng;
use crate::cert_config::{CertConfig, sanitize_for_cert_field};

pub struct GeneratedCert {
    pub key_pem: String,
    pub csr_pem: String,
}

pub fn generate_cert_request(config: &CertConfig) -> io::Result<GeneratedCert> {
    let key_size: usize = config.key_size.parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid key size"))?;

    log::debug!("Generating certificate with key size {} bits", key_size);
    let private_key = RsaPrivateKey::new(&mut OsRng, key_size)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("RSA key generation failed: {}", e)))?;
    log::debug!("Generated RSA key");

    let key_pem = private_key.to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Key PEM export failed: {}", e)))?;

    let sign_algo = match config.hash_algorithm {
        "sha384" => &PKCS_RSA_SHA384,
        "sha512" => &PKCS_RSA_SHA512,
        _ => &PKCS_RSA_SHA256,
    };

    log::debug!("Using hash algorithm {}", config.hash_algorithm);

    let key_pair = KeyPair::from_pkcs8_pem_and_sign_algo(key_pem.as_str(), sign_algo)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Key pair creation failed: {}", e)))?;

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CountryName, config.country);
    dn.push(DnType::StateOrProvinceName, sanitize_for_cert_field(config.state));
    dn.push(DnType::LocalityName, sanitize_for_cert_field(config.locality));
    dn.push(DnType::OrganizationName, sanitize_for_cert_field(config.organization));

    if let Some(street) = config.street_address {
        if !street.trim().is_empty() {
            dn.push(DnType::CustomDnType(vec![2, 5, 4, 9]), sanitize_for_cert_field(street));
        }
    }

    if let Some(postal) = config.postal_code {
        if !postal.trim().is_empty() {
            dn.push(DnType::CustomDnType(vec![2, 5, 4, 17]), postal.to_string());
        }
    }

    if let Some(ou) = config.organizational_unit {
        if !ou.trim().is_empty() {
            dn.push(DnType::OrganizationalUnitName, sanitize_for_cert_field(ou));
        }
    }

    dn.push(DnType::CommonName, config.common_name);

    if let Some(email) = config.email {
        if !email.trim().is_empty() {
            dn.push(DnType::CustomDnType(vec![1, 2, 840, 113549, 1, 9, 1]), email.to_string());
        }
    }

    let mut params = CertificateParams::default();
    params.distinguished_name = dn;

    for san in config.san.iter() {
        if let Ok(ip) = san.parse::<std::net::IpAddr>() {
            params.subject_alt_names.push(SanType::IpAddress(ip));
        } else {
            params.subject_alt_names.push(SanType::DnsName(san.parse().unwrap()));
        }
    }

    log::debug!("Using params: {:?}", params);

    log::debug!("Generating CSR");
    let cert = params.serialize_request(&key_pair)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Certificate creation failed: {}", e)))?;

    log::debug!("Converting CSR to PEM format");
    let csr_pem = cert.pem()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("CSR PEM export failed: {}", e)))?;

    log::info!("Generated certificate request for {} with {} SANs", config.common_name, config.san.len());
    Ok(GeneratedCert {
        key_pem: key_pem.to_string(),
        csr_pem,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(san: &Vec<String>) -> CertConfig {
        CertConfig {
            country: "DE",
            state: "Nordrhein-Westfalen",
            locality: "Muenster",
            organization: "Test GmbH",
            organizational_unit: None,
            email: None,
            street_address: None,
            postal_code: None,
            common_name: "test.example.com",
            san,
            key_size: "2048",
            hash_algorithm: "sha256",
        }
    }

    #[test]
    fn test_basic_generation_produces_valid_pem() {
        let sans = vec!["test.example.com".to_string()];
        let config = test_config(&sans);
        let result = generate_cert_request(&config).unwrap();
        assert!(result.key_pem.contains("BEGIN PRIVATE KEY"));
        assert!(result.key_pem.contains("END PRIVATE KEY"));
        assert!(result.csr_pem.contains("BEGIN CERTIFICATE REQUEST"));
        assert!(result.csr_pem.contains("END CERTIFICATE REQUEST"));
    }

    #[test]
    fn test_multiple_dns_sans() {
        let sans = vec![
            "example.com".to_string(),
            "www.example.com".to_string(),
            "mail.example.com".to_string(),
        ];
        let config = test_config(&sans);
        assert!(generate_cert_request(&config).is_ok());
    }

    #[test]
    fn test_ip_san() {
        let sans = vec!["example.com".to_string(), "192.168.1.1".to_string()];
        let config = test_config(&sans);
        assert!(generate_cert_request(&config).is_ok());
    }

    #[test]
    fn test_no_sans() {
        let sans = vec![];
        let config = test_config(&sans);
        assert!(generate_cert_request(&config).is_ok());
    }

    #[test]
    fn test_wildcard_cn() {
        let sans = vec!["*.example.com".to_string()];
        let config = CertConfig {
            common_name: "*.example.com",
            san: &sans,
            ..test_config(&sans)
        };
        assert!(generate_cert_request(&config).is_ok());
    }

    #[test]
    fn test_sha384() {
        let sans = vec!["test.example.com".to_string()];
        let config = CertConfig { hash_algorithm: "sha384", ..test_config(&sans) };
        assert!(generate_cert_request(&config).is_ok());
    }

    #[test]
    fn test_sha512() {
        let sans = vec!["test.example.com".to_string()];
        let config = CertConfig { hash_algorithm: "sha512", ..test_config(&sans) };
        assert!(generate_cert_request(&config).is_ok());
    }

    #[test]
    fn test_unknown_hash_algorithm_falls_back_to_sha256() {
        let sans = vec!["test.example.com".to_string()];
        let config = CertConfig { hash_algorithm: "md5", ..test_config(&sans) };
        assert!(generate_cert_request(&config).is_ok());
    }

    #[test]
    fn test_all_optional_dn_fields() {
        let sans = vec!["corp.example.de".to_string()];
        let config = CertConfig {
            country: "DE",
            state: "Hessen",
            locality: "Frankfurt",
            organization: "Test AG",
            organizational_unit: Some("IT Abteilung"),
            email: Some("admin@example.de"),
            street_address: Some("Hauptstrasse 1"),
            postal_code: Some("60313"),
            common_name: "corp.example.de",
            san: &sans,
            key_size: "2048",
            hash_algorithm: "sha256",
        };
        assert!(generate_cert_request(&config).is_ok());
    }

    #[test]
    fn test_empty_optional_fields_are_skipped() {
        let sans = vec!["test.example.com".to_string()];
        let config = CertConfig {
            organizational_unit: Some(""),
            email: Some("   "),
            street_address: Some(""),
            postal_code: Some(""),
            ..test_config(&sans)
        };
        assert!(generate_cert_request(&config).is_ok());
    }

    #[test]
    fn test_german_characters_in_fields() {
        let sans = vec!["test.example.de".to_string()];
        let config = CertConfig {
            state: "Thüringen",
            locality: "Mühlhausen",
            organization: "Bäckerei Müller & Söhne GmbH",
            ..test_config(&sans)
        };
        assert!(generate_cert_request(&config).is_ok());
    }

    #[test]
    fn test_invalid_key_size_returns_error() {
        let sans = vec!["test.example.com".to_string()];
        let config = CertConfig { key_size: "not_a_number", ..test_config(&sans) };
        assert!(generate_cert_request(&config).is_err());
    }

    #[test]
    #[ignore]
    fn test_4096_key_size() {
        let sans = vec!["test.example.com".to_string()];
        let config = CertConfig { key_size: "4096", ..test_config(&sans) };
        assert!(generate_cert_request(&config).is_ok());
    }
}
