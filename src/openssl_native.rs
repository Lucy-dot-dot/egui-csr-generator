use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::{X509Req, X509Name};
use openssl::x509::extension::SubjectAlternativeName;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::stack::Stack;
use std::io;

use crate::cert_config::{CertConfig, sanitize_for_cert_field};

pub struct GeneratedCert {
    pub key_pem: String,
    pub csr_pem: String,
}

pub fn generate_cert_request(config: &CertConfig) -> io::Result<GeneratedCert> {
    // 1. Generate RSA key
    let key_size: u32 = config.key_size.parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid key size"))?;

    let rsa = Rsa::generate(key_size)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("RSA generation failed: {}", e)))?;

    let pkey = PKey::from_rsa(rsa)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("PKey creation failed: {}", e)))?;

    // 2. Create X509 Name (Distinguished Name)
    let mut name_builder = X509Name::builder()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Name builder failed: {}", e)))?;

    name_builder.append_entry_by_nid(Nid::COUNTRYNAME, config.country)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    name_builder.append_entry_by_nid(Nid::STATEORPROVINCENAME, &sanitize_for_cert_field(config.state))
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    name_builder.append_entry_by_nid(Nid::LOCALITYNAME, &sanitize_for_cert_field(config.locality))
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    name_builder.append_entry_by_nid(Nid::ORGANIZATIONNAME, &sanitize_for_cert_field(config.organization))
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    // Optional fields
    if let Some(street) = config.street_address {
        if !street.trim().is_empty() {
            name_builder.append_entry_by_nid(Nid::STREETADDRESS, &sanitize_for_cert_field(street))
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        }
    }

    if let Some(postal) = config.postal_code {
        if !postal.trim().is_empty() {
            name_builder.append_entry_by_nid(Nid::POSTALCODE, postal)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        }
    }

    if let Some(ou) = config.organizational_unit {
        if !ou.trim().is_empty() {
            name_builder.append_entry_by_nid(Nid::ORGANIZATIONALUNITNAME, &sanitize_for_cert_field(ou))
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        }
    }

    name_builder.append_entry_by_nid(Nid::COMMONNAME, config.common_name)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    if let Some(email) = config.email {
        if !email.trim().is_empty() {
            name_builder.append_entry_by_nid(Nid::PKCS9_EMAILADDRESS, email)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        }
    }

    let name = name_builder.build();

    // 3. Create Certificate Signing Request
    let mut req_builder = X509Req::builder()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("CSR builder failed: {}", e)))?;

    req_builder.set_subject_name(&name)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    req_builder.set_pubkey(&pkey)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    // 4. Add SANs if present
    if !config.san.is_empty() {
        let mut san_builder = SubjectAlternativeName::new();

        for san in config.san.iter() {
            if san.parse::<std::net::IpAddr>().is_ok() {
                san_builder.ip(san);
            } else {
                san_builder.dns(san);
            }
        }

        let san_extension = san_builder.build(&req_builder.x509v3_context(None))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("SAN extension failed: {}", e)))?;

        let mut stack = Stack::new()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        stack.push(san_extension)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        req_builder.add_extensions(&stack)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    }

    // 5. Sign the request
    let hash_algo = match config.hash_algorithm {
        "sha256" => MessageDigest::sha256(),
        "sha384" => MessageDigest::sha384(),
        "sha512" => MessageDigest::sha512(),
        _ => MessageDigest::sha256(),
    };

    req_builder.sign(&pkey, hash_algo)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Signing failed: {}", e)))?;

    let req = req_builder.build();

    // 6. Export to PEM
    let key_pem = pkey.private_key_to_pem_pkcs8()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Key PEM export failed: {}", e)))?;

    let csr_pem = req.to_pem()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("CSR PEM export failed: {}", e)))?;

    Ok(GeneratedCert {
        key_pem: String::from_utf8_lossy(&key_pem).to_string(),
        csr_pem: String::from_utf8_lossy(&csr_pem).to_string(),
    })
}
