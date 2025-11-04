use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::{X509Req, X509Name};
use openssl::x509::extension::SubjectAlternativeName;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::stack::Stack;
use std::io;
use std::process::{Command, Stdio};
use crate::CertGenApp;

pub struct GeneratedCert {
    pub key_pem: String,
    pub csr_pem: String,
}

pub struct CertConfig<'a> {
    pub country: &'a str,
    pub state: &'a str,
    pub locality: &'a str,
    pub organization: &'a str,
    pub organizational_unit: Option<&'a str>,
    pub email: Option<&'a str>,
    pub street_address: Option<&'a str>,
    pub postal_code: Option<&'a str>,
    pub common_name: &'a str,
    pub san: &'a Vec<String>,
    pub key_size: &'a str,
    pub hash_algorithm: &'a str,
}

impl<'a> From<&'a CertGenApp> for CertConfig<'a> {
    fn from(value: &'a CertGenApp) -> Self {
        CertConfig {
            country: &value.country,
            state: &value.state,
            locality: &value.locality,
            organization: &value.organization,
            organizational_unit: if value.organizational_unit.is_empty() { None } else { Some(&value.organizational_unit) },
            email: if value.email.is_empty() { None } else { Some(&value.email) },
            street_address: if value.street_address.is_empty() { None } else { Some(&value.street_address) },
            postal_code: if value.postal_code.is_empty() { None } else { Some(&value.postal_code) },
            common_name: &value.common_name,
            san: &value.sans,
            key_size: &value.key_size,
            hash_algorithm: &value.hash_algorithm,
        }
    }
}


/// Sanitizes input for use in filenames and domain names
/// - Replaces special characters with ASCII equivalents
/// - Converts spaces to hyphens
/// - Removes/replaces characters not valid for domain names
pub fn sanitize(input: &str) -> String {
    sanitize_internal(input, false)
}

/// Sanitizes input for use in certificate Distinguished Name fields
/// - Replaces special characters with ASCII equivalents
/// - PRESERVES spaces (doesn't convert them to hyphens)
/// - Removes/replaces other invalid characters
pub fn sanitize_for_cert_field(input: &str) -> String {
    sanitize_internal(input, true)
}

fn sanitize_internal(input: &str, preserve_spaces: bool) -> String {
    // First pass: replace known special characters with ASCII equivalents
    let mut result = String::new();

    for c in input.chars() {
        let replacement = match c {
            // German umlauts and ß
            'ä' | 'Ä' => "ae",
            'ö' | 'Ö' => "oe",
            'ü' | 'Ü' => "ue",
            'ß' => "ss",

            // French accents
            'à' | 'â' | 'á' | 'ã' | 'å' => "a",
            'À' | 'Â' | 'Á' | 'Ã' | 'Å' => "A",
            'é' | 'è' | 'ê' | 'ë' => "e",
            'É' | 'È' | 'Ê' | 'Ë' => "E",
            'î' | 'ï' | 'í' | 'ì' => "i",
            'Î' | 'Ï' | 'Í' | 'Ì' => "I",
            'ô' | 'ó' | 'ò' | 'õ' => "o",
            'Ô' | 'Ó' | 'Ò' | 'Õ' => "O",
            'û' | 'ú' | 'ù' => "u",
            'Û' | 'Ú' | 'Ù' => "U",
            'ÿ' | 'ý' => "y",
            'Ÿ' | 'Ý' => "Y",
            'ç' => "c",
            'Ç' => "C",

            // Scandinavian characters
            'æ' => "ae",
            'Æ' => "AE",
            'ø' => "oe",
            'Ø' => "OE",

            // Spanish
            'ñ' => "n",
            'Ñ' => "N",

            // Polish and Eastern European
            'ł' => "l",
            'Ł' => "L",
            'ą' => "a",
            'Ą' => "A",
            'ę' => "e",
            'Ę' => "E",
            'ć' => "c",
            'Ć' => "C",
            'ń' => "n",
            'Ń' => "N",
            'ś' => "s",
            'Ś' => "S",
            'ź' | 'ż' => "z",
            'Ź' | 'Ż' => "Z",

            // Czech and Slovak
            'č' => "c",
            'Č' => "C",
            'ď' => "d",
            'Ď' => "D",
            'ě' => "e",
            'Ě' => "E",
            'ň' => "n",
            'Ň' => "N",
            'ř' => "r",
            'Ř' => "R",
            'š' => "s",
            'Š' => "S",
            'ť' => "t",
            'Ť' => "T",
            'ů' => "u",
            'Ů' => "U",
            'ž' => "z",
            'Ž' => "Z",

            // Space handling - conditional based on mode
            ' ' => {
                if preserve_spaces {
                    result.push(' ');
                    continue;
                } else {
                    "-"
                }
            }

            // Other common symbols
            '&' => "and",
            '@' => "at",
            '/' | '\\' => "-",

            // Valid characters for domain names and filenames: pass through
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' => {
                result.push(c);
                continue;
            }

            // For any other character, replace with underscore
            _ => "_",
        };

        result.push_str(replacement);
    }

    // Clean up potential issues from replacement:
    if preserve_spaces {
        // For cert fields: trim leading/trailing spaces and underscores, collapse multiple spaces
        result = result.trim().to_string();
        while result.contains("  ") {
            result = result.replace("  ", " ");
        }
    } else {
        // For filenames: remove leading/trailing hyphens and underscores
        result = result
            .trim_matches(|c| c == '-' || c == '_')
            .to_string();

        // Replace multiple consecutive separators with a single one
        while result.contains("--") || result.contains("__") || result.contains("-.") || result.contains("._") {
            result = result
                .replace("--", "-")
                .replace("__", "_")
                .replace("-.", ".")
                .replace(".-", ".");
        }
    }

    result
}

impl<'a> CertConfig<'a> {

    pub fn generate_config(&self) -> io::Result<String> {
        // Validate country code is two letters
        if self.country.len() != 2 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Country code must be exactly 2 letters"));
        }

        // Generate configuration content
        let mut config_content = String::new();

        // Basic configuration
        config_content.push_str("[req]\n");
        config_content.push_str("distinguished_name = req_distinguished_name\n");
        config_content.push_str(&format!("default_bits = {}\n", self.key_size));
        config_content.push_str("prompt = no\n");
        config_content.push_str(&format!("default_md = {}\n", self.hash_algorithm));
        config_content.push_str("encrypt_key = no\n");      // Equivalent to -nodes option
        let keyfile_name = if self.common_name.starts_with("*.") {
            self.common_name.replacen("*.", "wildcard.", 1)
        } else {
            self.common_name.to_string()
        };

        config_content.push_str(&format!("default_keyfile = {}.key\n", keyfile_name));

        if !self.san.is_empty() {
            config_content.push_str("req_extensions = v3_req\n");
        }

        // Distinguished name section
        config_content.push_str("\n[req_distinguished_name]\n");
        config_content.push_str(&format!("C = {}\n", self.country));
        config_content.push_str(&format!("ST = {}\n", sanitize_for_cert_field(self.state)));
        config_content.push_str(&format!("L = {}\n", sanitize_for_cert_field(self.locality)));

        // Optional street address and postal code
        if let Some(street) = self.street_address {
            if !street.trim().is_empty() {
                config_content.push_str(&format!("street = {}\n", sanitize_for_cert_field(street)));
            }
        }

        if let Some(postal) = self.postal_code {
            if !postal.trim().is_empty() {
                config_content.push_str(&format!("postalCode = {}\n", postal));
            }
        }

        config_content.push_str(&format!("O = {}\n", sanitize_for_cert_field(self.organization)));

        // Optional OU
        if let Some(ou) = self.organizational_unit {
            if !ou.trim().is_empty() {
                config_content.push_str(&format!("OU = {}\n", sanitize_for_cert_field(ou)));
            }
        }

        config_content.push_str(&format!("CN = {}\n", self.common_name));

        if let Some(email_addr) = self.email {
            if !email_addr.trim().is_empty() {
                config_content.push_str(&format!("emailAddress = {}\n", email_addr));
            }
        }

        if !self.san.is_empty() {
            // Extensions section
            config_content.push_str("[v3_req]\n");
            config_content.push_str("subjectAltName = @alt_names\n\n");

            // Alternative names section
            config_content.push_str("[alt_names]\n");
            for (i, san) in self.san.iter().enumerate() {
                // Check if it's an IP address or DNS name (simple check)
                if san.parse::<std::net::IpAddr>().is_ok() {
                    config_content.push_str(&format!("IP.{} = {}\n", i + 1, san));
                } else {
                    config_content.push_str(&format!("DNS.{} = {}\n", i + 1, san));
                }
            }
        }
        Ok(config_content)
    }
}

pub fn execute_openssl_command(command: &str) -> io::Result<(String, String)> {
    // Split the command into program and arguments
    let parts: Vec<&str> = command.split_whitespace().collect();
    if parts.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Empty command"));
    }

    let program = parts[0];
    let args = &parts[1..];

    // Execute the command
    let output = Command::new(program)
        .args(args)
        .stdin(Stdio::inherit())
        .output()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to execute command: {}", e)))?;

    if output.status.success() {
        log::debug!("OpenSSL command executed successfully!");
    } else {
        log::error!("OpenSSL command failed with exit code: {}", output.status);
    }

    Ok((String::from_utf8_lossy(&*output.stdout).parse().unwrap(), String::from_utf8_lossy(&*output.stderr).parse().unwrap()))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_german_characters() {
        assert_eq!(sanitize("Müller"), "Mueller");
        assert_eq!(sanitize("Schön"), "Schoen");
        assert_eq!(sanitize("Bäcker"), "Baecker");
        assert_eq!(sanitize("Straße"), "Strasse");
        // Note: uppercase Ü is replaced with lowercase "ue"
        assert_eq!(sanitize("MÜNCHEN"), "MueNCHEN");
    }

    #[test]
    fn test_sanitize_french_characters() {
        assert_eq!(sanitize("Café"), "Cafe");
        assert_eq!(sanitize("Crème"), "Creme");
        assert_eq!(sanitize("Naïve"), "Naive");
        assert_eq!(sanitize("François"), "Francois");
        assert_eq!(sanitize("Château"), "Chateau");
    }

    #[test]
    fn test_sanitize_scandinavian_characters() {
        assert_eq!(sanitize("København"), "Koebenhavn");
        assert_eq!(sanitize("Malmö"), "Malmoe");
        assert_eq!(sanitize("Æther"), "AEther");
    }

    #[test]
    fn test_sanitize_spanish_characters() {
        assert_eq!(sanitize("España"), "Espana");
        assert_eq!(sanitize("Señor"), "Senor");
        assert_eq!(sanitize("Niño"), "Nino");
    }

    #[test]
    fn test_sanitize_polish_characters() {
        assert_eq!(sanitize("Łódź"), "Lodz");
        assert_eq!(sanitize("Kraków"), "Krakow");
        // Note: Capital Ą becomes A, and both ź and ż become z
        assert_eq!(sanitize("Ąćęłńóśźż"), "Acelnoszz");
    }

    #[test]
    fn test_sanitize_czech_slovak_characters() {
        assert_eq!(sanitize("Čeština"), "Cestina");
        assert_eq!(sanitize("Řešení"), "Reseni");
        assert_eq!(sanitize("Žižkov"), "Zizkov");
    }

    #[test]
    fn test_sanitize_symbols() {
        assert_eq!(sanitize("Smith & Jones"), "Smith-and-Jones");
        assert_eq!(sanitize("user@company"), "useratcompany");
        assert_eq!(sanitize("path/to/file"), "path-to-file");
        assert_eq!(sanitize("back\\slash"), "back-slash");
    }

    #[test]
    fn test_sanitize_spaces() {
        assert_eq!(sanitize("Hello World"), "Hello-World");
        assert_eq!(sanitize("Multiple   Spaces"), "Multiple-Spaces");
    }

    #[test]
    fn test_sanitize_mixed_special_characters() {
        assert_eq!(sanitize("Müller & Söhne GmbH"), "Mueller-and-Soehne-GmbH");
        assert_eq!(sanitize("Café François"), "Cafe-Francois");
        // Note: @ becomes "at", and trailing underscores are trimmed
        assert_eq!(sanitize("Test!@#$%"), "Test_at");
    }

    #[test]
    fn test_sanitize_preserves_valid_characters() {
        assert_eq!(sanitize("abc123"), "abc123");
        assert_eq!(sanitize("test-file_name.txt"), "test-file_name.txt");
        assert_eq!(sanitize("UPPERCASE"), "UPPERCASE");
    }

    #[test]
    fn test_sanitize_removes_leading_trailing_separators() {
        assert_eq!(sanitize("-leading"), "leading");
        assert_eq!(sanitize("trailing-"), "trailing");
        assert_eq!(sanitize("_both_"), "both");
        assert_eq!(sanitize("---multiple---"), "multiple");
    }

    #[test]
    fn test_sanitize_collapses_multiple_separators() {
        assert_eq!(sanitize("double--dash"), "double-dash");
        assert_eq!(sanitize("triple___underscore"), "triple_underscore");
    }

    #[test]
    fn test_sanitize_complex_real_world_examples() {
        // German company name
        assert_eq!(
            sanitize("Bäckerei Müller & Söhne GmbH"),
            "Baeckerei-Mueller-and-Soehne-GmbH"
        );

        // French address
        assert_eq!(
            sanitize("123 Rue de l'Église"),
            "123-Rue-de-l_Eglise"
        );

        // Mixed international - note: periods are valid characters and preserved
        assert_eq!(
            sanitize("Łódź/Kraków Services Pty."),
            "Lodz-Krakow-Services-Pty."
        );
    }

    #[test]
    fn test_sanitize_unicode_edge_cases() {
        // Emoji and other unicode are replaced with underscores,
        // but trailing underscores are trimmed
        assert_eq!(sanitize("Test😀"), "Test");
        assert_eq!(sanitize("Hello™"), "Hello");
        assert_eq!(sanitize("Copyright©2024"), "Copyright_2024");
        // Emoji in the middle is preserved
        assert_eq!(sanitize("Test😀Data"), "Test_Data");
    }

    #[test]
    fn test_sanitize_empty_and_whitespace() {
        assert_eq!(sanitize(""), "");
        assert_eq!(sanitize("   "), "");
        assert_eq!(sanitize("a b c"), "a-b-c");
    }

    // Tests for sanitize_for_cert_field (preserves spaces)
    #[test]
    fn test_sanitize_cert_field_preserves_spaces() {
        assert_eq!(sanitize_for_cert_field("Hello World"), "Hello World");
        assert_eq!(sanitize_for_cert_field("New York"), "New York");
        assert_eq!(sanitize_for_cert_field("San Francisco Bay Area"), "San Francisco Bay Area");
    }

    #[test]
    fn test_sanitize_cert_field_german_with_spaces() {
        assert_eq!(sanitize_for_cert_field("Müller & Söhne GmbH"), "Mueller and Soehne GmbH");
        assert_eq!(sanitize_for_cert_field("Stadt München"), "Stadt Muenchen");
    }

    #[test]
    fn test_sanitize_cert_field_collapses_multiple_spaces() {
        assert_eq!(sanitize_for_cert_field("Too    Many   Spaces"), "Too Many Spaces");
        assert_eq!(sanitize_for_cert_field("  Leading and trailing  "), "Leading and trailing");
    }

    #[test]
    fn test_sanitize_cert_field_special_characters() {
        // Spaces preserved, special chars replaced
        assert_eq!(sanitize_for_cert_field("Café François"), "Cafe Francois");
        assert_eq!(sanitize_for_cert_field("Łódź Province"), "Lodz Province");
        assert_eq!(sanitize_for_cert_field("São Paulo"), "Sao Paulo");
    }

    #[test]
    fn test_sanitize_vs_cert_field_comparison() {
        let input = "Müller & Söhne GmbH";
        // sanitize converts spaces to hyphens
        assert_eq!(sanitize(input), "Mueller-and-Soehne-GmbH");
        // sanitize_for_cert_field preserves spaces
        assert_eq!(sanitize_for_cert_field(input), "Mueller and Soehne GmbH");
    }
}