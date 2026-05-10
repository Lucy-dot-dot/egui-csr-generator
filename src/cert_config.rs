use std::io;
use crate::CertGenApp;

#[derive(Clone, Debug, PartialEq)]
pub enum KeyAlgorithm {
    Rsa2048,
    Rsa3072,
    Rsa4096,
    EcdsaP256,
    EcdsaP384,
}

#[derive(Clone, Debug, PartialEq)]
pub enum CertPurpose {
    TlsServer,
    TlsClient,
}

pub struct CertConfig {
    pub country: String,
    pub state: String,
    pub locality: String,
    pub organization: String,
    pub organizational_unit: Option<String>,
    pub email: Option<String>,
    pub street_address: Option<String>,
    pub postal_code: Option<String>,
    pub common_name: String,
    pub san: Vec<String>,
    pub key_algorithm: KeyAlgorithm,
    pub hash_algorithm: String,
    pub cert_purpose: CertPurpose,
}

impl From<&CertGenApp> for CertConfig {
    fn from(value: &CertGenApp) -> Self {
        CertConfig {
            country: value.country.clone(),
            state: value.state.clone(),
            locality: value.locality.clone(),
            organization: value.organization.clone(),
            organizational_unit: if value.organizational_unit.is_empty() { None } else { Some(value.organizational_unit.clone()) },
            email: if value.email.is_empty() { None } else { Some(value.email.clone()) },
            street_address: if value.street_address.is_empty() { None } else { Some(value.street_address.clone()) },
            postal_code: if value.postal_code.is_empty() { None } else { Some(value.postal_code.clone()) },
            common_name: value.common_name.clone(),
            san: value.sans.clone(),
            key_algorithm: value.key_algorithm.clone(),
            hash_algorithm: value.hash_algorithm.clone(),
            cert_purpose: value.cert_purpose.clone(),
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

impl CertConfig {

    pub fn generate_config(&self) -> io::Result<String> {
        // Validate country code is two letters
        if self.country.len() != 2 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Country code must be exactly 2 letters"));
        }

        let mut config_content = String::new();

        config_content.push_str("[req]\n");
        config_content.push_str("distinguished_name = req_distinguished_name\n");

        match &self.key_algorithm {
            KeyAlgorithm::Rsa2048 => {
                config_content.push_str("default_bits = 2048\n");
                config_content.push_str(&format!("default_md = {}\n", self.hash_algorithm));
            }
            KeyAlgorithm::Rsa3072 => {
                config_content.push_str("default_bits = 3072\n");
                config_content.push_str(&format!("default_md = {}\n", self.hash_algorithm));
            }
            KeyAlgorithm::Rsa4096 => {
                config_content.push_str("default_bits = 4096\n");
                config_content.push_str(&format!("default_md = {}\n", self.hash_algorithm));
            }
            KeyAlgorithm::EcdsaP256 => {
                config_content.push_str("default_md = sha256\n");
            }
            KeyAlgorithm::EcdsaP384 => {
                config_content.push_str("default_md = sha384\n");
            }
        }

        config_content.push_str("prompt = no\n");
        config_content.push_str("encrypt_key = no\n");

        let keyfile_name = if self.common_name.starts_with("*.") {
            self.common_name.replacen("*.", "wildcard.", 1)
        } else {
            self.common_name.clone()
        };

        // RSA uses default_keyfile; ECDSA key is generated separately and passed via -key flag
        match &self.key_algorithm {
            KeyAlgorithm::Rsa2048 | KeyAlgorithm::Rsa3072 | KeyAlgorithm::Rsa4096 => {
                config_content.push_str(&format!("default_keyfile = {}.key\n", keyfile_name));
            }
            KeyAlgorithm::EcdsaP256 | KeyAlgorithm::EcdsaP384 => {}
        }

        config_content.push_str("req_extensions = v3_req\n");

        config_content.push_str("\n[req_distinguished_name]\n");
        config_content.push_str(&format!("C = {}\n", self.country));
        config_content.push_str(&format!("ST = {}\n", sanitize_for_cert_field(&self.state)));
        config_content.push_str(&format!("L = {}\n", sanitize_for_cert_field(&self.locality)));

        if let Some(street) = &self.street_address && !street.trim().is_empty() {
            config_content.push_str(&format!("street = {}\n", sanitize_for_cert_field(street)));
        }

        if let Some(postal) = &self.postal_code && !postal.trim().is_empty() {
            config_content.push_str(&format!("postalCode = {}\n", postal));
        }

        config_content.push_str(&format!("O = {}\n", sanitize_for_cert_field(&self.organization)));

        if let Some(ou) = &self.organizational_unit && !ou.trim().is_empty() {
            config_content.push_str(&format!("OU = {}\n", sanitize_for_cert_field(ou)));
        }

        config_content.push_str(&format!("CN = {}\n", self.common_name));

        if let Some(email_addr) = &self.email && !email_addr.trim().is_empty() {
            config_content.push_str(&format!("emailAddress = {}\n", email_addr));
        }

        config_content.push_str("\n[v3_req]\n");

        let key_usage = match (&self.key_algorithm, &self.cert_purpose) {
            (KeyAlgorithm::EcdsaP256 | KeyAlgorithm::EcdsaP384, _) => {
                "critical, digitalSignature"
            }
            (_, CertPurpose::TlsServer) => "critical, digitalSignature, keyEncipherment",
            (_, CertPurpose::TlsClient) => "critical, digitalSignature",
        };
        config_content.push_str(&format!("keyUsage = {}\n", key_usage));

        let ext_key_usage = match &self.cert_purpose {
            CertPurpose::TlsServer => "serverAuth",
            CertPurpose::TlsClient => "clientAuth",
        };
        config_content.push_str(&format!("extendedKeyUsage = {}\n", ext_key_usage));

        if !self.san.is_empty() {
            config_content.push_str("subjectAltName = @alt_names\n\n");

            config_content.push_str("[alt_names]\n");
            for (i, san) in self.san.iter().enumerate() {
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
