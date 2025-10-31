use std::io;
use std::process::{Command, Stdio};

pub struct CertConfig<'a> {
    pub country: &'a str,
    pub state: &'a str,
    pub locality: &'a str,
    pub organization: &'a str,
    pub organizational_unit: Option<&'a str>,
    pub email: Option<&'a str>,
    pub common_name: &'a str,
    pub san: &'a Vec<String>,
    pub key_size: &'a str,
    pub hash_algorithm: &'a str,
}

fn sanitize(input: &str) -> String {
    input.replace("ä", "ae").replace("ü", "ue").replace("ö", "oe")
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
        config_content.push_str(&format!("ST = {}\n", sanitize(self.state)));
        config_content.push_str(&format!("L = {}\n", sanitize(self.locality)));
        config_content.push_str(&format!("O = {}\n", sanitize(self.organization)));

        // Optional OU and Email
        if let Some(ou) = self.organizational_unit {
            if !ou.trim().is_empty() {
                config_content.push_str(&format!("OU = {}\n", sanitize(ou)));
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
        println!("OpenSSL command executed successfully!");
    } else {
        eprintln!("OpenSSL command failed with exit code: {}", output.status);
    }

    Ok((String::from_utf8_lossy(&*output.stdout).parse().unwrap(), String::from_utf8_lossy(&*output.stderr).parse().unwrap()))
}