use std::io;
use std::process::{Command, Stdio};

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
