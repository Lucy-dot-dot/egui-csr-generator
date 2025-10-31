use std::fs;
use zip::{ZipWriter, write::SimpleFileOptions};
use std::io::{Write, Cursor};

pub mod form;
pub mod openssloutput;
pub mod save_button;
pub mod execute_button;

pub fn generate_and_save(cnf: &str, name: &str, key: &str, csr: &str) -> std::io::Result<()> {
    log::debug!("Generating and saving files to zip");
    log::debug!("Contents: \n{name}.cnf = {cnf}\n\n{name}.key = {key}\n\n{name}.csr = {csr}\n\ncommand: openssl req -new -out {name}.csr -config {name}.cnf");
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

    zip.start_file("recreate_command.txt", options)?;
    zip.write_all(format!("openssl req -new -out {}.csr -config {}.cnf", name, name).as_bytes())?;

    // Finalize the zip
    zip.finish()?;

    // Get the zip data
    let zip_data = zip_buffer.into_inner();

    if let Some(path) = dirs::download_dir() {
        let target = path.join(format!("{}_certificate_files.zip", name));
        log::info!("Writing zip to {}", target.display());
        fs::write(target, zip_data)?;
    }
    Ok(())
}
