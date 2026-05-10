use std::fs;
use zip::{ZipWriter, write::SimpleFileOptions};
use std::io::{Write, Cursor};

pub mod form;
pub mod openssloutput;
pub mod save_button;
pub mod execute_button;

pub fn generate_and_save(cnf: &str, name: &str, key: &str, csr: &str, recreate_cmd: &str) -> std::io::Result<()> {
    log::debug!("Generating and saving files to zip");
    log::debug!("Contents: \n{name}.cnf = {cnf}\n\n{name}.key = {key}\n\n{name}.csr = {csr}\n\ncommand: {recreate_cmd}");
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
    zip.write_all(recreate_cmd.as_bytes())?;

    // Finalize the zip
    zip.finish()?;

    // Get the zip data
    let zip_data = zip_buffer.into_inner();

    if let Some(path) = dirs::download_dir() {
        let target = path.join(format!("{}_certificate_files.zip", name));
        if target.exists() {
            log::info!("Target location already exists, finding alternative name");
            // you have other issues if you exhaust 100.000 files in your downloads folder
            for i in 1..100_000 {
                let alt_name = format!("{}_certificate_files_{}.zip", name, i);
                let alt_path = path.join(alt_name.clone());
                log::debug!("Checking if {} exists", alt_path.display());
                if !alt_path.exists() {
                    log::info!("Alternative name {} not found, writing to {}", alt_name, target.display());
                    fs::write(alt_path, zip_data)?;
                    return Ok(());
                } else {
                    log::info!("Alternative name {} already exists, next attempt", alt_name);
                }
            }
        } else {
            log::info!("Writing zip to {}", target.display());
            fs::write(target, zip_data)?;
        }
    } else {
        log::error!("Could not find downloads folder");
        return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "Unable to determine downloads folder path"));
    }
    Ok(())
}
