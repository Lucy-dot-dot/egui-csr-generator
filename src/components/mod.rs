use std::fs;
use zip::{ZipWriter, write::SimpleFileOptions};
use std::io::{Write, Cursor};
use rfd::FileDialog;

pub mod form;
pub mod output;
pub mod execute_button;

/// The generated zip file does not use compression, the files are not even 5kb big.
pub fn save_certificate_files_to_zip(cnf: &str, name: &str, key: &str, csr: &str, recreate_cmd: &str) -> std::io::Result<()> {
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

    let default_name = format!("{}_certificate_files.zip", name);

    if let Some(target_path) = FileDialog::new()
        .set_file_name(&default_name)
        .add_filter("ZIP Archive", &["zip"])
        .save_file()
    {
        log::info!("Writing zip to {}", target_path.display());
        fs::write(target_path, zip_data)?;
        Ok(())
    } else {
        log::info!("User cancelled the save dialog");
        // Return an interrupted error so the UI knows it wasn't a real failure
        Err(std::io::Error::new(std::io::ErrorKind::Interrupted, "Save cancelled by user"))
    }
}
