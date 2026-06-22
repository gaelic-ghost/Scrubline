use std::ffi::OsString;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::AppError;

static TEMP_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub struct TransactionalOutput {
    destination: PathBuf,
    temporary: PathBuf,
    file: Option<File>,
    committed: bool,
}

impl TransactionalOutput {
    pub fn create(
        destination: &Path,
        input_path: &Path,
        input_metadata: Option<&Metadata>,
    ) -> Result<Self, AppError> {
        let (destination, permissions) =
            resolve_destination(destination, input_path, input_metadata)?;
        let parent = destination
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));

        for _ in 0..100 {
            let sequence = TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let mut name = OsString::from(".scrubline-");
            name.push(std::process::id().to_string());
            name.push("-");
            name.push(sequence.to_string());
            name.push(".tmp");
            let temporary = parent.join(name);

            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
            {
                Ok(file) => {
                    if let Some(permissions) = permissions.clone() {
                        if let Err(error) = file.set_permissions(permissions) {
                            drop(file);
                            let _ = fs::remove_file(&temporary);
                            return Err(AppError::CreateOutput(error));
                        }
                    }
                    return Ok(Self {
                        destination,
                        temporary,
                        file: Some(file),
                        committed: false,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(AppError::CreateOutput(error)),
            }
        }

        Err(AppError::CreateOutput(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "unable to reserve a unique temporary output file",
        )))
    }

    pub fn commit(mut self) -> Result<(), AppError> {
        let file = self
            .file
            .as_mut()
            .expect("transaction owns its file until commit");
        file.flush().map_err(AppError::FlushOutput)?;
        file.sync_all().map_err(AppError::FlushOutput)?;
        self.file.take();
        fs::rename(&self.temporary, &self.destination).map_err(AppError::CommitOutput)?;
        self.committed = true;
        Ok(())
    }
}

impl Write for TransactionalOutput {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.file
            .as_mut()
            .expect("transaction owns its file until commit")
            .write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file
            .as_mut()
            .expect("transaction owns its file until commit")
            .flush()
    }
}

impl Drop for TransactionalOutput {
    fn drop(&mut self) {
        if !self.committed {
            self.file.take();
            let _ = fs::remove_file(&self.temporary);
        }
    }
}

fn resolve_destination(
    destination: &Path,
    input_path: &Path,
    input_metadata: Option<&Metadata>,
) -> Result<(PathBuf, Option<fs::Permissions>), AppError> {
    let output_metadata = match fs::metadata(destination) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(AppError::CreateOutput(error)),
    };

    if output_metadata.as_ref().is_some_and(Metadata::is_dir) {
        return Err(AppError::CreateOutput(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the output destination is a directory",
        )));
    }

    let canonical_input = input_metadata.and_then(|_| fs::canonicalize(input_path).ok());
    let canonical_output = fs::canonicalize(destination).ok();
    let paths_match = canonical_input
        .as_ref()
        .zip(canonical_output.as_ref())
        .is_some_and(|(input, output)| input == output);
    let identities_match = input_metadata
        .zip(output_metadata.as_ref())
        .is_some_and(|(input, output)| same_file(input, output));

    if paths_match || identities_match {
        return Err(AppError::SameInputAndOutput);
    }

    let permissions = output_metadata.map(|metadata| metadata.permissions());
    Ok((
        canonical_output.unwrap_or_else(|| destination.to_owned()),
        permissions,
    ))
}

#[cfg(unix)]
fn same_file(left: &Metadata, right: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file(_left: &Metadata, _right: &Metadata) -> bool {
    false
}
