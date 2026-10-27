//! Seal dotenv files without printing secrets or overwriting existing files.

use std::{
    fs::File,
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result, ensure};
use clap::Parser;
use secure_store_core::MAX_PASSWORD_BYTES;
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

#[derive(Debug, Parser)]
#[command(
    name = "secure-store",
    version,
    about = "Encrypt a dotenv file into a local vault"
)]
struct Arguments {
    /// Plaintext dotenv input. The source remains unchanged.
    input: PathBuf,
    /// New encrypted vault output. Existing files are never overwritten.
    output: PathBuf,
    /// UTF-8 password file for noninteractive use. Remove trailing CR/LF bytes.
    #[arg(long)]
    password_file: Option<PathBuf>,
}

fn main() -> Result<()> {
    let arguments = Arguments::parse();
    let password = read_password(arguments.password_file.as_deref())?;
    let data = secure_store_core::seal_file(&arguments.input, password.as_bytes())?;
    let directory = arguments
        .output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temporary = NamedTempFile::new_in(directory).context("cannot create vault output")?;
    temporary
        .write_all(&data)
        .context("cannot write vault output")?;
    temporary
        .as_file()
        .sync_all()
        .context("cannot sync vault output")?;
    temporary
        .persist_noclobber(&arguments.output)
        .map_err(|error| error.error)
        .context("cannot publish vault without overwriting an existing file")?;
    Ok(())
}

fn read_password(path: Option<&Path>) -> Result<Zeroizing<String>> {
    if let Some(path) = path {
        let mut password = Zeroizing::new(String::new());
        File::open(path)
            .context("cannot read password file")?
            .take((MAX_PASSWORD_BYTES + 3) as u64)
            .read_to_string(&mut password)
            .context("cannot read password file")?;
        ensure!(
            password.len() <= MAX_PASSWORD_BYTES + 2,
            "password file exceeds the size limit"
        );
        let length = password.trim_end_matches(['\r', '\n']).len();
        password.truncate(length);
        return Ok(password);
    }
    let password = Zeroizing::new(rpassword::prompt_password("Vault password: ")?);
    let confirmation = Zeroizing::new(rpassword::prompt_password("Confirm password: ")?);
    ensure!(
        *password == *confirmation,
        "password confirmation does not match"
    );
    Ok(password)
}
