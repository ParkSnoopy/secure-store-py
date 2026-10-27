//! Generate an optional encrypted embedded vault, never plaintext Rust constants.

use std::{env, fmt::Write as _, fs, io::Write as _, path::PathBuf};

use anyhow::{Context as _, Result};
use zeroize::Zeroizing;

fn main() -> Result<()> {
    let output = PathBuf::from(env::var_os("OUT_DIR").context("missing Cargo output directory")?);
    writeln!(
        std::io::stdout(),
        "cargo:rerun-if-env-changed=SECURE_STORE_ENV_FILE"
    )?;
    let source = match env::var_os("SECURE_STORE_ENV_FILE") {
        Some(path) => {
            let path = PathBuf::from(path)
                .canonicalize()
                .context("cannot resolve dotenv file")?;
            writeln!(
                std::io::stdout(),
                "cargo:rerun-if-changed={}",
                path.display()
            )?;
            generate_embedded(&path, &output)?
        }
        None => String::from(
            "const fn embedded_store() -> Result<Vault, StoreError> { Err(StoreError::NotEmbedded) }\n",
        ),
    };
    fs::write(output.join("embedded.rs"), source).context("cannot write embedded vault bindings")
}

fn generate_embedded(path: &std::path::Path, output: &std::path::Path) -> Result<String> {
    let mut password = Zeroizing::new([0_u8; 32]);
    let mut mask = [0_u8; 32];
    getrandom::fill(password.as_mut()).map_err(|_| anyhow::anyhow!("random generation failed"))?;
    getrandom::fill(&mut mask).map_err(|_| anyhow::anyhow!("random generation failed"))?;
    let data = secure_store_core::seal_file(path, password.as_ref())?;
    fs::write(output.join("embedded.vault"), data)
        .context("cannot write encrypted embedded vault")?;
    let mut masked = [0_u8; 32];
    for ((result, key_byte), mask_byte) in masked.iter_mut().zip(password.iter()).zip(mask) {
        *result = key_byte ^ mask_byte;
    }
    // This split only obstructs static inspection. It does not protect against runtime extraction.
    let mut source = String::new();
    writeln!(
        source,
        "fn embedded_store() -> Result<Vault, StoreError> {{
    let mask = std::hint::black_box({mask:?});
    let masked = std::hint::black_box({masked:?});
    let mut password = zeroize::Zeroizing::new([0_u8; 32]);
    for ((result, key_byte), mask_byte) in password.iter_mut().zip(masked).zip(mask) {{
        *result = key_byte ^ mask_byte;
    }}
    Vault::open(include_bytes!(concat!(env!(\"OUT_DIR\"), \"/embedded.vault\")), password.as_ref())
}}"
    )?;
    Ok(source)
}
