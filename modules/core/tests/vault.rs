//! Integration tests for authenticated vault contents and input limits.

use std::io::Write as _;

use anyhow::{Context as _, Result, ensure};
use secure_store_core::{
    MAX_EMBEDDED_BYTES, MAX_ENV_BYTES, MAX_PASSWORD_BYTES, MAX_VAULT_BYTES, Store, StoreError,
    seal_dotenv, seal_embedded, seal_embedded_file, seal_file,
};
use serde_json::{Value, json};
use tempfile::NamedTempFile;

const PASSWORD: &[u8] = b"synthetic-test-password-only";
const SOURCE: &str = "API_KEY='synthetic-secret-marker'\nSECOND='other-secret'\n";

#[test]
fn dotenv_round_trip_preserves_supported_values_and_environment() -> Result<()> {
    let before: Vec<_> = std::env::vars_os().collect();
    let source = "# comment\r\nexport API_KEY='first'\r\nAPI_KEY='literal-$HOME-\\n-密钥'\r\nEMPTY=\r\nQUOTED=\"line\\nnext\" # comment\r\n";
    let data = seal_dotenv(source, PASSWORD)?;
    let store = Store::open(&data, PASSWORD)?;
    ensure!(
        *store.get("API_KEY")? == "literal-$HOME-\\n-密钥",
        "literal value changed"
    );
    ensure!(store.get("EMPTY")?.is_empty(), "empty value changed");
    ensure!(
        *store.get("QUOTED")? == "line\nnext",
        "quoted escape changed"
    );
    ensure!(
        matches!(store.get("ABSENT"), Err(StoreError::NotFound)),
        "missing key accepted"
    );
    ensure!(
        format!("{store:?}") == "Store(<redacted>)",
        "debug output exposes contents"
    );
    ensure!(
        std::env::vars_os().collect::<Vec<_>>() == before,
        "process environment changed"
    );
    ensure!(
        !data
            .windows(b"literal-$HOME".len())
            .any(|bytes| bytes == b"literal-$HOME"),
        "plaintext leaked"
    );
    Ok(())
}

#[test]
fn rejects_wrong_password_and_authenticates_empty_vaults() -> Result<()> {
    for source in [SOURCE, ""] {
        let data = seal_dotenv(source, PASSWORD)?;
        ensure!(
            matches!(
                Store::open(&data, b"wrong-password"),
                Err(StoreError::Authentication)
            ),
            "wrong password accepted"
        );
        Store::open(&data, PASSWORD)?;
    }
    Ok(())
}

#[test]
fn rejects_modified_ciphertexts_nonces_salt_and_authenticator() -> Result<()> {
    let data = seal_dotenv(SOURCE, PASSWORD)?;
    for pointer in [
        "/manifest/salt/0",
        "/manifest/entries/API_KEY/nonce/0",
        "/manifest/entries/API_KEY/ciphertext/0",
        "/authentication/nonce/0",
        "/authentication/ciphertext/0",
    ] {
        let mut value: Value = serde_json::from_slice(&data)?;
        let field = value
            .pointer_mut(pointer)
            .context("missing fixture field")?;
        *field = json!(field.as_u64().context("invalid fixture byte")? ^ 1);
        ensure!(
            matches!(
                Store::open(&serde_json::to_vec(&value)?, PASSWORD),
                Err(StoreError::Authentication)
            ),
            "modified vault accepted: {pointer}"
        );
    }
    Ok(())
}

#[test]
fn rejects_deleted_renamed_and_substituted_entries() -> Result<()> {
    let data = seal_dotenv(SOURCE, PASSWORD)?;
    for operation in ["delete", "rename", "substitute"] {
        let mut value: Value = serde_json::from_slice(&data)?;
        let entries = value["manifest"]["entries"]
            .as_object_mut()
            .context("missing entries")?;
        let entry = entries.remove("API_KEY").context("missing fixture entry")?;
        match operation {
            "delete" => {}
            "rename" => {
                entries.insert("RENAMED".to_owned(), entry);
            }
            _ => {
                entries.insert("API_KEY".to_owned(), entries["SECOND"].clone());
            }
        }
        ensure!(
            matches!(
                Store::open(&serde_json::to_vec(&value)?, PASSWORD),
                Err(StoreError::Authentication)
            ),
            "changed entry set accepted: {operation}"
        );
    }
    Ok(())
}

#[test]
fn rejects_invalid_formats_and_redacts_parser_errors() -> Result<()> {
    for source in [
        "MISSING_EQUALS secret-marker",
        "API_KEY='unterminated-secret-marker",
    ] {
        let error = seal_dotenv(source, PASSWORD)
            .err()
            .context("invalid dotenv accepted")?;
        ensure!(
            matches!(error, StoreError::InvalidEnv),
            "wrong parser error"
        );
        ensure!(
            !format!("{error:?}").contains("secret-marker"),
            "parser error leaked plaintext"
        );
    }
    for data in [b"".as_slice(), b"{}", b"not json"] {
        ensure!(
            matches!(Store::open(data, PASSWORD), Err(StoreError::InvalidFormat)),
            "invalid format accepted"
        );
    }
    let data = seal_dotenv(SOURCE, PASSWORD)?;
    let mut value: Value = serde_json::from_slice(&data)?;
    value["manifest"]["version"] = json!(99);
    ensure!(
        matches!(
            Store::open(&serde_json::to_vec(&value)?, PASSWORD),
            Err(StoreError::InvalidFormat)
        ),
        "unknown version accepted"
    );
    let mut value: Value = serde_json::from_slice(&data)?;
    value["unexpected"] = json!(true);
    ensure!(
        matches!(
            Store::open(&serde_json::to_vec(&value)?, PASSWORD),
            Err(StoreError::InvalidFormat)
        ),
        "unknown field accepted"
    );
    ensure!(
        Store::open(&data[..data.len() - 1], PASSWORD).is_err(),
        "truncated vault accepted"
    );
    Ok(())
}

#[test]
fn uses_fresh_salts_and_nonces() -> Result<()> {
    let first: Value = serde_json::from_slice(&seal_dotenv(SOURCE, PASSWORD)?)?;
    let second: Value = serde_json::from_slice(&seal_dotenv(SOURCE, PASSWORD)?)?;
    ensure!(
        first["manifest"]["salt"] != second["manifest"]["salt"],
        "salt reused"
    );
    ensure!(
        first["manifest"]["entries"]["API_KEY"]["nonce"]
            != second["manifest"]["entries"]["API_KEY"]["nonce"],
        "nonce reused"
    );
    Ok(())
}

#[test]
fn enforces_password_and_buffer_limits_before_decryption() -> Result<()> {
    for password in [Vec::new(), vec![b'x'; MAX_PASSWORD_BYTES + 1]] {
        ensure!(
            matches!(
                seal_dotenv(SOURCE, &password),
                Err(StoreError::InvalidPassword)
            ),
            "invalid password accepted"
        );
    }
    ensure!(
        matches!(
            seal_dotenv(&"x".repeat(MAX_ENV_BYTES + 1), PASSWORD),
            Err(StoreError::SizeLimit)
        ),
        "large dotenv accepted"
    );
    ensure!(
        matches!(
            Store::open(&vec![0; MAX_VAULT_BYTES + 1], PASSWORD),
            Err(StoreError::SizeLimit)
        ),
        "large vault accepted"
    );
    Ok(())
}

#[test]
fn file_interfaces_round_trip_and_reject_invalid_files() -> Result<()> {
    let mut source = NamedTempFile::new()?;
    source.write_all(SOURCE.as_bytes())?;
    let mut vault = NamedTempFile::new()?;
    vault.write_all(&seal_file(source.path(), PASSWORD)?)?;
    ensure!(
        *Store::open_file(vault.path(), PASSWORD)?.get("API_KEY")? == "synthetic-secret-marker",
        "file round trip changed value"
    );
    let oversized = NamedTempFile::new()?;
    oversized.as_file().set_len((MAX_ENV_BYTES + 1) as u64)?;
    ensure!(
        matches!(
            seal_file(oversized.path(), PASSWORD),
            Err(StoreError::SizeLimit)
        ),
        "large dotenv file accepted"
    );
    oversized.as_file().set_len((MAX_VAULT_BYTES + 1) as u64)?;
    ensure!(
        matches!(
            Store::open_file(oversized.path(), PASSWORD),
            Err(StoreError::SizeLimit)
        ),
        "large vault file accepted"
    );
    let mut invalid = NamedTempFile::new()?;
    invalid.write_all(&[0xff])?;
    ensure!(
        matches!(
            seal_file(invalid.path(), PASSWORD),
            Err(StoreError::InvalidEnv)
        ),
        "non-UTF-8 dotenv accepted"
    );
    ensure!(
        matches!(
            Store::open_file(source.path().with_extension("missing"), PASSWORD),
            Err(StoreError::Io(_))
        ),
        "missing file accepted"
    );
    Ok(())
}

#[test]
fn embedded_bundles_round_trip_without_plaintext_passwords_or_values() -> Result<()> {
    for source in [SOURCE, ""] {
        let data = seal_embedded(source, PASSWORD)?;
        let store = Store::open_embedded(&data)?;
        if source.is_empty() {
            ensure!(matches!(store.get("API_KEY"), Err(StoreError::NotFound)));
        } else {
            ensure!(*store.get("API_KEY")? == "synthetic-secret-marker");
        }
        ensure!(!data.windows(PASSWORD.len()).any(|bytes| bytes == PASSWORD));
        ensure!(
            !data
                .windows(b"synthetic-secret-marker".len())
                .any(|bytes| bytes == b"synthetic-secret-marker")
        );
        ensure!(
            data != seal_embedded(source, PASSWORD)?,
            "bundle reused randomness"
        );
        Store::open(&data[68..], PASSWORD)?;
    }
    Ok(())
}

#[test]
fn embedded_bundles_reject_modified_headers_keys_manifests_and_limits() -> Result<()> {
    let data = seal_embedded(SOURCE, PASSWORD)?;
    for length in 0..=68 {
        ensure!(Store::open_embedded(&data[..length]).is_err());
    }
    for offset in [0, 4, 36, 68, data.len() - 1] {
        let mut changed = data.clone();
        changed[offset] ^= 1;
        ensure!(
            Store::open_embedded(&changed).is_err(),
            "modified bundle accepted"
        );
    }
    ensure!(matches!(
        Store::open_embedded(&vec![0; MAX_EMBEDDED_BYTES + 1]),
        Err(StoreError::SizeLimit)
    ));
    for password in [Vec::new(), vec![b'x'; MAX_PASSWORD_BYTES + 1]] {
        ensure!(matches!(
            seal_embedded(SOURCE, &password),
            Err(StoreError::InvalidPassword)
        ));
    }
    ensure!(matches!(
        seal_embedded(&"x".repeat(MAX_ENV_BYTES + 1), PASSWORD),
        Err(StoreError::SizeLimit)
    ));
    Ok(())
}

#[test]
fn embedded_file_builds_preserve_source_and_enforce_input_bounds() -> Result<()> {
    let mut source = NamedTempFile::new()?;
    source.write_all(SOURCE.as_bytes())?;
    let data = seal_embedded_file(source.path(), PASSWORD)?;
    ensure!(*Store::open_embedded(&data)?.get("API_KEY")? == "synthetic-secret-marker");
    ensure!(std::fs::read_to_string(source.path())? == SOURCE);
    source.as_file().set_len((MAX_ENV_BYTES + 1) as u64)?;
    ensure!(matches!(
        seal_embedded_file(source.path(), PASSWORD),
        Err(StoreError::SizeLimit)
    ));
    let mut invalid = NamedTempFile::new()?;
    invalid.write_all(&[0xff])?;
    ensure!(matches!(
        seal_embedded_file(invalid.path(), PASSWORD),
        Err(StoreError::InvalidEnv)
    ));
    ensure!(matches!(
        seal_embedded_file(source.path().with_extension("missing"), PASSWORD),
        Err(StoreError::Io(_))
    ));
    Ok(())
}
