//! Authenticated, per-value encryption for local dotenv vaults.
//!
//! Passwords use Argon2id. Values and the complete manifest use
//! XChaCha20-Poly1305. No function changes the process environment.

use std::{collections::BTreeMap, fmt, fs::File, io::Read, path::Path};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305,
    aead::{Aead, Payload},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

/// Maximum plaintext dotenv size, in bytes.
pub const MAX_ENV_BYTES: usize = 64 * 1024;
/// Maximum serialized vault size, in bytes.
pub const MAX_VAULT_BYTES: usize = 1024 * 1024;
/// Maximum unlock password size, in bytes.
pub const MAX_PASSWORD_BYTES: usize = 1024;
const FORMAT_VERSION: u8 = 1;

/// Failures never include plaintext values, passwords, or parser input.
#[derive(Debug, Error)]
pub enum StoreError {
    /// Input or output exceeded a documented size limit.
    #[error("input exceeds the store size limit")]
    SizeLimit,
    /// Passwords must contain between one and 1024 bytes.
    #[error("password must contain between 1 and 1024 bytes")]
    InvalidPassword,
    /// The dotenv source is not valid dotenv syntax.
    #[error("invalid dotenv syntax")]
    InvalidEnv,
    /// The vault structure or version is not supported.
    #[error("invalid or unsupported vault format")]
    InvalidFormat,
    /// A password is incorrect or authenticated content changed.
    #[error("vault authentication failed")]
    Authentication,
    /// The operating system could not provide random bytes.
    #[error("secure random generation failed")]
    Random,
    /// The password derivation could not complete.
    #[error("password derivation failed")]
    KeyDerivation,
    /// A requested secret does not exist.
    #[error("secret not found")]
    NotFound,
    /// The Python extension was built without embedded secrets.
    #[error("this module was built without an embedded vault")]
    NotEmbedded,
    /// A store file could not be read.
    #[error("store file could not be read")]
    Io(#[from] std::io::Error),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u8,
    salt: [u8; 16],
    entries: BTreeMap<String, Record>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    manifest: Manifest,
    authentication: Record,
}

/// An authenticated vault that keeps its values encrypted until requested.
///
/// Dropping the store clears its derived key. Returned plaintext belongs to
/// the caller and needs separate lifetime management.
pub struct Store {
    key: Zeroizing<[u8; 32]>,
    entries: BTreeMap<String, Record>,
}

impl fmt::Debug for Store {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Store(<redacted>)")
    }
}

impl Store {
    /// Authenticate a vault with an external password or embedded random key.
    ///
    /// # Errors
    /// Returns an error for invalid sizes, formats, passwords, or authentication.
    ///
    /// # Examples
    /// ```
    /// # fn main() -> Result<(), secure_store_core::StoreError> {
    /// let data = secure_store_core::seal_dotenv("API_KEY='example-only'", b"example password")?;
    /// let store = secure_store_core::Store::open(&data, b"example password")?;
    /// # let _value = store.get("API_KEY")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn open(data: &[u8], password: &[u8]) -> Result<Self, StoreError> {
        check_size(data.len(), MAX_VAULT_BYTES)?;
        check_password(password)?;
        let envelope: Envelope =
            serde_json::from_slice(data).map_err(|_| StoreError::InvalidFormat)?;
        if envelope.manifest.version != FORMAT_VERSION {
            return Err(StoreError::InvalidFormat);
        }
        let key = derive_key(password, &envelope.manifest.salt)?;
        let cipher = cipher(&key)?;
        let manifest = serialize(&envelope.manifest)?;
        let proof = decrypt(&cipher, &envelope.authentication, &manifest)?;
        if !proof.is_empty() {
            return Err(StoreError::InvalidFormat);
        }
        Ok(Self {
            key,
            entries: envelope.manifest.entries,
        })
    }

    /// Read and authenticate a vault without loading an unbounded file.
    ///
    /// # Errors
    /// Returns an error for file access or any failure from [`Self::open`].
    pub fn open_file(path: impl AsRef<Path>, password: &[u8]) -> Result<Self, StoreError> {
        Self::open(&read_limited(path.as_ref(), MAX_VAULT_BYTES)?, password)
    }

    /// Decrypt one value without caching plaintext or changing environment variables.
    ///
    /// # Errors
    /// Returns an error for a missing name, authentication failure, or invalid UTF-8.
    pub fn get(&self, name: &str) -> Result<Zeroizing<String>, StoreError> {
        let record = self.entries.get(name).ok_or(StoreError::NotFound)?;
        let plaintext = decrypt(&cipher(&self.key)?, record, name.as_bytes())?;
        let value = std::str::from_utf8(&plaintext).map_err(|_| StoreError::InvalidFormat)?;
        Ok(Zeroizing::new(value.to_owned()))
    }
}

/// Seal dotenv values with random salts and per-value nonces.
///
/// Parsing uses dotenvy syntax, including variable expansion at sealing time.
/// Single-quoted values remain literal. Duplicate names use the last assignment.
///
/// # Errors
/// Returns an error for invalid syntax, sizes, passwords, randomness, or encryption.
pub fn seal_dotenv(source: &str, password: &[u8]) -> Result<Vec<u8>, StoreError> {
    check_size(source.len(), MAX_ENV_BYTES)?;
    check_password(password)?;
    let values = dotenvy::from_read_iter(source.as_bytes())
        .map(|item| {
            let (name, value) = item.map_err(|_| StoreError::InvalidEnv)?;
            Ok((name, Zeroizing::new(value)))
        })
        .collect::<Result<BTreeMap<_, _>, StoreError>>()?;
    let salt = random_array()?;
    let key = derive_key(password, &salt)?;
    let cipher = cipher(&key)?;
    let entries = values
        .into_iter()
        .map(|(name, value)| {
            let record = encrypt(&cipher, value.as_bytes(), name.as_bytes())?;
            Ok((name, record))
        })
        .collect::<Result<_, StoreError>>()?;
    let manifest = Manifest {
        version: FORMAT_VERSION,
        salt,
        entries,
    };
    let authentication = encrypt(&cipher, b"", &serialize(&manifest)?)?;
    let data = serialize(&Envelope {
        manifest,
        authentication,
    })?;
    check_size(data.len(), MAX_VAULT_BYTES)?;
    Ok(data)
}

/// Read a bounded UTF-8 dotenv file and seal it without modifying the source.
///
/// # Errors
/// Returns an error for file access, invalid UTF-8, or any [`seal_dotenv`] failure.
pub fn seal_file(path: impl AsRef<Path>, password: &[u8]) -> Result<Vec<u8>, StoreError> {
    let source = read_limited(path.as_ref(), MAX_ENV_BYTES)?;
    let source = std::str::from_utf8(&source).map_err(|_| StoreError::InvalidEnv)?;
    seal_dotenv(source, password)
}

const fn check_size(length: usize, maximum: usize) -> Result<(), StoreError> {
    if length > maximum {
        return Err(StoreError::SizeLimit);
    }
    Ok(())
}

const fn check_password(password: &[u8]) -> Result<(), StoreError> {
    if password.is_empty() || password.len() > MAX_PASSWORD_BYTES {
        return Err(StoreError::InvalidPassword);
    }
    Ok(())
}

fn read_limited(path: &Path, maximum: usize) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    let mut data = Zeroizing::new(Vec::new());
    File::open(path)?
        .take((maximum + 1) as u64)
        .read_to_end(&mut data)?;
    check_size(data.len(), maximum)?;
    Ok(data)
}

fn random_array<const N: usize>() -> Result<[u8; N], StoreError> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes).map_err(|_| StoreError::Random)?;
    Ok(bytes)
}

fn derive_key(password: &[u8], salt: &[u8; 16]) -> Result<Zeroizing<[u8; 32]>, StoreError> {
    let parameters =
        Params::new(64 * 1024, 3, 1, Some(32)).map_err(|_| StoreError::KeyDerivation)?;
    let mut key = Zeroizing::new([0; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, parameters)
        .hash_password_into(password, salt, key.as_mut())
        .map_err(|_| StoreError::KeyDerivation)?;
    Ok(key)
}

fn cipher(key: &[u8; 32]) -> Result<XChaCha20Poly1305, StoreError> {
    XChaCha20Poly1305::new_from_slice(key).map_err(|_| StoreError::KeyDerivation)
}

fn encrypt(cipher: &XChaCha20Poly1305, msg: &[u8], aad: &[u8]) -> Result<Record, StoreError> {
    let nonce: [u8; 24] = random_array()?;
    let ciphertext = cipher
        .encrypt(&nonce.into(), Payload { msg, aad })
        .map_err(|_| StoreError::Authentication)?;
    Ok(Record { nonce, ciphertext })
}

fn decrypt(
    cipher: &XChaCha20Poly1305,
    record: &Record,
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    cipher
        .decrypt(
            &record.nonce.into(),
            Payload {
                msg: &record.ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| StoreError::Authentication)
}

fn serialize(value: &impl Serialize) -> Result<Vec<u8>, StoreError> {
    serde_json::to_vec(value).map_err(|_| StoreError::InvalidFormat)
}
