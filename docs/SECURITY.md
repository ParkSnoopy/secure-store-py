# Security model

## Local modes

Without an embedded bundle, `Store.open(path)` reads the named plaintext dotenv file and emits a `RuntimeWarning`.
The file remains plaintext on disk and must not be distributed or committed.
The store encrypts its values in memory after parsing, but plaintext copies can remain in memory.

External-password mode protects vault contents when an attacker copies the vault but does not know the password.
Use a strong password or a random secret supplied outside the application.
Do not distribute the password beside the vault or place it in application source.
An operating-system credential manager can supply the password through application code.
This project does not provide a credential-manager adapter.

Embedded mode packages encrypted values and masked unlock material in the application or native extension.
The masking obstructs simple static inspection only.
Anyone who can inspect or control the running app can recover the unlock material or plaintext values.
Anyone who can load an embedded wheel can call Store.embedded().get(name) without a debugger.
Application-build bundles contain equivalent recoverable unlock material.
Nuitka, PyArmor, and native compilation do not remove this limitation.
A shared provider key remains a shared credential after distribution.
Use provider restrictions, quotas, and rotation to limit exposure.
A server proxy is necessary if clients must never receive a shared provider key.

## Encryption and authentication

Version 1 uses Argon2id version 19 with 65536 KiB of memory, three iterations, one lane, and a 32-byte output.
Each vault has a random 16-byte salt.
The implementation fixes these parameters instead of accepting them from an untrusted vault.

Each value uses XChaCha20-Poly1305 with a random 24-byte nonce.
The cipher authenticates the secret name as associated data for that value.
A separate empty-message authentication record covers the canonical JSON serialization of the complete manifest.
The manifest includes the version, salt, names, nonces, and ciphertexts.
Opening a vault authenticates this manifest before returning a store.
Each retrieval decrypts only its requested value.

Names, entry counts, and approximate value lengths remain visible.
The store does not detect replacement with an older authentic vault.
Authentication does not establish freshness or identify who supplied the vault.

## Plaintext and input limits

The module does not cache decrypted values or place them in environment variables.
Native derived keys and explicitly managed plaintext buffers use zeroize on drop.
This does not clear every parser, allocator, compiler, operating-system, or Python copy.
This module cannot reliably clear returned Python strings.
Process memory, debugging, crash dumps, and compromised dependencies remain outside its protection.

The store limits plaintext dotenv input to 64 KiB.
The store limits serialized vault input and output to 1 MiB.
Passwords contain between one and 1024 bytes.
File reads enforce limits before loading an entire oversized file.
Parser and authentication errors exclude secret values and passwords.

Parsing uses dotenvy, including its quote, escape, and variable-expansion rules.
Expansion occurs when sealing, not when retrieving values.
Use single quotes for literal API keys that contain dollar signs or backslashes.
Duplicate names use the last assignment.
Native vault operations never change the process environment.

## Distribution and updates

Keep the original dotenv input, password files, build caches, and source archives private.
Cargo's generated embedded bindings contain recoverable unlock material.
Keep separate artifacts for applications with different embedded credentials.
Replacing application-build credentials requires rebuilding and redistributing the application, not its generic native wheel.
Replacing wheel-level embedded credentials requires rebuilding and redistributing the wheel and any packaged application.
Build without SECURE_STORE_ENV_FILE for a generic wheel.
A generic wheel outside a hooked application must reject Store.embedded() rather than use a fallback credential.

The CLI creates output through a temporary file and refuses an existing destination.
On Unix, the temporary file and published vault have owner-only permissions.
The original dotenv input remains unchanged.
For noninteractive sealing, --password-file reads a UTF-8 password and removes trailing CR/LF bytes.
Protect that file separately and never package it with the vault.

## Python application-build encryption

The Nuitka hook requires SECURE_STORE_ENV_FILE and accepts an optional SECURE_STORE_CRED inside the application build.
If the credential is missing or empty, the hook generates a fresh password from 32 bytes of cryptographic randomness.
The hook removes the variables from that process environment before C compilation.
The hook invokes the installed native extension for bounded input reads, dotenv parsing, and encryption.
It supplies generated module source in memory without changing installed package files.
It rejects distribution of the selected plaintext input as a data file, including filesystem aliases.
It also rejects exclusion of the embedded resource.
In an embedded application, `Store.open(path)` selects the single embedded bundle regardless of the supplied path.
It does not read the path or fall back to plaintext when the bundle fails authentication.
An explicitly supplied password selects the external encrypted-vault path instead.

The bundle starts with the four bytes `SSB1`, followed by a random 32-byte mask and the 32-byte derived key XORed with that mask.
The remaining bytes are the normal authenticated version-1 vault.
The store limits bundle size to the vault limit plus its 68-byte header.
Opening reconstructs the key in native memory and authenticates the manifest before returning a store.
It does not require the original password or repeat password derivation at runtime.
Malformed bundles and authentication failures must not fall back to a wheel-level vault.

The original password and plaintext values are not generated as resource literals.
When supplied through the environment, credentials may be inspected by local processes or CI infrastructure during part of the build.
Literal shell assignments can expose credentials through command history, and shell tracing can expose expanded variables.
The build process and Python allocator may retain credential copies despite removing environment variables.
Generated resource data, build caches, and final binaries contain recoverable decryption capability.
Passing a plaintext scan proves only the absence of that searched representation, not confidentiality from the recipient.
