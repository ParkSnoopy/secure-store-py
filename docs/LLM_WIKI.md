# Technical wiki

Secure Store is a native Python module that stores API keys as encrypted dotenv values.
The Python import name is `secure_store`.
Run the commands below from the repository root.
Building the module requires Python 3.10 or newer, uv, and a Rust toolchain.

## Local storage modes

- **External password:** keep the password outside the distributed app. This protects a copied vault when the password remains secret.
- **Embedded:** compile an encrypted vault and its unlock material into a native module. This hides plaintext from simple string searches.

Anyone who can load an embedded module can retrieve its values without a debugger.
Embedded mode is obfuscation, not confidentiality against the recipient.
The module never creates a plaintext dotenv file at runtime or copies secrets into the process environment.

## External-password setup

Use an existing Python environment or create one with `uv venv .venv`.
Install the native module:

```bash
uv pip install .
```

Do not set `SECURE_STORE_ENV_FILE` when building an external-password-only module.
Create a vault:

```bash
cargo run --release -p secure-store-cli -- .env secrets.vault
```

The CLI requests a password twice and checks that both entries match without echoing them.
It refuses to overwrite an existing output file.
The original `.env` remains unchanged.

Use `secure_store.Store.open("secrets.vault", password)` to open the vault.
Call `store.get("API_KEY")` to retrieve one value.
Supply the password at runtime, for example through Python's `getpass.getpass()`.
Do not put the password in Python source.

For an in-memory vault, use `secure_store.seal(dotenv_text, password)` and `secure_store.Store(vault_bytes, password)`.

## Embedded setup

Build a separate wheel for each app's secrets:

```bash
SECURE_STORE_ENV_FILE="$(pwd)/.env" uvx maturin build --release --out target/wheels-embedded
uv pip install --reinstall target/wheels-embedded/*.whl
```

Use `secure_store.Store.embedded()` to open the compiled vault.
Call `store.get("API_KEY")` to retrieve one value.
This mode needs no runtime password or dotenv file.
A module built without an embedded vault raises `RuntimeError` for `Store.embedded()`.

Do not distribute the plaintext `.env`, source archives, or build directory.
The wheel contains your app's recoverable unlock material.
Treat it as a private distribution artifact.
Replacing embedded credentials requires rebuilding and redistributing the wheel and any packaged application.

## Nuitka and PyArmor

Nuitka standalone builds must include the installed `secure_store` package and its native extension.
PyArmor distributions must also include this package.
The native module does not depend on either compiler's string protection.
Neither tool prevents a recipient from retrieving embedded secrets.

See [packaging smoke checks](DEVELOPMENT.md#packaging-smoke-checks) for the demonstration build commands and their verification scope.

## Module ownership

- [Store](../modules/store/src/lib.rs) owns dotenv parsing, bounded reads, password derivation, authenticated serialization, and per-value decryption.
- [Python bindings](../modules/python/src/lib.rs) expose the shared store through PyO3.
- [Embedded build](../modules/python/build.rs) encrypts the selected dotenv input during compilation.
- [CLI](../modules/cli/src/main.rs) reads passwords and publishes encrypted vault files without overwriting existing files.

The Python and CLI crates share the same store implementation.
Keep new storage behavior in that shared implementation rather than adding a second Python implementation.

## Detailed references

- [Security model](SECURITY.md): encryption parameters, authenticated contents, input limits, dotenv syntax, memory limits, and distribution risks.
- [Modules and development](DEVELOPMENT.md): workspace structure, wheel builds, CLI options, integration checks, and independent cryptographic verification.
- [Project rules](CONSTITUTION.md): code, error-handling, documentation, and testing requirements.
