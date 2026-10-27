# Secure Store for Python

A native Python module that stores API keys as encrypted dotenv values.  

Choose one local mode:  

- **External password:** keep the password outside the distributed app. This protects a copied vault when the password remains secret.  
- **Embedded:** compile an encrypted vault and its unlock material into a native module. This hides plaintext from simple string searches. Anyone who can load the module can retrieve its values.  

The module never creates a plaintext dotenv file at runtime.  
It does not copy secrets into the process environment.  

## External-password mode

Build and install the Python module with `uv pip install .` in your Python environment.  

Create a vault with `cargo run --release -p secure-store-cli -- .env secrets.vault`.  
The CLI requests and confirms a password without echoing it.  
It refuses to overwrite an existing output file.  
The original `.env` remains unchanged.  

Use `secure_store.Store.open("secrets.vault", password)` to open the vault.  
Call `store.get("API_KEY")` to retrieve one value.  
Supply the password at runtime, for example through Python's `getpass.getpass()`.  
Do not put the password in your Python source.  

For an in-memory vault, use `secure_store.seal(dotenv_text, password)` and `secure_store.Store(vault_bytes, password)`.  

## Embedded mode

Build a separate wheel for each app's secrets:  

```bash
SECURE_STORE_ENV_FILE="$(pwd)/.env" uvx maturin build --release --out target/wheels-embedded
uv pip install --reinstall target/wheels-embedded/*.whl
```

Use `secure_store.Store.embedded()` to open the compiled vault.  
Call `store.get("API_KEY")` to retrieve one value.  
This mode needs no runtime password or dotenv file.  
Do not distribute the plaintext `.env`, source archives, or build directory.  
The wheel contains your app's recoverable unlock material.  
Treat it as a private distribution artifact.  

Nuitka standalone builds must include the installed `secure_store` package and its native extension.  
PyArmor distributions must also include this package.  
The native module does not depend on either compiler's string protection.  

[Security limits and file format](docs/SECURITY.md) · [Modules and development](docs/DEVELOPMENT.md)  
