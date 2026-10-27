# Technical wiki

Secure Store is a native Python module that stores API keys as encrypted dotenv values.
The Python import name is `secure_store`.
Run the commands below from the repository root.
Building the native wheel requires Python 3.10 or newer, uv, and a Rust toolchain.
Installing a compatible prebuilt wheel and building an application with it do not require Cargo.

## Local storage modes

- **External password:** keep the password outside the distributed app. This protects a copied vault when the password remains secret.
- **Embedded:** encrypt dotenv during the Python application build and compile the resulting bundle into the application. This hides plaintext from simple string searches.
- **Development:** open a plaintext dotenv file directly with `Store.open(".env")`. The module emits a `RuntimeWarning` because the file remains unencrypted on disk.

A recipient can recover embedded unlock material and retrieve the values.
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

## Python application builds (Nuitka)

Use a generic wheel with the `nuitka` extra for the target OS and architecture.
Set `WHEEL` to the absolute path of the selected compatible wheel.
For wheel production, see [generic wheel builds](DEVELOPMENT.md#generic-wheel).
For Linux:

```bash
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python "${WHEEL}[nuitka]"
source .venv/bin/activate
```

The application calls `secure_store.Store.open(".env")` and retrieves values with `store.get("API_KEY")`.
Build it with one invocation:

```bash
SECURE_STORE_ENV_FILE=.env python -m secure_store --mode=onefile app.py
```

For Windows PowerShell, select a Windows wheel and use:

```powershell
uv venv --python 3.12 .venv
uv pip install --python .venv/Scripts/python.exe "${WHEEL}[nuitka]"
.venv/Scripts/Activate.ps1
$env:SECURE_STORE_ENV_FILE = ".env"
python -m secure_store --mode=onefile app.py
Remove-Item Env:SECURE_STORE_ENV_FILE
```

Use `--mode=standalone` for a directory distribution instead.
Nuitka requires a C compiler on the application build machine.
The build extra supplies Nuitka, zstandard, and patchelf on Linux.
The virtual environment must be active so build helpers are on PATH.

The hook reads and encrypts dotenv inside Nuitka's build process through the precompiled native extension.
When `SECURE_STORE_CRED` is missing or empty, the hook generates a fresh cryptographically random password for the build.
To supply a password instead, set `SECURE_STORE_CRED` from a secret manager or hidden prompt.
There is no separate sealing command or pre-existing encrypted vault.
It replaces `secure_store._embedded` source in memory without modifying the installed wheel or application source.
Only encrypted values and a masked derived key enter the generated resource.
The original build password is not embedded.
The hook removes its build variables from the compiler process environment before native compilation.
The finished application needs neither a runtime credential nor the original dotenv file.
Without a build-time bundle, `Store.open(path)` reads the supplied plaintext dotenv and warns.
With an embedded bundle, it returns the one embedded store for any supplied path and does not read that path.
Applications needing multiple independently selected stores must use a different design.
Passing a password explicitly continues to open a password-protected vault file.

A missing or empty `SECURE_STORE_ENV_FILE`, invalid input, and oversized input fail the build.
Excluding the embedded module or including the selected plaintext dotenv as a data file also fails the build.
Treat generated build directories and final binaries as private artifacts because their unlock material remains recoverable.

## Optional wheel-level embedding

The native Cargo build can also embed secrets directly in a wheel.
This separate path requires Rust for each customized wheel and is not needed for the Nuitka workflow above.

```bash
SECURE_STORE_ENV_FILE="$(pwd)/.env" uvx maturin build --release --out target/wheels-embedded
uv pip install --reinstall target/wheels-embedded/*.whl
```

Use `secure_store.Store.open(".env")` to open the compiled vault.
Call `store.get("API_KEY")` to retrieve one value.
This mode needs no runtime password or dotenv file.
A generic wheel outside a hooked application raises `RuntimeError` for `Store.embedded()`.

Do not distribute the plaintext `.env`, source archives, or build directory.
The wheel contains your app's recoverable unlock material.
Treat it as a private distribution artifact.
Replacing embedded credentials requires rebuilding and redistributing the wheel and any packaged application.

## Nuitka and PyArmor

Nuitka standalone builds must include the installed `secure_store` package and its native extension.
PyArmor distributions must also include this package.
The native module does not depend on either compiler's string protection.
Neither tool prevents a recipient from retrieving embedded secrets.
PyArmor alone does not execute the Nuitka encryption hook.

See [packaging smoke checks](DEVELOPMENT.md#packaging-smoke-checks) for the demonstration build commands and their verification scope.

## Module ownership

- [Core](../modules/core/src/lib.rs) owns dotenv parsing, bounded reads, password derivation, authenticated serialization, and per-value decryption.
- [Python bindings](../modules/py/src/lib.rs) expose the shared store through PyO3.
- [Nuitka entry point](../python/secure_store/__main__.py) enables the installed [build hook](../python/secure_store/nuitka_plugin.py).
- [Embedded resource](../python/secure_store/_embedded.py) holds the stub that the build hook replaces in memory.
- [Native embedded build](../modules/py/build.rs) provides optional wheel-level embedding.
- [CLI](../modules/cli/src/main.rs) reads passwords and publishes encrypted vault files without overwriting existing files.

The Python and CLI crates share the same store implementation.
Keep new storage behavior in that shared implementation rather than adding a second Python implementation.

## Detailed references

- [Security model](SECURITY.md): encryption parameters, authenticated contents, input limits, dotenv syntax, memory limits, and distribution risks.
- [Modules and development](DEVELOPMENT.md): workspace structure, wheel builds, CLI options, integration checks, and independent cryptographic verification.
- [Project rules](CONSTITUTION.md): code, error-handling, documentation, and testing requirements.
