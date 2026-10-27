# Modules and development

Run commands from the repository root.
Building the native module requires Python 3.10 or newer, uv, and a Rust toolchain.

## Workspace

- [Store](../modules/store/src/lib.rs) owns dotenv parsing, bounded reads, password derivation, authenticated serialization, and per-value decryption.
- [Python](../modules/python/src/lib.rs) exposes the shared store through PyO3.
- [Embedded build](../modules/python/build.rs) encrypts an explicitly selected dotenv file during compilation.
- [CLI](../modules/cli/src/main.rs) reads passwords and publishes encrypted vault files without overwriting existing files.

The Cargo workspace shares dependencies, package metadata, and the original strict lint policy.
The Python and CLI crates call the same store implementation.
New local storage behavior belongs in the store crate, not a second Python implementation.

## External-password wheel

```bash
uv venv --python 3.12 .venv
uvx maturin build --release --locked --out target/wheels-external
uv pip install --python .venv/bin/python --reinstall target/wheels-external/*.whl
cargo build --locked -p secure-store-cli
SECURE_STORE_CLI="$(pwd)/target/debug/secure-store" .venv/bin/python -m unittest discover -s tests -v
```

Do not set SECURE_STORE_ENV_FILE for this build.

The CLI accepts two positional paths: dotenv input and encrypted output.
It requests a password twice unless --password-file supplies a protected UTF-8 file.
It never prints decrypted values.

## Embedded wheel

The fixture below contains only a synthetic demonstration key.
Never put real credentials in that fixture.

```bash
SECURE_STORE_ENV_FILE="$(pwd)/examples/demo.env" uvx maturin build --release --locked --out target/wheels-embedded
uv pip install --python .venv/bin/python --reinstall target/wheels-embedded/*.whl
SECURE_STORE_TEST_EMBEDDED=1 SECURE_STORE_CLI="$(pwd)/target/debug/secure-store" .venv/bin/python -m unittest discover -s tests -v
.venv/bin/python examples/embedded.py
```

SECURE_STORE_ENV_FILE must name an existing dotenv input.
Cargo tracks both this selection and changes to the selected file.
An invalid selection fails the build instead of producing an unprotected fallback.
Cargo generates embedded material in its build output rather than the source tree.

## Packaging smoke checks

Build and install the demonstration embedded wheel before these checks.
For the Nuitka command, the wheel output directory must contain exactly one selected wheel.
The commands below target Linux and Python 3.12.

```bash
uvx --python 3.12 --with patchelf --with zstandard --with "$(pwd)"/target/wheels-embedded/*.whl nuitka --onefile --include-package=secure_store --output-dir=target/nuitka --assume-yes-for-downloads examples/embedded.py
uvx --python 3.12 pyarmor gen -O target/pyarmor examples/embedded.py
SECURE_STORE_TEST_EMBEDDED=1 SECURE_STORE_CLI="$(pwd)/target/debug/secure-store" SECURE_STORE_NUITKA_BINARY="$(pwd)/target/nuitka/embedded.bin" SECURE_STORE_PYARMOR_SCRIPT="$(pwd)/target/pyarmor/embedded.py" .venv/bin/python -m unittest discover -s tests -v
```

The distribution checks run Nuitka's standalone and onefile executables from an empty temporary directory.
They also check the generated distribution files for the synthetic plaintext key.
The PyArmor check exercises the trial runtime, not paid protection options.

For independent Argon2 and libsodium decryption checks, run:

```bash
SECURE_STORE_TEST_EMBEDDED=1 SECURE_STORE_TEST_INTEROP=1 uv run --no-project --python 3.12 --with argon2-cffi --with pynacl --with "$(pwd)"/target/wheels-embedded/*.whl python -m unittest discover -s tests -v
```

The extra verification packages are not application dependencies.

## Native checks

```bash
cargo fmt --all --check
cargo test --locked --workspace --no-fail-fast
cargo clippy --locked --workspace --all-targets --all-features
cargo deny check advisories licenses bans sources
uvx ruff check tests examples
uvx ruff format --check tests examples
```

[Rust integration tests](../modules/store/tests/vault.rs) exercise the shared store interface, malformed inputs, authentication failures, entry deletion, renaming, substitution, and bounded file reads.
[Python and CLI tests](../tests/test_store.py) exercise the installed extension and the real executable.
Set SECURE_STORE_CLI to run CLI cases instead of skipping them.
Only set SECURE_STORE_TEST_EMBEDDED when testing a wheel built with the demonstration fixture.

See the [security model](SECURITY.md) before distributing an embedded wheel.
Follow the [project rules](CONSTITUTION.md) when changing the workspace.
