# Modules and development

Run commands from the repository root.
Building the native module requires Python 3.10 or newer, uv, and a Rust toolchain.

## Workspace

- [Core](../modules/core/src/lib.rs) owns dotenv parsing, bounded reads, password derivation, authenticated serialization, and per-value decryption.
- [Python](../modules/py/src/lib.rs) exposes the shared store through PyO3.
- [Python package](../python/secure_store/__init__.py) preserves the public import surface around the native extension.
- [Nuitka hook](../python/secure_store/nuitka_plugin.py) encrypts dotenv during the application build without recompiling Rust.
- [Native embedded build](../modules/py/build.rs) supports optional wheel-level embedding.
- [CLI](../modules/cli/src/main.rs) reads passwords and publishes encrypted vault files without overwriting existing files.

The Cargo workspace shares dependencies, package metadata, and the original strict lint policy.
The Python and CLI crates call the same store implementation.
New local storage behavior belongs in the core crate, not a second Python implementation.

## Generic wheel

```bash
uv venv --python 3.12 .venv
env -u SECURE_STORE_ENV_FILE -u SECURE_STORE_CRED uvx maturin build --release --locked --out target/wheels-generic
uv pip install --python .venv/bin/python --reinstall target/wheels-generic/*.whl
cargo build --locked -p secure-store-cli
SECURE_STORE_CLI="$(pwd)/target/debug/secure-store" .venv/bin/python -m unittest discover -s tests -v
```

Generic wheels contain no application credentials and support external vaults and Nuitka application-build embedding.
Producing the wheel requires Rust, but installing it and building applications against it do not.
Public package indexes must receive generic wheels only.
Build compatible wheels for each supported OS and architecture.
The extension uses the CPython stable ABI from Python 3.10.
Linux wheel tags must reflect the actual manylinux or musllinux compatibility.

The CLI accepts two positional paths: dotenv input and encrypted output.
It requests a password twice unless --password-file supplies a protected UTF-8 file.
It never prints decrypted values.

## Native embedded wheel

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

Build a generic wheel, then set WHEEL to its absolute path.
The following commands target Linux and Python 3.12.
The credential below and [dotenv fixture](../examples/demo.env) are synthetic demonstration data.

```bash
uv pip install --python .venv/bin/python "${WHEEL}[nuitka]"
source .venv/bin/activate
SECURE_STORE_ENV_FILE=examples/demo.env SECURE_STORE_CRED=synthetic-build-password-only python -m secure_store --mode=onefile --output-dir=target/nuitka-app --assume-yes-for-downloads examples/embedded.py
SECURE_STORE_NUITKA_BINARY="$(pwd)/target/nuitka-app/embedded.bin" python -m unittest discover -s tests -v
SECURE_STORE_TEST_BUILD=1 SECURE_STORE_TEST_BUILD_DIR="$(pwd)/target/nuitka-build" python -m unittest discover -s tests -v
```

The build regression starts with plaintext dotenv and no encrypted vault.
It invokes the installed Python compiler entry point with unusable CARGO and RUSTC selections.
It removes the source and dotenv before running both executables from an empty directory without build variables.
It checks the generated build files and distribution for the synthetic plaintext value and password.
The installed embedded-resource stub must remain unchanged.
Input failures, plaintext data-file inclusion, and excluded embedded modules have separate rejection cases.

For the existing PyArmor smoke check, first install a native embedded wheel built with the demonstration fixture:

```bash
uvx --python 3.12 pyarmor gen -O target/pyarmor examples/embedded.py
SECURE_STORE_TEST_EMBEDDED=1 SECURE_STORE_PYARMOR_SCRIPT="$(pwd)/target/pyarmor/embedded.py" python -m unittest discover -s tests -v
```

The PyArmor check exercises the trial runtime, not paid protection options or the Nuitka hook.
Reinstall the generic wheel before running the application-build regression.

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
uvx ruff check python tests examples
uvx ruff format --check python tests examples
```

[Rust integration tests](../modules/core/tests/vault.rs) exercise the shared store interface, malformed inputs, authentication failures, entry deletion, renaming, substitution, and bounded file reads.
[Python and CLI tests](../tests/test_store.py) exercise the installed extension and the real executable.
Set SECURE_STORE_CLI to run CLI cases instead of skipping them.
Only set SECURE_STORE_TEST_EMBEDDED when testing a wheel built with the demonstration fixture.

See the [security model](SECURITY.md) before distributing an embedded wheel.
Follow the [project rules](CONSTITUTION.md) when changing the workspace.
