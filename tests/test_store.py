"""Exercise the installed native extension and the real sealing CLI."""

import hashlib
import importlib.util
import json
import os
import pickle
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import secure_store
from secure_store import _embedded, _native

PASSWORD = "synthetic-test-password-only"
MARKER = "synthetic-secret-marker"
SOURCE = f"API_KEY='{MARKER}'\nEMPTY=\n"
DEMO_KEY = "demo-not-a-real-key-9d2f6a8b1c4e7f03"


class StoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = secure_store.seal(SOURCE, PASSWORD)

    def test_round_trip_and_no_environment_mutation(self):
        before = dict(os.environ)
        store = secure_store.Store(self.data, PASSWORD)
        self.assertEqual(store.get("API_KEY"), MARKER)
        self.assertEqual(store.get("EMPTY"), "")
        self.assertEqual(repr(store), "Store(<redacted>)")
        self.assertEqual(dict(os.environ), before)
        self.assertNotIn(MARKER.encode(), self.data)
        with self.assertRaises(KeyError):
            store.get("ABSENT")
        with self.assertRaises(TypeError):
            pickle.dumps(store)

    def test_wrong_password_and_tampering(self):
        with self.assertRaisesRegex(ValueError, "authentication failed"):
            secure_store.Store(self.data, "wrong-password")
        value = json.loads(self.data)
        del value["manifest"]["entries"]["EMPTY"]
        with self.assertRaisesRegex(ValueError, "authentication failed"):
            secure_store.Store(json.dumps(value).encode(), PASSWORD)

    @unittest.skipUnless(
        os.environ.get("SECURE_STORE_TEST_INTEROP") == "1",
        "set SECURE_STORE_TEST_INTEROP with argon2-cffi and pynacl installed",
    )
    def test_independent_argon2_and_libsodium_decryption(self):
        from argon2.low_level import Type, hash_secret_raw
        from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt

        document = json.loads(self.data)
        manifest = document["manifest"]
        key = hash_secret_raw(
            PASSWORD.encode(), bytes(manifest["salt"]), 3, 65536, 1, 32, Type.ID, 19
        )
        authentication = document["authentication"]
        canonical = json.dumps(
            manifest, ensure_ascii=False, separators=(",", ":")
        ).encode()
        self.assertEqual(
            crypto_aead_xchacha20poly1305_ietf_decrypt(
                bytes(authentication["ciphertext"]),
                canonical,
                bytes(authentication["nonce"]),
                key,
            ),
            b"",
        )
        for name, expected in {"API_KEY": MARKER.encode(), "EMPTY": b""}.items():
            record = manifest["entries"][name]
            self.assertEqual(
                crypto_aead_xchacha20poly1305_ietf_decrypt(
                    bytes(record["ciphertext"]),
                    name.encode(),
                    bytes(record["nonce"]),
                    key,
                ),
                expected,
            )

    def test_file_open_and_missing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "secrets.vault"
            path.write_bytes(self.data)
            self.assertEqual(
                secure_store.Store.open(path, PASSWORD).get("API_KEY"), MARKER
            )
            with self.assertRaises(OSError):
                secure_store.Store.open(path.with_suffix(".missing"), PASSWORD)

    def test_invalid_input_and_redacted_errors(self):
        for source in [f"{MARKER} missing equals", f"API_KEY='{MARKER}"]:
            with self.assertRaisesRegex(ValueError, "invalid dotenv syntax") as raised:
                secure_store.seal(source, PASSWORD)
            self.assertNotIn(MARKER, str(raised.exception))
        for password in ["", "x" * 1025]:
            with self.assertRaises(ValueError):
                secure_store.seal(SOURCE, password)
        with self.assertRaises(ValueError):
            secure_store.Store(b"x" * (1024 * 1024 + 1), PASSWORD)

    def test_selected_embedding_mode(self):
        if os.environ.get("SECURE_STORE_TEST_EMBEDDED") != "1":
            with self.assertRaisesRegex(RuntimeError, "without an embedded vault"):
                secure_store.Store.embedded()
            return
        store = secure_store.Store.embedded()
        self.assertEqual(store.get("API_KEY"), DEMO_KEY)
        assert secure_store.__file__ is not None
        native_files = [
            *Path(secure_store.__file__).parent.glob("*.so"),
            *Path(secure_store.__file__).parent.glob("*.pyd"),
        ]
        self.assertTrue(native_files, "native extension not found")
        for path in native_files:
            self.assertNotIn(DEMO_KEY.encode(), path.read_bytes())

    def test_application_bundle_round_trip_and_authentication(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.env"
            source.write_text(SOURCE)
            data = _native._seal_embedded_file(source, PASSWORD)
            self.assertNotIn(MARKER.encode(), data)
            self.assertNotIn(PASSWORD.encode(), data)
            self.assertEqual(source.read_text(), SOURCE)
            with patch.object(_embedded, "DATA", data):
                store = secure_store.Store.embedded()
                self.assertEqual(store.get("API_KEY"), MARKER)
                self.assertEqual(store.get("EMPTY"), "")
            for offset in [0, 4, 36, 68, len(data) - 1]:
                changed = bytearray(data)
                changed[offset] ^= 1
                with (
                    patch.object(_embedded, "DATA", bytes(changed)),
                    self.assertRaises(ValueError),
                ):
                    secure_store.Store.embedded()
            for invalid in [b"", b"SSB1", b"x" * (1024 * 1024 + 69)]:
                with (
                    patch.object(_embedded, "DATA", invalid),
                    self.assertRaises(ValueError),
                ):
                    secure_store.Store.embedded()
            with (
                patch.object(_embedded, "DATA", "not bytes"),
                self.assertRaises(TypeError),
            ):
                secure_store.Store.embedded()

    def test_application_bundle_rejects_invalid_file_and_password(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.env"
            for data in [b"x" * (64 * 1024 + 1), b"\xff", b"API_KEY='unterminated"]:
                source.write_bytes(data)
                with self.assertRaises(ValueError) as raised:
                    _native._seal_embedded_file(source, PASSWORD)
                self.assertNotIn(MARKER, str(raised.exception))
                self.assertNotIn(PASSWORD, str(raised.exception))
            source.write_text(SOURCE)
            for password in ["", "x" * 1025]:
                with self.assertRaises(ValueError):
                    _native._seal_embedded_file(source, password)
            with self.assertRaises(OSError):
                _native._seal_embedded_file(source.with_suffix(".missing"), PASSWORD)


@unittest.skipUnless(
    os.environ.get("SECURE_STORE_CLI"), "set SECURE_STORE_CLI to the real binary"
)
class CliTests(unittest.TestCase):
    def invoke(self, source, output, password):
        return subprocess.run(
            [
                os.environ["SECURE_STORE_CLI"],
                str(source),
                str(output),
                "--password-file",
                str(password),
            ],
            capture_output=True,
            check=False,
            timeout=60,
        )

    def test_cli_round_trip_permissions_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output, password = (
                root / "input.env",
                root / "output.vault",
                root / "password.key",
            )
            source.write_text(SOURCE)
            password.write_text(PASSWORD + "\r\n")
            result = self.invoke(source, output, password)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, b"")
            self.assertNotIn(MARKER.encode(), result.stderr)
            self.assertEqual(
                secure_store.Store.open(output, PASSWORD).get("API_KEY"), MARKER
            )
            self.assertEqual(source.read_text(), SOURCE)
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            original = output.read_bytes()
            result = self.invoke(source, output, password)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(output.read_bytes(), original)
            self.assertEqual(
                sorted(path.name for path in root.iterdir()),
                ["input.env", "output.vault", "password.key"],
            )

    def test_cli_failure_does_not_publish_output_or_leak_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output, password = (
                root / "input.env",
                root / "output.vault",
                root / "password.key",
            )
            source.write_text(f"API_KEY='{MARKER}")
            password.write_text(PASSWORD)
            result = self.invoke(source, output, password)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output.exists())
            self.assertNotIn(MARKER.encode(), result.stdout + result.stderr)
            source.write_text(SOURCE)
            password.write_text("x" * 1027)
            result = self.invoke(source, output, password)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output.exists())


class DistributionTests(unittest.TestCase):
    @unittest.skipUnless(
        os.environ.get("SECURE_STORE_NUITKA_BINARY"), "set SECURE_STORE_NUITKA_BINARY"
    )
    def test_nuitka_runs_without_source_and_excludes_plaintext(self):
        binary = Path(os.environ["SECURE_STORE_NUITKA_BINARY"]).resolve(strict=True)
        distribution = binary.with_suffix(".dist")
        standalone = distribution / binary.name
        with tempfile.TemporaryDirectory() as directory:
            for executable in [binary, standalone]:
                result = subprocess.run(
                    [str(executable)],
                    cwd=directory,
                    capture_output=True,
                    check=True,
                    timeout=60,
                )
                self.assertEqual(result.stdout, b"Native embedded vault unlocked.\n")
        for path in [binary, *distribution.rglob("*")]:
            if path.is_file():
                self.assertNotIn(DEMO_KEY.encode(), path.read_bytes(), str(path))

    @unittest.skipUnless(
        os.environ.get("SECURE_STORE_PYARMOR_SCRIPT"), "set SECURE_STORE_PYARMOR_SCRIPT"
    )
    def test_pyarmor_runs_without_source(self):
        script = Path(os.environ["SECURE_STORE_PYARMOR_SCRIPT"]).resolve(strict=True)
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [sys.executable, str(script)],
                cwd=directory,
                capture_output=True,
                check=True,
                timeout=60,
            )
        self.assertEqual(result.stdout, b"Native embedded vault unlocked.\n")


@unittest.skipUnless(importlib.util.find_spec("nuitka"), "install the nuitka extra")
class NuitkaBuildTests(unittest.TestCase):
    def build(self, source, entry, output, extra=(), credential=PASSWORD):
        environment = dict(os.environ)
        environment.pop("PYTHONPATH", None)
        if source is None:
            environment.pop("SECURE_STORE_ENV_FILE", None)
        else:
            environment["SECURE_STORE_ENV_FILE"] = str(source)
        environment["CARGO"] = str(entry.parent / "unavailable-cargo")
        environment["RUSTC"] = str(entry.parent / "unavailable-rustc")
        if credential is None:
            environment.pop("SECURE_STORE_CRED", None)
        else:
            environment["SECURE_STORE_CRED"] = credential
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "secure_store",
                f"--output-dir={output}",
                *extra,
                str(entry),
            ],
            env=environment,
            cwd=entry.parent,
            capture_output=True,
            check=False,
            timeout=600,
        )

    def test_invalid_build_inputs_fail_without_leaking_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, entry = root / "input.env", root / "app.py"
            entry.write_text("from secure_store import Store\nStore.embedded()\n")
            cases = [
                (SOURCE.encode(), None, "Set SECURE_STORE_ENV_FILE"),
                (SOURCE.encode(), "", "Set SECURE_STORE_ENV_FILE"),
                (SOURCE.encode(), "x" * 1025, "Cannot encrypt"),
                (f"API_KEY='{MARKER}".encode(), PASSWORD, "Cannot encrypt"),
                (b"\xff", PASSWORD, "Cannot encrypt"),
                (b"x" * (64 * 1024 + 1), PASSWORD, "Cannot encrypt"),
                (None, PASSWORD, "Cannot encrypt"),
            ]
            for data, credential, expected in cases:
                with self.subTest(expected=expected, credential_missing=not credential):
                    if data is not None:
                        source.write_bytes(data)
                    elif source.exists():
                        source.unlink()
                    result = self.build(
                        source, entry, root / "out", ["--mode=standalone"], credential
                    )
                    output = result.stdout + result.stderr
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(expected.encode(), output)
                    self.assertNotIn(MARKER.encode(), output)
                    self.assertNotIn(PASSWORD.encode(), output)
            source.write_text(SOURCE)
            for missing in [None, ""]:
                result = self.build(missing, entry, root / "out", ["--mode=standalone"])
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    b"Set SECURE_STORE_ENV_FILE", result.stdout + result.stderr
                )
            result = self.build(source, entry, root / "out")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"Use --mode=standalone", result.stdout + result.stderr)

    def test_build_rejects_plaintext_inclusion_and_excluded_resource(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, entry = root / "input.env", root / "app.py"
            source.write_text(SOURCE)
            entry.write_text("from secure_store import Store\nStore.embedded()\n")
            alias = root / "alias.env"
            alias.hardlink_to(source)
            for extra, expected in [
                ([f"--include-data-files={source}=input.env"], b"plaintext dotenv"),
                ([f"--include-data-files={alias}=alias.env"], b"plaintext dotenv"),
                (["--nofollow-import-to=secure_store._embedded"], b"embedded resource"),
            ]:
                with self.subTest(expected=expected):
                    result = self.build(
                        source,
                        entry,
                        root / "out",
                        ["--mode=standalone", "--generate-c-only", *extra],
                    )
                    output = result.stdout + result.stderr
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(expected, output)
                    self.assertNotIn(MARKER.encode(), output)
                    self.assertNotIn(PASSWORD.encode(), output)

    @unittest.skipUnless(
        os.environ.get("SECURE_STORE_TEST_BUILD") == "1", "set SECURE_STORE_TEST_BUILD"
    )
    def test_build_encrypts_dotenv_and_runs_without_source_or_credentials(self):
        with self.assertRaisesRegex(RuntimeError, "without an embedded vault"):
            secure_store.Store.embedded()
        resource = Path(_embedded.__file__)
        original = resource.read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, entry = root / "input.env", root / "app.py"
            source.write_text(SOURCE)
            expected = hashlib.sha256(MARKER.encode()).hexdigest()
            entry.write_text(
                "import os\nfrom hashlib import sha256\nfrom secure_store import Store\n"
                "if 'SECURE_STORE_CRED' in os.environ:\n"
                "    raise RuntimeError('Unexpected runtime credential')\n"
                "value = Store.embedded().get('API_KEY')\n"
                f"if sha256(value.encode()).hexdigest() != {expected!r}:\n"
                "    raise RuntimeError('Wrong embedded vault')\n"
                "print('Application build vault unlocked.')\n"
            )
            output = Path(os.environ.get("SECURE_STORE_TEST_BUILD_DIR", root / "out"))
            output = output.resolve()
            result = self.build(
                source, entry, output, ["--mode=onefile", "--assume-yes-for-downloads"]
            )
            build_log = result.stdout + result.stderr
            self.assertNotIn(MARKER.encode(), build_log)
            self.assertNotIn(PASSWORD.encode(), build_log)
            self.assertEqual(result.returncode, 0, build_log.decode(errors="replace"))
            (output / "build.log").write_bytes(build_log)
            source.unlink()
            entry.unlink()
            runtime = root / "runtime"
            runtime.mkdir()
            environment = dict(os.environ)
            for name in ["SECURE_STORE_ENV_FILE", "SECURE_STORE_CRED", "PYTHONPATH"]:
                environment.pop(name, None)
            suffix = ".exe" if sys.platform == "win32" else ".bin"
            binary = output / f"app{suffix}"
            standalone = output / "app.dist" / binary.name
            for executable in [binary, standalone]:
                result = subprocess.run(
                    [str(executable)],
                    cwd=runtime,
                    env=environment,
                    capture_output=True,
                    check=True,
                    timeout=60,
                )
                self.assertEqual(result.stdout, b"Application build vault unlocked.\n")
            for path in output.rglob("*"):
                if path.is_file():
                    data = path.read_bytes()
                    self.assertFalse(
                        MARKER.encode() in data, f"plaintext value in {path}"
                    )
                    self.assertFalse(
                        PASSWORD.encode() in data, f"plaintext password in {path}"
                    )
                    self.assertNotEqual(path.name, "input.env")
        self.assertEqual(resource.read_bytes(), original)
        self.assertIsNone(_embedded.DATA)


if __name__ == "__main__":
    unittest.main()
