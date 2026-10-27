"""Exercise the installed native extension and the real sealing CLI."""

import json
import os
import pickle
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import secure_store

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


if __name__ == "__main__":
    unittest.main()
