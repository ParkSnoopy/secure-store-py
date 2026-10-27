"""Encrypt the selected dotenv during Nuitka's application build."""

import os
import secrets
from pathlib import Path

from nuitka.options.Options import isStandaloneMode
from nuitka.plugins.PluginBase import NuitkaPluginBase

from secure_store._native import _seal_embedded_file


class NuitkaPluginSecureStore(NuitkaPluginBase):
    """Inject a native-readable bundle without modifying the installed package."""

    plugin_name = "secure-store"
    plugin_desc = "Encrypt dotenv inside the Python application build."

    def __init__(self):
        source = os.environ.pop("SECURE_STORE_ENV_FILE", None) or ".env"
        credential = os.environ.pop("SECURE_STORE_CRED", None)
        if not isStandaloneMode():
            self.sysexit(
                "Use --mode=standalone or --mode=onefile for secure-store builds."
            )
        try:
            if not credential:
                credential = secrets.token_urlsafe(32)
            self.source = Path(source).resolve(strict=True)
            self.data = _seal_embedded_file(self.source, credential)
        except (OSError, ValueError, RuntimeError):
            self.sysexit(
                "Cannot encrypt the selected dotenv; check its syntax and limits."
            )

    def getImplicitImports(self, module):
        """Include the resource that the native extension imports at runtime."""
        if module.getFullName() == "secure_store":
            yield "secure_store._embedded"

    def onModuleSourceCode(self, module_name, source_filename, source_code):
        """Supply only encrypted data and masked derived-key bytes to Nuitka."""
        if module_name == "secure_store._embedded":
            return f"DATA = {self.data!r}\n"
        return source_code

    def onModuleCompleteSet(self, module_set):
        """Reject builds that excluded the embedded resource."""
        if not any(
            module.getFullName() == "secure_store._embedded" for module in module_set
        ):
            self.sysexit(
                "The application must include secure_store and its embedded resource."
            )

    def onDataFileTags(self, included_datafile):
        """Reject attempts to distribute the selected plaintext dotenv file."""
        if included_datafile.kind == "data_file" and Path(
            included_datafile.source_path
        ).samefile(self.source):
            self.sysexit(
                "Do not include the plaintext dotenv as an application data file."
            )
