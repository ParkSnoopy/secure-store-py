"""Compile a Python application with build-time dotenv encryption."""

import sys
from pathlib import Path


def main() -> None:
    """Run Nuitka with the installed secure-store build hook enabled."""
    try:
        from nuitka.__main__ import main as nuitka_main
    except ModuleNotFoundError as error:
        if error.name != "nuitka":
            raise
        raise SystemExit(
            "Install secure-store-py[nuitka] to build applications."
        ) from None

    plugin = Path(__file__).with_name("nuitka_plugin.py")
    sys.argv[1:1] = [f"--user-plugin={plugin}"]
    nuitka_main()


if __name__ == "__main__":
    main()
